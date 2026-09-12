<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Support;

use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Storage\StorageInterface;
use Kanopi\Firewall\Utility\BlockList;
use Symfony\Component\HttpFoundation\Request;

/**
 * Block, unblock and look up clients from the command line.
 *
 * The library's `bin/firewall-block` can list, find, show and lift — it cannot
 * *add*. That is a deliberate gap upstream, where blocks are something rules
 * earn, not something an operator writes. It is a gap all the same the first
 * time somebody is on the phone reading a reference number off an error page,
 * or a scraper needs stopping before a rule can be written and deployed.
 *
 * So these three operations are implemented here rather than forwarded to a
 * script, against the library's public API: `BlockList` for reads and lifts,
 * `StorageInterface` for the write. Nothing reaches into internals, which is
 * why they can exist in this package at all.
 *
 * ## What was learned about the storage contract
 *
 * Two details decided the shape of this class and neither is guessable:
 *
 * - **`$expire` passed to `set()` is a duration in seconds, not a timestamp.**
 *   The backend adds `time()` itself, and `0` means "no expiry". Reading it as
 *   a timestamp would make every block either permanent or already expired.
 * - **`set()` on a key that already exists replaces the payload and keeps the
 *   original expiry.** So re-blocking an address cannot extend its ban, which
 *   is the opposite of what an operator typing a longer `--duration` expects.
 *   That is what `$force` is for: it deletes first, so the new duration
 *   actually applies.
 */
final class BlockManager
{
    /**
     * Where the reference lives inside a stored record.
     *
     * `QueryableStorageInterface::find()` documents the payload as being
     * carried "alongside" `expire`, which reads as flat. It is not: the payload
     * is nested under `value`, with `expire`, `expires_at` and `offenses`
     * beside it. Established by writing a record and dumping what came back,
     * because a lookup keyed on the wrong path finds nothing and reports "no
     * such reference" — which is indistinguishable from a reference that does
     * not exist.
     */
    private const PAYLOAD = 'value';

    public function __construct(private readonly BlockList $blockList)
    {
    }

    /**
     * Put a client on the block list.
     *
     * @param string $ip
     *   A single address. **Not a CIDR range**: storage keys are the client IP
     *   verbatim and `isBlocked()` is an exact key lookup, so a range written
     *   here would sit in the list looking authoritative and match no visitor
     *   ever. Ranges belong in an `IpAddress` rule, which is evaluated rather
     *   than looked up.
     * @param int $duration
     *   Seconds until it lapses. `0` never lapses.
     * @param string $reason
     *   A note stored with the record, for whoever reads the list next.
     * @param bool $force
     *   Replace an existing block, so a new duration applies.
     *
     * @return array{address: string, expires: string, reference: string, replaced: bool}
     *
     * @throws IntegrationException
     *   When the address is not a single valid IP, when the backend cannot
     *   store it, or when a block already exists and `$force` is FALSE.
     */
    public function add(string $ip, int $duration, string $reason = '', bool $force = false): array
    {
        $address = $this->validateAddress($ip);
        $storage = $this->blockList->storage();
        $existing = $storage->isBlocked($address) !== false;

        if ($existing && !$force) {
            throw new IntegrationException(sprintf(
                '%s is already blocked. Re-blocking would replace the reason and keep the '
                . 'original expiry, because that is what the storage backend does — pass '
                . '--force to lift it and apply the new duration, or firewall:unblock %s '
                . 'first.',
                $address,
                $address
            ));
        }

        if ($existing) {
            $storage->delete($address);
        }

        $request = $this->requestFor($address);
        $reference = $this->generateReference();
        $request->attributes->set('x-request-id', $reference);

        // Built by the backend rather than assembled here, so a record written
        // by hand carries the same keys as one written by a rule and
        // `firewall:blocks` renders both identically. The note is added
        // afterwards: it is this package's, and nothing in the library reads it.
        $payload = $storage->getStorageData($request, null);
        $payload['blocked_by'] = 'firewall:block';

        if ($reason !== '') {
            $payload['reason'] = $reason;
        }

        if (!$storage->set($address, $payload, max(0, $duration))) {
            throw new IntegrationException(sprintf(
                'The storage backend (%s) refused to record a block for %s.',
                $this->backendClass(),
                $address
            ));
        }

        return [
            'address' => $address,
            'expires' => $duration > 0 ? date('c', time() + $duration) : 'never',
            'reference' => $reference,
            'replaced' => $existing,
        ];
    }

    /**
     * Lift every block matching an address or CIDR range.
     *
     * Ranges are fine here, unlike in `add()`: lifting matches against stored
     * addresses rather than creating a key, so `10.0.0.0/8` means "everything
     * in the list that falls inside this range".
     *
     * @return int
     *   How many records went, or would have gone for a dry run.
     */
    public function remove(string $pattern, bool $dryRun = false): int
    {
        $this->assertQueryable();

        if ($dryRun) {
            return count($this->blockList->find($pattern));
        }

        return $this->blockList->lift([$pattern]);
    }

    /**
     * Empty the block list.
     *
     * Implemented as a lift of everything the list reports rather than
     * `StorageInterface::reset()`, which also discards offense history — and
     * that history is what drives escalating bans. An operator clearing blocks
     * after a false positive wants the slate clean, not the escalation ladder
     * reset for every address that has ever misbehaved.
     *
     * @return int
     *   How many records went, or would have gone for a dry run.
     */
    public function clear(bool $dryRun = false): int
    {
        $this->assertQueryable();

        $addresses = array_keys($this->blockList->all());

        if ($addresses === [] || $dryRun) {
            return count($addresses);
        }

        return $this->blockList->lift($addresses);
    }

    /**
     * Find the block a reference number belongs to.
     *
     * The reference is the `event_id` the firewall shows a blocked visitor —
     * the hex string in "…Request Banned". It is what a support caller can
     * read out, and until now there was no way to turn it back into an address:
     * it appears in the block page and in the logs, and nothing indexed it.
     *
     * Matched case-insensitively because the firewall renders it uppercase and
     * people retype it however they like.
     *
     * The scan is linear over the whole list, which is the right trade here.
     * The alternative is a second index to keep in step with the library's own
     * storage — more moving parts, and an index that disagrees with the list is
     * worse than a scan. A list large enough for this to hurt has a bigger
     * problem than a slow lookup.
     *
     * @return array{address: string, record: array<string, mixed>}|null
     *   NULL when no block carries that reference, which includes the ordinary
     *   case of a reference whose block has since lapsed.
     */
    public function findReference(string $reference): ?array
    {
        $needle = strtoupper(trim($reference));

        if ($needle === '') {
            return null;
        }

        // `$this->all()`, not `$this->blockList->all()`. The library's method
        // answers an unqueryable backend with an empty list, which this loop
        // would report as "no block carries that reference" — the exact
        // confusion between "no" and "cannot tell" that `assertQueryable()`
        // exists to prevent. Caught by a test, having been written the wrong
        // way round first.
        foreach ($this->all() as $address => $record) {
            if ($this->referenceOf($record) === $needle) {
                return ['address' => (string) $address, 'record' => $record];
            }
        }

        return null;
    }

    /**
     * Every block currently in force, keyed by address.
     *
     * @return array<string, array<string, mixed>>
     */
    public function all(): array
    {
        $this->assertQueryable();

        return $this->blockList->all();
    }

    /**
     * The reference stored on a record, uppercased, or an empty string.
     */
    public function referenceOf(mixed $record): string
    {
        if (!is_array($record)) {
            return '';
        }

        $payload = $record[self::PAYLOAD] ?? null;
        $reference = is_array($payload) ? ($payload['event_id'] ?? null) : null;

        return is_string($reference) ? strtoupper($reference) : '';
    }

    /**
     * One field from a record's payload, as a string.
     */
    public function payloadValue(mixed $record, string $key): string
    {
        if (!is_array($record)) {
            return '';
        }

        $payload = $record[self::PAYLOAD] ?? null;
        $value = is_array($payload) ? ($payload[$key] ?? null) : null;

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * The class actually storing blocks, for a message that names it.
     */
    public function backendClass(): string
    {
        // Indexed without a fallback: `BlockList::backend()` declares a fixed
        // shape, so a `??` here would be a branch nothing can reach.
        return $this->blockList->backend()['class'];
    }

    /**
     * Refuse the operations that need a backend able to answer questions.
     *
     * `InMemoryStorage` is queryable but per-process, and a backend that is not
     * queryable at all returns an empty list from every read — so a lift would
     * report "0 removed" and a lookup "no such reference", both of which read
     * as an answer rather than as an inability to answer.
     *
     * @throws IntegrationException
     */
    private function assertQueryable(): void
    {
        if ($this->blockList->backend()['queryable']) {
            return;
        }

        throw new IntegrationException(sprintf(
            'The configured storage backend (%s) cannot be queried, so blocks cannot be '
            . 'listed or lifted from the command line. Use FileStorage, DatabaseStorage or '
            . 'RedisStorage.',
            $this->backendClass()
        ));
    }

    /**
     * @throws IntegrationException
     */
    private function validateAddress(string $ip): string
    {
        $address = trim($ip);

        if (filter_var($address, FILTER_VALIDATE_IP) !== false) {
            return $address;
        }

        throw new IntegrationException(sprintf(
            str_contains($address, '/')
                ? '"%s" is a range, and a block is stored under one exact address — a range '
                    . 'here would never match a visitor. Put ranges in an IpAddress rule '
                    . '(php artisan firewall:rule add --plugin=ip --rule=%s), which is '
                    . 'evaluated rather than looked up.'
                : '"%s" is not a valid IP address.',
            $address,
            $address
        ));
    }

    /**
     * A request carrying the address, for the backend to derive a key from.
     *
     * `getKey()` returns `$request->getClientIp()` verbatim, so REMOTE_ADDR is
     * all this needs. No forwarded headers are set, so trusted-proxy
     * configuration cannot affect what gets keyed — which matters, because an
     * operator blocking an address must get that address and not one derived
     * from a header.
     */
    private function requestFor(string $address): Request
    {
        return Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $address]);
    }

    /**
     * A reference in the same shape the firewall generates.
     *
     * 16 random bytes, hex, uppercase — matching `Firewall::generateId()`, so a
     * reference from a hand-written block is indistinguishable in form from one
     * the firewall issued and can be looked up the same way.
     */
    private function generateReference(): string
    {
        return strtoupper(bin2hex(random_bytes(16)));
    }
}
