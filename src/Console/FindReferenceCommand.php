<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Console;

use Illuminate\Console\Command;
use Kanopi\Firewall\Exception\FirewallException;
use Kanopi\Firewall\Laravel\Support\BlockManager;

/**
 * Turn a reference number from a block page back into a client.
 *
 * The firewall shows a blocked visitor a hex reference in its banning message —
 * the `event_id` it recorded with the block. That string is the only thing a
 * caller can read out: the page deliberately tells them nothing about which
 * rule matched or why.
 *
 * Which left support with a reference and no way to use it. The reference
 * appears on the page and in the logs, and nothing indexed it, so answering
 * "why is this customer blocked?" meant grepping logs and hoping the retention
 * window reached back far enough. This is that lookup, against the block list
 * itself.
 *
 * A reference that finds nothing is the ordinary case as often as it is a
 * mistyped one: blocks lapse, and the page the caller is looking at may be
 * cached or from yesterday. The output says so rather than implying the
 * reference was wrong.
 */
final class FindReferenceCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'firewall:find-reference
        {reference : The reference from the block page, e.g. 2CB3B1780E3653DE9C7AFA913F3C1A33}
        {--json : Machine-readable output}';

    /**
     * @var string
     */
    protected $description = 'Find which blocked client a reference number belongs to';

    public function handle(BlockManager $blocks): int
    {
        $reference = $this->argument('reference');

        try {
            $found = $blocks->findReference(is_string($reference) ? $reference : '');
        } catch (FirewallException $exception) {
            $this->components->error($exception->getMessage());

            return FirewallCommand::EXIT_ERROR;
        }

        if ($found === null) {
            return $this->reportMiss(is_string($reference) ? $reference : '');
        }

        $record = $found['record'];

        $details = [
            'reference' => $blocks->referenceOf($record),
            'address' => $found['address'],
            'plugin' => $blocks->payloadValue($record, 'plugin'),
            'blocked_at' => $blocks->payloadValue($record, 'timestamp'),
            'reason' => $blocks->payloadValue($record, 'reason'),
            'blocked_by' => $blocks->payloadValue($record, 'blocked_by'),
            'expires_at' => $this->stringField($record, 'expires_at'),
            'offenses' => $this->stringField($record, 'offenses'),
        ];

        if ((bool) $this->option('json')) {
            $this->line((string) json_encode(
                array_filter($details, static fn (string $value): bool => $value !== ''),
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
            ));

            return FirewallCommand::EXIT_OK;
        }

        $this->components->info(sprintf('Reference %s belongs to %s.', $details['reference'], $details['address']));

        // Bound to a variable rather than iterated inline, which PSR-12 reads
        // as a multi-line control structure and wants reformatted into
        // something less legible than this.
        $rows = [
            'Address' => $details['address'],
            'Blocked by rule' => $details['plugin'],
            'Blocked at' => $details['blocked_at'],
            'Expires' => $details['expires_at'],
            'Offenses' => $details['offenses'],
            'Reason' => $details['reason'],
            'Added by' => $details['blocked_by'],
        ];

        foreach ($rows as $label => $value) {
            if ($value !== '') {
                $this->components->twoColumnDetail($label, $value);
            }
        }

        $this->newLine();
        $this->line(sprintf('  Lift it with: <fg=cyan>php artisan firewall:unblock %s</>', $details['address']));

        return FirewallCommand::EXIT_OK;
    }

    /**
     * Report a reference that matched nothing.
     *
     * Exits non-zero, so a script can branch on it, while the message covers
     * the likeliest innocent explanations — because "not found" here usually
     * means the block has lapsed rather than that anybody got it wrong.
     */
    private function reportMiss(string $reference): int
    {
        if ((bool) $this->option('json')) {
            $this->line((string) json_encode([
                'reference' => strtoupper(trim($reference)),
                'found' => false,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return FirewallCommand::EXIT_ERROR;
        }

        $this->components->warn(sprintf(
            'No block in force carries reference %s.',
            strtoupper(trim($reference))
        ));

        $this->line(
            '  That is expected if the block has since lapsed or been lifted — the list holds'
            . PHP_EOL . '  only what is currently in force. The firewall log keeps the decision for'
            . PHP_EOL . '  longer: search it for the reference to see what matched and when.'
        );

        return FirewallCommand::EXIT_ERROR;
    }

    /**
     * A top-level record field as a string.
     *
     * `expires_at` and `offenses` sit beside the payload rather than inside it,
     * so they are read directly rather than through the payload accessors.
     *
     * Typed `array` rather than `mixed`: this is only ever handed
     * `findReference()`'s record, which that method declares as an array — so a
     * runtime check for anything else would be a branch nothing can reach.
     * `BlockManager`'s own accessors do take `mixed`, because they are public
     * and a caller may hand them a record a store wrote before this package
     * existed.
     *
     * @param array<string, mixed> $record
     */
    private function stringField(array $record, string $key): string
    {
        $value = $record[$key] ?? null;

        return is_scalar($value) ? (string) $value : '';
    }
}
