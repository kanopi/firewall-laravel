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
 * Block a client now, without writing a rule.
 *
 * The rule-shaped answer to "stop this address" is
 * `firewall:rule add --ip=… --response=block`, and it is the better answer
 * whenever there is time for it: a rule is configuration, it is reviewable, it
 * survives a cleared block list and it says why it exists.
 *
 * This is for when there is not time for it. A scraper is costing money now, or
 * a customer's compromised office IP needs stopping before anyone can agree on
 * a rule. The block is durable state rather than configuration, so it takes
 * effect on the next request with no deploy — and `--duration` means it lapses
 * on its own rather than outliving the incident.
 *
 * Takes the address as an argument rather than an option, because that is the
 * shape of the thing being acted on and `firewall:block 203.0.113.9` is what
 * somebody types under pressure.
 */
final class BlockAddCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'firewall:block
        {ip : The client address to block. A single IP, not a range}
        {--duration=3600 : Seconds until the block lapses. 0 blocks until lifted}
        {--reason= : A note stored with the block, for whoever reads the list next}
        {--force : Replace an existing block, so a new duration applies}';

    /**
     * @var string
     */
    protected $description = 'Block a client address immediately';

    public function handle(BlockManager $blocks): int
    {
        $ip = $this->argument('ip');
        $reason = $this->option('reason');

        try {
            $result = $blocks->add(
                is_string($ip) ? $ip : '',
                $this->duration(),
                is_string($reason) ? $reason : '',
                (bool) $this->option('force')
            );
        } catch (FirewallException $exception) {
            // Every refusal this can hit — a range where an address belongs, an
            // already-blocked client, a backend that will not write — arrives as
            // a FirewallException carrying a message written for an operator. It
            // is shown as-is rather than wrapped, because the wrapping would
            // only repeat it less well.
            $this->components->error($exception->getMessage());

            return FirewallCommand::EXIT_ERROR;
        }

        $this->components->info(sprintf(
            '%s %s.',
            $result['replaced'] ? 'Replaced the block on' : 'Blocked',
            $result['address']
        ));

        $this->components->twoColumnDetail('Expires', $result['expires']);
        // Printed because it is the only way back from an error page to a
        // record: the visitor sees this string and nothing else identifying.
        $this->components->twoColumnDetail('Reference', $result['reference']);
        $this->components->twoColumnDetail('Backend', $blocks->backendClass());

        return FirewallCommand::EXIT_OK;
    }

    /**
     * The requested duration in seconds.
     *
     * A non-numeric `--duration` becomes the default hour rather than `0`,
     * which `(int)` would have produced — and `0` means "until somebody lifts
     * it". A typo should not silently create a permanent block.
     */
    private function duration(): int
    {
        $duration = $this->option('duration');

        return is_string($duration) && is_numeric($duration) ? max(0, (int) $duration) : 3600;
    }
}
