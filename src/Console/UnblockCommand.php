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
 * Let a client back in.
 *
 * Accepts a range as well as an address, because lifting matches against what
 * is already stored rather than creating a key — `10.0.0.0/8` means "everything
 * in the list inside this range". That asymmetry with `firewall:block`, which
 * refuses ranges, is not an inconsistency: a range cannot be *stored* as a
 * block because lookups are exact, but it is exactly the right shape for
 * *finding* blocks to remove.
 *
 * `--all` empties the list. It lifts every address rather than resetting the
 * backend, which would also discard offense history — and that history is what
 * drives escalating bans, so resetting it would quietly reward every address
 * that has ever misbehaved.
 */
final class UnblockCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'firewall:unblock
        {ip? : The address or CIDR range to lift. Omit it with --all}
        {--all : Lift every block currently in force}
        {--dry-run : Report what would be lifted without lifting it}';

    /**
     * @var string
     */
    protected $description = 'Lift a firewall block';

    public function handle(BlockManager $blocks): int
    {
        $ip = $this->argument('ip');
        $pattern = is_string($ip) ? trim($ip) : '';
        $all = (bool) $this->option('all');

        // Refused rather than resolved either way round. Guessing that `--all`
        // wins would empty the list for somebody who typed an address; guessing
        // the address wins would ignore a flag they passed deliberately. Both
        // are worse than asking again.
        if ($all && $pattern !== '') {
            $this->components->error('Pass either an address or --all, not both.');

            return FirewallCommand::EXIT_CONFIG_UNREADABLE;
        }

        if (!$all && $pattern === '') {
            $this->components->error(
                'Name an address or range to lift, or pass --all to empty the list.'
            );

            return FirewallCommand::EXIT_CONFIG_UNREADABLE;
        }

        $dryRun = (bool) $this->option('dry-run');

        try {
            $lifted = $all
                ? $blocks->clear($dryRun)
                : $blocks->remove($pattern, $dryRun);
        } catch (FirewallException $exception) {
            $this->components->error($exception->getMessage());

            return FirewallCommand::EXIT_ERROR;
        }

        if ($lifted === 0) {
            // Not an error. "Nothing matched" is a complete and useful answer to
            // "is this address blocked?", and exiting non-zero would make a
            // deploy step that lifts an address defensively fail once the
            // address is no longer listed.
            $this->components->info($all
                ? 'The block list is already empty.'
                : sprintf('Nothing in the block list matches %s.', $pattern));

            return FirewallCommand::EXIT_OK;
        }

        $this->components->info(sprintf(
            '%s %d block%s%s.',
            $dryRun ? 'Would lift' : 'Lifted',
            $lifted,
            $lifted === 1 ? '' : 's',
            $all ? '' : sprintf(' matching %s', $pattern)
        ));

        if ($dryRun) {
            $this->components->warn('Dry run — nothing was changed.');
        }

        return FirewallCommand::EXIT_OK;
    }
}
