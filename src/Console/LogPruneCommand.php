<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Console;

/**
 * Delete firewall log rows older than the retention window.
 *
 * Applies to the library's own `DatabaseHandler`, and only to handlers declared
 * in `firewall.logger.handlers`. A deployment that logs through a borrowed
 * Laravel channel — the default — has no such handler, and this will correctly
 * report that there is nothing to prune. See the note in `RunsFirewallBinary`
 * on why the borrowed handlers cannot be described to the script.
 *
 * `DatabaseHandler` can also prune itself on a fraction of writes, which needs
 * no scheduling. This is the honest version of the same job: it runs when you
 * say it runs and it tells you how many rows went. Set `prune_probability: 0`
 * on the handler and pruning happens only here.
 */
final class LogPruneCommand extends FirewallCommand
{
    /**
     * @var string
     */
    protected $signature = 'firewall:log-prune
        {--days= : Prune to this many days instead of each handler\'s retention_days}
        {--dry-run : Report what would be deleted without deleting it}
        {--quiet-output : Only report failures}
        {--keep-config : Leave the dumped effective configuration on disk and print its path}';

    /**
     * @var string
     */
    protected $description = 'Prune old rows from the firewall log table';

    public function handle(): int
    {
        return $this->runFirewallBinary('firewall-log-prune', array_merge(
            $this->forwardOptions(flags: ['dry-run'], values: ['days']),
            (bool) $this->option('quiet-output') ? ['--quiet'] : []
        ));
    }
}
