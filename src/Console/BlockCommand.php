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
 * See who is blocked.
 *
 * Plural, and separate from `firewall:block`, because they do opposite things:
 * this one reads the list, and the singular one adds to it. Overloading a
 * single `firewall:block` with both — an argument to add, a flag to list —
 * would make the destructive reading of a bare typo the easy one to reach.
 *
 * Reads and writes the **real** storage backend, unlike `firewall:check`, which
 * swaps in a throwaway store so that asking a question cannot ban anybody. That
 * is the point of it: it is the command for the moment somebody is on the phone
 * about a customer who cannot check out.
 *
 * `--lift` is kept here as well as in `firewall:unblock` because it is the
 * script's own flag and this command is a wrapper around that script; the
 * dedicated command is the one to reach for, and is what the documentation
 * shows.
 */
final class BlockCommand extends FirewallCommand
{
    /**
     * @var string
     */
    protected $signature = 'firewall:blocks
        {--list : Every block currently in force. The default when no action is given}
        {--find= : Blocks matching an address or CIDR range}
        {--show= : One address, with when it offended}
        {--lift=* : Remove blocks matching an address or CIDR range}
        {--dry-run : With --lift, report what would go without removing it}
        {--json : Machine-readable output}
        {--keep-config : Leave the dumped effective configuration on disk and print its path}';

    /**
     * @var string
     */
    protected $description = 'List and inspect firewall blocks';

    public function handle(): int
    {
        return $this->runFirewallBinary('firewall-block', $this->forwardOptions(
            flags: ['list', 'dry-run', 'json'],
            values: ['find', 'show'],
            repeatable: ['lift']
        ));
    }
}
