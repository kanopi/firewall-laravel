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
 * Ask whether a given request would be blocked, and by what.
 *
 * Safe to point at a production config: the script swaps storage for a
 * throwaway store by default, so checking an address cannot ban it. Pass
 * `--live-storage` to consult the durable blocklist, and read the warning it
 * prints — a blocked verdict is then recorded for real.
 *
 * `--lint` answers a different question entirely and takes no request: what is
 * wrong with these rules, regardless of any request.
 */
final class CheckCommand extends FirewallCommand
{
    /**
     * @var string
     */
    protected $signature = 'firewall:check
        {--ip= : Client IP (IPv4 or IPv6). Default 127.0.0.1}
        {--url= : Path, with optional query string. Default /}
        {--method= : HTTP method. Default GET, or POST when --body is given}
        {--header=* : Request header as NAME:VALUE}
        {--body= : Request body}
        {--explain : Show every plugin that evaluated, with result and timing}
        {--lint : Report what is wrong with the rules and exit, without evaluating a request}
        {--live-storage : Consult the configured storage instead of a throwaway store}
        {--json : Machine-readable output}
        {--keep-config : Leave the dumped effective configuration on disk and print its path}';

    /**
     * @var string
     */
    protected $description = 'Check whether a request would be blocked, and by which rule';

    public function handle(): int
    {
        // `firewall-check` takes its config as `--config=FILE` rather than
        // positionally, alone among the scripts. Normalising that upstream
        // would be a breaking change to a documented interface for no gain, so
        // it is handled here.
        return $this->runFirewallBinary(
            'firewall-check',
            $this->forwardOptions(
                flags: ['explain', 'lint', 'live-storage', 'json'],
                values: ['ip', 'url', 'method', 'body'],
                repeatable: ['header']
            ),
            configAsOption: true
        );
    }
}
