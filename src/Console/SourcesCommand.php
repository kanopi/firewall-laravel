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
 * Refresh every rule source the configuration declares, out of band.
 *
 * Sources can refresh themselves on a TTL while requests are being served, and
 * that is the worse arrangement: a cold or expired cache makes a visitor wait
 * on somebody else's HTTP server, and an expiry under load sends every
 * concurrent request after the same URL at once.
 *
 * Schedule this instead — in `routes/console.php` or `app/Console/Kernel.php` —
 * and pair it with `sources.offline: true` in the global config, so the runtime
 * reads cached results and never opens a socket:
 *
 *     Schedule::command('firewall:sources')->hourly();
 */
final class SourcesCommand extends FirewallCommand
{
    /**
     * @var string
     */
    protected $signature = 'firewall:sources
        {--force : Revalidate even when a cached copy is still fresh}
        {--dry-run : Report what would be fetched without writing the cache}
        {--cache-dir= : Write to this directory instead of the configured cache location}
        {--quiet-output : Only report failures}
        {--keep-config : Leave the dumped effective configuration on disk and print its path}';

    /**
     * @var string
     */
    protected $description = 'Refresh the firewall rule sources declared in config';

    public function handle(): int
    {
        return $this->runFirewallBinary('firewall-sources', array_merge(
            $this->forwardOptions(
                flags: ['force', 'dry-run'],
                values: ['cache-dir']
            ),
            // Renamed from the script's `--quiet` because Symfony Console
            // reserves that name for its own verbosity flag, and an Artisan
            // command cannot redeclare it.
            (bool) $this->option('quiet-output') ? ['--quiet'] : []
        ));
    }
}
