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
 * Bring the firewall's own tables up to the schema this release declares.
 *
 * Nothing to do with Laravel's migrations, and deliberately not wired into
 * them. The firewall's tables are created on first write by the storage
 * backend that owns them, and their schema is declared on those classes rather
 * than in a migration file — so a Laravel migration would be a second
 * description of the same schema, and the two would disagree the first time
 * the library added a column.
 *
 * Only ever additive: it adds missing columns and indexes and never drops,
 * renames or rewrites anything, so no sequence of runs can lose a row.
 *
 * `--dry-run` exits 3 when changes are pending, which makes it usable as a
 * deploy gate: run it before the deploy, and a non-zero exit means the schema
 * needs bringing forward.
 */
final class MigrateCommand extends FirewallCommand
{
    /**
     * @var string
     */
    protected $signature = 'firewall:migrate
        {--dry-run : Report what is missing, and the statements, without running them}
        {--quiet-output : Only report changes and failures}
        {--keep-config : Leave the dumped effective configuration on disk and print its path}';

    /**
     * @var string
     */
    protected $description = 'Apply pending schema changes to the firewall tables';

    public function handle(): int
    {
        return $this->runFirewallBinary('firewall-migrate', array_merge(
            $this->forwardOptions(flags: ['dry-run']),
            (bool) $this->option('quiet-output') ? ['--quiet'] : []
        ));
    }
}
