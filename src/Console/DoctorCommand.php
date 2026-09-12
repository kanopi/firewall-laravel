<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Console;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Laravel\Diagnostics\IntegrationDoctor;

/**
 * Diagnose the firewall, and the Laravel wiring around it.
 *
 * The only command here that does more than forward to a script. It runs two
 * doctors and prints one report:
 *
 *  - The **integration** checks, which are this package's: middleware ordering
 *    against TrustProxies, whether a challenge submission can reach the
 *    firewall, whether the panic switch is connected to anything under Octane,
 *    whether the CLI short-circuit is quietly disabling the whole thing.
 *  - The library's own `bin/firewall-doctor`, which checks the firewall:
 *    storage reachability, GeoIP freshness, rules that will not build.
 *
 * They are run in that order deliberately. An integration failure invalidates
 * the library's findings — a firewall whose middleware never runs is
 * perfectly healthy and completely ineffective — so the operator should read
 * about the wiring before reading a clean bill of health about the rules.
 */
final class DoctorCommand extends FirewallCommand
{
    /**
     * @var string
     */
    protected $signature = 'firewall:doctor
        {--json : Machine-readable output}
        {--quiet-checks : Only show warnings and errors}
        {--integration-only : Skip the library checks and only verify the Laravel wiring}
        {--keep-config : Leave the dumped effective configuration on disk and print its path}';

    /**
     * @var string
     */
    protected $description = 'Diagnose the firewall and its Laravel integration';

    public function handle(): int
    {
        $findings = $this->laravel->make(IntegrationDoctor::class)->run();

        $json = (bool) $this->option('json');

        if ($json) {
            $this->line((string) json_encode(
                ['integration' => array_map(
                    static fn (Diagnosis $diagnosis): array => $diagnosis->toArray(),
                    $findings
                )],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
            ));
        } else {
            $this->renderFindings($findings);
        }

        $integrationFailed = $this->hasError($findings);

        if ((bool) $this->option('integration-only')) {
            return $integrationFailed ? self::EXIT_ERROR : self::EXIT_OK;
        }

        if (!$json) {
            $this->newLine();
            $this->components->info('Library checks (bin/firewall-doctor)');
        }

        // array_merge, not `+`: both halves are integer-keyed lists, and `+`
        // would keep only the first array's element at each index — silently
        // dropping --quiet whenever --json was also given.
        $libraryExit = $this->runFirewallBinary('firewall-doctor', array_merge(
            $this->forwardOptions(flags: ['json']),
            (bool) $this->option('quiet-checks') ? ['--quiet'] : []
        ));

        // The worse of the two. A green library report does not redeem a
        // middleware that runs before TrustProxies, and this command is meant
        // to be usable as a deploy gate — so it must fail if either half does.
        return max($libraryExit, $integrationFailed ? self::EXIT_ERROR : self::EXIT_OK);
    }

    /**
     * Print the integration findings.
     *
     * @param array<int, Diagnosis> $findings
     */
    private function renderFindings(array $findings): void
    {
        $this->components->info('Laravel integration checks');

        $quiet = (bool) $this->option('quiet-checks');
        $shown = 0;

        foreach ($findings as $finding) {
            if ($quiet && $finding->status === Diagnosis::OK) {
                continue;
            }

            ++$shown;
            $this->renderFinding($finding);
        }

        if ($shown === 0) {
            $this->components->twoColumnDetail('Nothing to report', '<fg=green>OK</>');
        }

        $tally = array_count_values(array_map(
            static fn (Diagnosis $diagnosis): string => $diagnosis->status,
            $findings
        ));

        $this->newLine();
        $this->line(sprintf(
            '  <fg=green>%d ok</>, <fg=yellow>%d warning</>, <fg=red>%d error</>',
            $tally[Diagnosis::OK] ?? 0,
            $tally[Diagnosis::WARNING] ?? 0,
            $tally[Diagnosis::ERROR] ?? 0
        ));
    }

    private function renderFinding(Diagnosis $diagnosis): void
    {
        $label = match ($diagnosis->status) {
            Diagnosis::ERROR => '<fg=red;options=bold>ERROR</>',
            Diagnosis::WARNING => '<fg=yellow;options=bold>WARN</>',
            default => '<fg=green>OK</>',
        };

        $this->components->twoColumnDetail($diagnosis->title, $label);

        if ($diagnosis->detail !== null) {
            // Wrapped at 96 rather than left to the terminal, because these
            // details are paragraphs of remediation advice and an unwrapped
            // one is unreadable in a CI log with no terminal width to report.
            foreach (explode("\n", wordwrap($diagnosis->detail, 96)) as $line) {
                $this->line('    <fg=gray>' . $line . '</>');
            }
        }

        if ($diagnosis->reference !== null) {
            $this->line('    <fg=blue>see: https://github.com/kanopi/firewall/blob/2.x/' . $diagnosis->reference . '</>');
        }
    }

    /**
     * @param array<int, Diagnosis> $findings
     */
    private function hasError(array $findings): bool
    {
        foreach ($findings as $finding) {
            if ($finding->status === Diagnosis::ERROR) {
                return true;
            }
        }

        return false;
    }
}
