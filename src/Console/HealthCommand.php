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
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Laravel\Support\HealthReport;

/**
 * Report whether the running firewall is actually doing its job.
 *
 * ## Why this is not `firewall:doctor`
 *
 * The two look similar and answer different questions, and the difference is
 * the reason both exist:
 *
 * - `firewall:doctor` asks **is this configured correctly**. It is a deploy
 *   gate: run it once, read the prose, fix what it names. Its output is a list
 *   of diagnoses written for a person.
 * - `firewall:health` asks **is this working right now**. It is a monitoring
 *   probe: run it every minute, and the only thing consuming it is a script.
 *   Its output is a fixed, flat shape — `healthy`, `mode`, `panic_switch`,
 *   `failed_rules`, `degraded_backends` — that a check can key off without
 *   parsing sentences.
 *
 * It also reports one thing the doctor cannot: `getDegradedBackends()`, the
 * backends that constructed successfully and cannot reach their store. Those
 * are invisible to every static check, because the plugin using them built
 * perfectly — a rate limit rule reporting healthy while it counts nothing.
 *
 * ## Not for a request path
 *
 * Answering builds every rule, because rules are constructed lazily and a
 * firewall that has evaluated nothing has nothing that could have failed yet.
 * Building a rule is what opens its storage connection, which is what makes the
 * answer worth having — and what makes this a command rather than middleware.
 */
final class HealthCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'firewall:health
        {--json : Machine-readable output, for a monitoring probe}
        {--strict : Treat warnings as failures too}';

    /**
     * @var string
     */
    protected $description = 'Report whether the running firewall is healthy';

    public function handle(): int
    {
        $report = (new HealthReport($this->laravel->make(Firewall::class)))->toArray();

        if ((bool) $this->option('json')) {
            $this->line((string) json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } else {
            $this->render($report);
        }

        // A degraded backend is a warning, not a failure: the firewall is still
        // enforcing every rule that does not depend on that store, which is the
        // degrade the library chose deliberately. Paging somebody at 3am because
        // Redis blipped while the block list kept working is how a monitor gets
        // muted. `--strict` is there for the deployments that do want it.
        if ($report['errors'] !== []) {
            return FirewallCommand::EXIT_ERROR;
        }

        return (bool) $this->option('strict') && $report['warnings'] !== []
            ? FirewallCommand::EXIT_ERROR
            : FirewallCommand::EXIT_OK;
    }

    /**
     * Print the report for a person.
     *
     * The parameter carries `HealthReport::toArray()`'s shape rather than a
     * loose `array<string, mixed>`, so the values are already narrowed on
     * arrival. The looser type needed a helper to re-check each one at runtime,
     * and those checks were unreachable: the report is built by a method that
     * declares exactly what it returns. Restating the shape here is a little
     * verbose and keeps the two honest about each other.
     *
     * @param array{
     *     healthy: bool,
     *     mode: string,
     *     configured_mode: string,
     *     mode_overridden: bool,
     *     errors: array<int, string>,
     *     warnings: array<int, string>
     * } $report
     */
    private function render(array $report): void
    {
        $this->components->twoColumnDetail(
            'Firewall',
            $report['healthy'] ? '<fg=green;options=bold>HEALTHY</>' : '<fg=red;options=bold>UNHEALTHY</>'
        );

        $this->components->twoColumnDetail(
            'Mode',
            // Both are shown when they differ, because the effective mode alone
            // cannot distinguish "somebody configured log" from "somebody is
            // holding the panic switch down", and only one of those is meant to
            // be temporary.
            $report['mode_overridden']
                ? sprintf('%s <fg=gray>(configured: %s)</>', $report['mode'], $report['configured_mode'])
                : $report['mode']
        );

        foreach ($report['errors'] as $error) {
            $this->components->error($error);
        }

        foreach ($report['warnings'] as $warning) {
            $this->components->warn($warning);
        }

        if ($report['errors'] === [] && $report['warnings'] === []) {
            $this->components->twoColumnDetail(
                'Every configured rule is running and every backend reachable',
                '<fg=green>OK</>'
            );
        }
    }
}
