<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Kanopi\Firewall\Laravel\Console\FirewallCommand;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage;
use Kanopi\Firewall\Utility\DegradedBackends;
use PHPUnit\Framework\Attributes\Test;

/**
 * `firewall:health` — the monitoring probe.
 *
 * The exit code is the interface here. Everything else this command prints is
 * for a person who has already been paged by the exit code, so that is what
 * most of these assert.
 */
final class HealthCommandTest extends TestCase
{
    protected function tearDown(): void
    {
        DegradedBackends::reset();

        parent::tearDown();
    }

    #[Test]
    public function a_healthy_firewall_exits_zero(): void
    {
        $this->blockIp('198.51.100.1');

        $this->artisan('firewall:health')
            ->expectsOutputToContain('HEALTHY')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function it_reports_the_effective_mode(): void
    {
        $this->artisan('firewall:health')
            ->expectsOutputToContain('exception')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function it_says_so_when_there_is_nothing_to_report(): void
    {
        $this->artisan('firewall:health')
            ->expectsOutputToContain('Every configured rule is running')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * A rule that cannot be built is a failure, and the exit code says so.
     *
     * This is the condition the command exists for: the firewall answers every
     * request, looks entirely healthy, and is running one rule short.
     */
    #[Test]
    public function a_rule_that_cannot_be_built_exits_non_zero(): void
    {
        config(['firewall.plugins' => [[
            'plugin' => \Kanopi\Firewall\Plugins\RateLimit::class,
            'response' => 'block',
            'metadata' => [
                'storage' => [
                    'type' => \Kanopi\Firewall\RateLimitStorage\FileRateLimitStorage::class,
                    'config' => ['file' => '/dev/null/nope/ratelimit.data'],
                ],
            ],
            'config' => [['type' => 'AND', 'rules' => ['path:/x']]],
        ]]]);

        $this->artisan('firewall:health')
            ->expectsOutputToContain('UNHEALTHY')
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    /**
     * A degraded backend is a warning, and exits zero by default.
     *
     * The firewall is still enforcing every rule that does not depend on that
     * store, which is the degrade the library chose on purpose. Paging somebody
     * because Redis blipped while the block list kept working is how a monitor
     * gets muted.
     */
    #[Test]
    public function a_degraded_backend_exits_zero_by_default(): void
    {
        DegradedBackends::record('rate limit', RedisRateLimitStorage::class, 'Connection refused');

        $this->artisan('firewall:health')
            ->expectsOutputToContain('running without its store')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function strict_mode_turns_a_warning_into_a_failure(): void
    {
        DegradedBackends::record('rate limit', RedisRateLimitStorage::class, 'Connection refused');

        $this->artisan('firewall:health', ['--strict' => true])
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function strict_mode_still_exits_zero_when_there_is_nothing_to_report(): void
    {
        $this->artisan('firewall:health', ['--strict' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * The JSON shape is the contract a monitoring check is written against.
     *
     * Asserted key by key rather than loosely, because a rename here silently
     * breaks every check keyed off it — and a check that stopped evaluating
     * reports "healthy" forever.
     */
    #[Test]
    public function json_output_carries_the_documented_shape(): void
    {
        $this->artisan('firewall:health', ['--json' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $report = json_decode($this->jsonFrom('firewall:health'), true);

        $this->assertIsArray($report);

        foreach ([
            'healthy',
            'mode',
            'configured_mode',
            'mode_overridden',
            'panic_switch',
            'failed_rules',
            'degraded_backends',
            'errors',
            'warnings',
        ] as $key) {
            $this->assertArrayHasKey($key, $report);
        }

        $this->assertTrue($report['healthy']);
        $this->assertSame('exception', $report['mode']);
        $this->assertIsArray($report['panic_switch']);
        $this->assertArrayHasKey('active', $report['panic_switch']);
    }

    /**
     * An active panic switch is reported with both modes.
     *
     * The effective mode alone cannot distinguish "somebody configured log"
     * from "somebody is holding the switch down", and only one of those is
     * supposed to be temporary.
     */
    #[Test]
    public function an_active_panic_switch_shows_the_configured_mode_too(): void
    {
        $panic = tempnam(sys_get_temp_dir(), 'fw-panic-');
        $this->assertIsString($panic);
        file_put_contents($panic, "log\n");

        try {
            config(['firewall.global.panic_file' => $panic]);

            $this->artisan('firewall:health')
                ->expectsOutputToContain('configured: exception')
                ->expectsOutputToContain('panic switch is ACTIVE')
                ->assertExitCode(FirewallCommand::EXIT_OK);
        } finally {
            unlink($panic);
        }
    }

    /**
     * A panic file that did nothing is an error, not a warning.
     *
     * Somebody reached for the switch and it did not take. They are watching
     * the site, not the logs, so this has to page.
     */
    #[Test]
    public function a_panic_file_that_was_not_applied_exits_non_zero(): void
    {
        $panic = tempnam(sys_get_temp_dir(), 'fw-panic-');
        $this->assertIsString($panic);
        file_put_contents($panic, "not-a-mode\n");

        try {
            config(['firewall.global.panic_file' => $panic]);

            $this->artisan('firewall:health')
                ->assertExitCode(FirewallCommand::EXIT_ERROR);
        } finally {
            unlink($panic);
        }
    }

    /**
     * Capture a command's stdout.
     *
     * `Artisan::output()` is the only way to read what a command wrote;
     * `PendingCommand` asserts against output but does not hand it back.
     */
    private function jsonFrom(string $command): string
    {
        \Illuminate\Support\Facades\Artisan::call($command, ['--json' => true]);

        return \Illuminate\Support\Facades\Artisan::output();
    }
}
