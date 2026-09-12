<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Laravel\Support\HealthReport;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The health snapshot a status endpoint would serve.
 *
 * The condition being reported is the one a firewall is worst at announcing: a
 * rule that is not running, or is running blind, looks exactly like a rule that
 * is working. Nothing in the request path can tell the difference, which is why
 * this exists and why it is not cheap enough to call from one.
 */
final class HealthReportTest extends TestCase
{
    #[Test]
    public function a_healthy_firewall_reports_healthy(): void
    {
        $this->blockIp('198.51.100.1');

        $report = $this->report();

        $this->assertTrue($report['healthy']);
        $this->assertSame([], $report['failed_rules']);
        $this->assertSame([], $report['errors']);
    }

    #[Test]
    public function it_reports_the_effective_and_configured_modes(): void
    {
        $report = $this->report();

        // Both `exception`, because that is what `block` is delivered as and
        // the panic switch is not involved. `configured_mode` is the library's
        // view of what it was asked for, which is the translated value — the
        // untranslated one is reported by `firewall:doctor` instead.
        $this->assertSame('exception', $report['mode']);
        $this->assertSame('exception', $report['configured_mode']);
        $this->assertFalse($report['mode_overridden']);
    }

    /**
     * A rule that cannot be built is unhealthy, and names itself.
     *
     * The plugin index in the name is what makes two rules of the same class
     * distinguishable — `IpAddress:1` is the second entry, not the second rule
     * of that type.
     */
    #[Test]
    public function a_rule_that_cannot_be_built_is_reported_as_not_running(): void
    {
        config(['firewall.plugins' => [
            [
                'plugin' => \Kanopi\Firewall\Plugins\IpAddress::class,
                'response' => 'block',
                'config' => ['198.51.100.1'],
            ],
            [
                'plugin' => \Kanopi\Firewall\Plugins\RateLimit::class,
                'response' => 'block',
                'metadata' => [
                    'storage' => [
                        'type' => \Kanopi\Firewall\RateLimitStorage\FileRateLimitStorage::class,
                        'config' => ['file' => '/dev/null/nope/ratelimit.data'],
                    ],
                ],
                'config' => [['type' => 'AND', 'rules' => ['path:/x']]],
            ],
        ]]);

        $report = $this->report();

        $this->assertFalse($report['healthy']);
        $this->assertNotSame([], $report['failed_rules']);
        $this->assertSame('block', $report['failed_rules'][0]['bucket']);
        $this->assertStringContainsString('RateLimit', $report['failed_rules'][0]['plugin']);
        $this->assertNotSame([], $report['errors']);
        $this->assertStringContainsString('is not running', $report['errors'][0]);
    }

    #[Test]
    public function an_active_panic_switch_is_a_warning_not_a_failure(): void
    {
        $panic = tempnam(sys_get_temp_dir(), 'fw-panic-');
        $this->assertIsString($panic);
        file_put_contents($panic, "log\n");

        try {
            config(['firewall.global.panic_file' => $panic]);

            $report = $this->report();

            // Still healthy: every rule is running. The switch is doing what it
            // was asked to, and the risk it carries is that nobody notices it
            // is still down in three weeks — which is a warning's job.
            $this->assertTrue($report['healthy']);
            $this->assertTrue($report['panic_switch']['active']);
            $this->assertSame('log', $report['panic_switch']['mode']);
            $this->assertSame($panic, $report['panic_switch']['path']);
            $this->assertTrue($report['mode_overridden']);
            $this->assertSame('log', $report['mode']);
            $this->assertStringContainsString('panic switch is ACTIVE', $report['warnings'][0]);
        } finally {
            unlink($panic);
        }
    }

    /**
     * A panic file that did nothing is an error, not a warning.
     *
     * Somebody reached for the switch and it did not take. They are watching
     * the site, not the logs, so this has to be loud.
     */
    #[Test]
    public function a_panic_file_that_was_not_applied_is_an_error(): void
    {
        $panic = tempnam(sys_get_temp_dir(), 'fw-panic-');
        $this->assertIsString($panic);
        file_put_contents($panic, "not-a-mode\n");

        try {
            config(['firewall.global.panic_file' => $panic]);

            $report = $this->report();

            $this->assertFalse($report['panic_switch']['active']);
            $this->assertNotNull($report['panic_switch']['problem']);
            $this->assertNotSame([], $report['errors']);
            $this->assertStringContainsString('was not applied', $report['errors'][0]);
        } finally {
            unlink($panic);
        }
    }

    #[Test]
    public function no_panic_file_reports_an_inactive_switch(): void
    {
        $report = $this->report();

        $this->assertFalse($report['panic_switch']['active']);
        $this->assertNull($report['panic_switch']['mode']);
        $this->assertNull($report['panic_switch']['problem']);
        $this->assertSame([], $report['warnings']);
    }

    /**
     * A backend that is running but cannot reach its store is a warning.
     *
     * This is the condition `getFailedRules()` cannot see: `RedisStorage` and
     * `RedisRateLimitStorage` catch a connection failure, log it, and answer
     * every read as though nothing were stored — so the plugin constructs
     * fine, the rule reports healthy, and a rate limit counts nothing.
     *
     * Registered through the library's own `DegradedBackends::record()` rather
     * than by pointing a Redis backend at a dead host. Two reasons: ext-redis
     * is not installed everywhere this suite runs, so a real connection
     * failure would be an environment-dependent test that quietly stops
     * testing anything; and the behaviour under test is how the health report
     * *presents* a degraded backend, not how Redis fails.
     */
    #[Test]
    public function a_degraded_backend_is_a_warning_and_still_healthy(): void
    {
        \Kanopi\Firewall\Utility\DegradedBackends::reset();
        \Kanopi\Firewall\Utility\DegradedBackends::record(
            'rate limit',
            \Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage::class,
            'Connection refused'
        );

        try {
            $report = $this->report();

            // Still healthy: every rule is running. A degraded backend means
            // the firewall is enforcing everything that does not depend on
            // that store, which is the degrade the library chose on purpose.
            $this->assertTrue($report['healthy']);
            $this->assertNotSame([], $report['degraded_backends']);
            $this->assertStringContainsString('running without its store', $report['warnings'][0]);
            $this->assertStringContainsString('Connection refused', $report['warnings'][0]);
            $this->assertStringContainsString('rate limit', $report['warnings'][0]);
        } finally {
            \Kanopi\Firewall\Utility\DegradedBackends::reset();
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function report(): array
    {
        return (new HealthReport($this->app->make(Firewall::class)))->toArray();
    }
}
