<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\Http\Middleware\EvaluateFirewall;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use Symfony\Component\HttpFoundation\Response;

/**
 * End-to-end tests for the middleware, through a real HTTP kernel pass.
 *
 * Deliberately driven through `$this->get(...)` rather than by calling
 * `handle()` with a hand-made request. The three things most likely to be
 * wrong here are all properties of the assembled stack rather than of the
 * class: whether the middleware runs at all, whether it runs after
 * TrustProxies, and whether the response it returns survives the rest of the
 * pipeline. None of those is observable from a unit test of `handle()`.
 */
final class MiddlewareTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        $router->get('/allowed', static fn (): string => 'through');
        $router->get('/wp-login.php', static fn (): string => 'through');
    }

    #[Test]
    public function an_allowed_request_reaches_the_application(): void
    {
        $this->get('/allowed')->assertOk()->assertSee('through');
    }

    /**
     * The whole point of trap 1: `block` mode must never reach `exit()`.
     *
     * A firewall that called `exit()` here would produce a response with no
     * status, no headers and a truncated body — and, critically, the test
     * process itself would terminate. So this test passing at all is part of
     * what it asserts.
     */
    #[Test]
    public function a_blocked_request_is_rendered_by_laravel(): void
    {
        $this->blockIp('127.0.0.1');

        $response = $this->get('/allowed');

        // 400, not 403: that is FirewallBlockedException's own default status,
        // used when no rule and no global config asks for another. Asserted as
        // the concrete number rather than "any 4xx" because the status is the
        // part of a block that a CDN, a monitoring check and an error tracker
        // all key off.
        $response->assertStatus(400);
        $response->assertDontSee('through');
        $response->assertHeader('Content-Type', 'text/html; charset=utf-8');
    }

    #[Test]
    public function a_blocked_request_never_reaches_the_route(): void
    {
        $this->blockIp('127.0.0.1');

        Route::get('/never', static function (): string {
            throw new \LogicException('The route ran, so the firewall did not block.');
        });

        $this->get('/never')->assertStatus(400);
    }

    #[Test]
    public function a_block_honours_the_status_code_the_rule_asks_for(): void
    {
        $this->blockIp('127.0.0.1', ['metadata' => ['status_code' => 429]]);

        $this->get('/allowed')->assertStatus(429);
    }

    #[Test]
    public function a_blocked_api_client_gets_json(): void
    {
        $this->blockIp('127.0.0.1');

        $response = $this->getJson('/allowed');

        $response->assertStatus(400);
        $response->assertHeader('Cache-Control', 'no-store, private');
        $this->assertArrayHasKey('message', (array) $response->json());
    }

    #[Test]
    public function an_unrouted_path_is_still_evaluated(): void
    {
        $this->blockIp('127.0.0.1');

        // A firewall registered as route middleware would 404 here without
        // evaluating anything — and 404 is what an attacker probing for
        // /wp-admin/setup-config.php sees on a Laravel site anyway, so the
        // difference between "blocked" and "not found" is the difference
        // between a recorded offense and an unnoticed probe.
        $this->get('/no/such/route')->assertStatus(400);
    }

    #[Test]
    #[DefineEnvironment('disableFirewall')]
    public function a_disabled_firewall_lets_everything_through(): void
    {
        $this->blockIp('127.0.0.1');

        $this->get('/allowed')->assertOk()->assertSee('through');
    }

    #[Test]
    #[DefineEnvironment('modeDisabled')]
    public function disabled_mode_lets_everything_through(): void
    {
        $this->blockIp('127.0.0.1');

        $this->get('/allowed')->assertOk()->assertSee('through');
    }

    /**
     * Trap 2, asserted rather than assumed.
     *
     * PHPUnit runs under a CLI SAPI, and the library returns TRUE immediately
     * when `PHP_SAPI === 'cli'` for every mode except `exception`. So this test
     * documents the real behaviour of `log` mode under Octane on RoadRunner or
     * Swoole, whose workers run as `cli` while serving real traffic: nothing is
     * evaluated. It is the reason `block` is translated to `exception` rather
     * than left alone, and the reason `firewall:doctor` reports `log` mode
     * under a `cli` SAPI as an error.
     *
     * `artisan serve` is NOT this case — it runs as `cli-server` and does
     * evaluate. That distinction cannot be made from here, because PHPUnit is
     * always `cli`; it is asserted over HTTP in `tests/Integration/install.sh`.
     */
    #[Test]
    #[DefineEnvironment('modeLog')]
    public function log_mode_evaluates_nothing_under_a_cli_sapi(): void
    {
        $this->assertSame('cli', PHP_SAPI, 'This test only means anything under a CLI SAPI.');

        $this->blockIp('127.0.0.1');

        $this->get('/allowed')->assertOk()->assertSee('through');
    }

    /**
     * Trap 3: the ordering guard fires when proxies are declared but not applied.
     *
     * Driven by calling `handle()` directly, which is the only way to reach the
     * state being tested. Through a real kernel pass, `TrustProxies` runs first
     * and applies the declared proxies — so the misordering cannot be staged
     * from outside, and a test that tried would be asserting that the
     * middleware is correctly ordered, which `ServiceProviderTest` already
     * does. Here the Symfony static is left empty on purpose: that is exactly
     * what the firewall would see if it ran first.
     */
    #[Test]
    public function it_refuses_the_request_when_it_runs_before_trust_proxies(): void
    {
        config([
            'trustedproxy.proxies' => ['10.0.0.1'],
            'firewall.middleware.on_bad_order' => 'throw',
        ]);

        SymfonyRequest::setTrustedProxies([], SymfonyRequest::HEADER_X_FORWARDED_FOR);

        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/running before TrustProxies/');

        $this->app->make(EvaluateFirewall::class)->handle(
            Request::create('/allowed'),
            static fn (): Response => new Response('through')
        );
    }

    #[Test]
    public function it_logs_and_continues_when_ordering_is_wrong_by_default(): void
    {
        config(['trustedproxy.proxies' => ['10.0.0.1']]);

        SymfonyRequest::setTrustedProxies([], SymfonyRequest::HEADER_X_FORWARDED_FOR);

        Log::shouldReceive('error')
            ->once()
            ->withArgs(static fn (string $message): bool =>
                str_contains($message, 'running before TrustProxies'));

        $response = $this->app->make(EvaluateFirewall::class)->handle(
            Request::create('/allowed'),
            static fn (): Response => new Response('through')
        );

        // 'log' is the default policy: the request is served, because a
        // misordered stack is a deploy bug and refusing every request over it
        // is a decision an operator has to opt into.
        $this->assertSame('through', $response->getContent());
    }

    #[Test]
    public function the_guard_stays_quiet_once_trust_proxies_has_applied_them(): void
    {
        config(['trustedproxy.proxies' => ['10.0.0.1']]);

        SymfonyRequest::setTrustedProxies(['10.0.0.1'], SymfonyRequest::HEADER_X_FORWARDED_FOR);

        Log::shouldReceive('error')->never();

        $response = $this->app->make(EvaluateFirewall::class)->handle(
            Request::create('/allowed'),
            static fn (): Response => new Response('through')
        );

        $this->assertSame('through', $response->getContent());
    }

    /**
     * A forwarded address is what the rules see, once proxies are trusted.
     *
     * The positive half of trap 3. Without `setTrustedProxies()` the rule below
     * would be matching against 127.0.0.1 and this request would be allowed —
     * so a pass here is evidence that the middleware runs late enough to
     * benefit from TrustProxies, not merely that it runs.
     */
    #[Test]
    public function it_blocks_on_the_forwarded_address_when_the_proxy_is_trusted(): void
    {
        TrustProxies::at(['127.0.0.1']);

        $this->blockIp('198.51.100.7');

        $this->get('/allowed', ['X-Forwarded-For' => '198.51.100.7'])->assertStatus(400);
    }

    /**
     * And the same header is ignored when no proxy is trusted.
     */
    #[Test]
    public function it_ignores_a_forwarded_address_from_an_untrusted_source(): void
    {
        $this->blockIp('198.51.100.7');

        $this->get('/allowed', ['X-Forwarded-For' => '198.51.100.7'])->assertOk();
    }

    /**
     * A firewall that cannot start is not a verdict about the request.
     *
     * Staged with a challenge rule and no `challenge.secret`, which
     * `Firewall::create()` refuses outright. Chosen over an unwritable storage
     * path because it fails identically everywhere: a permissions-based
     * failure behaves differently when CI runs the suite as root, and a test
     * that quietly stops testing anything is worse than no test.
     */
    #[Test]
    public function a_broken_firewall_fails_closed_by_default(): void
    {
        $this->breakTheFirewall();

        $this->expectException(ConfigurationException::class);

        $this->app->make(EvaluateFirewall::class)->handle(
            Request::create('/allowed'),
            static fn (): Response => new Response('through')
        );
    }

    #[Test]
    public function a_broken_firewall_can_be_configured_to_fail_open(): void
    {
        $this->breakTheFirewall();

        config(['firewall.on_boot_failure' => 'allow']);

        Log::shouldReceive('critical')
            ->once()
            ->withArgs(static fn (string $message): bool =>
                str_contains($message, 'NOT filtered'));

        $response = $this->app->make(EvaluateFirewall::class)->handle(
            Request::create('/allowed'),
            static fn (): Response => new Response('through')
        );

        $this->assertSame('through', $response->getContent());
    }

    /**
     * Configure a firewall that `Firewall::create()` will reject.
     */
    private function breakTheFirewall(): void
    {
        config([
            'firewall.challenge.secret' => '',
            'firewall.plugins' => [[
                'plugin' => \Kanopi\Firewall\Plugins\Url::class,
                'response' => 'challenge',
                'name' => 'needs-a-secret',
                'config' => ['path:/allowed'],
            ]],
        ]);
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function disableFirewall($app): void
    {
        $app['config']->set('firewall.enabled', false);
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function modeDisabled($app): void
    {
        $app['config']->set('firewall.global.mode', 'disabled');
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function modeLog($app): void
    {
        $app['config']->set('firewall.global.mode', 'log');
    }




}
