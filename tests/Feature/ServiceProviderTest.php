<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Facades\Route;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Laravel\Config\LogHandlers;
use Kanopi\Firewall\Laravel\Config\TrustedProxies;
use Kanopi\Firewall\Laravel\Diagnostics\IntegrationDoctor;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\FirewallFactory;
use Kanopi\Firewall\Laravel\FirewallServiceProvider;
use Kanopi\Firewall\Laravel\Http\FirewallResponder;
use Kanopi\Firewall\Laravel\Http\Middleware\EvaluateFirewall;
use Kanopi\Firewall\Laravel\Support\Settings;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\Test;

final class ServiceProviderTest extends TestCase
{
    #[Test]
    public function it_merges_the_package_config(): void
    {
        $this->assertSame('/_firewall/challenge', config('firewall.challenge.path'));
        $this->assertTrue(config('firewall.middleware.global'));
    }

    /**
     * Every documented section survives the merge into a booted application.
     *
     * Asserted here rather than by `require`ing the file, because it calls
     * `storage_path()` and `base_path()` and so only produces its real values
     * inside an application. `ShippedConfigTest` covers what can be checked
     * from the source alone.
     */
    #[Test]
    public function the_published_config_declares_every_documented_section(): void
    {
        $config = config('firewall');

        $this->assertIsArray($config);

        foreach ([
            'enabled',
            'on_boot_failure',
            'global',
            'presets',
            'configs',
            'storage',
            'plugins',
            'challenge',
            'logger',
            'middleware',
            'octane',
            'views',
            'artisan',
        ] as $section) {
            $this->assertArrayHasKey($section, $config);
        }
    }

    /**
     * The firewall logs somewhere on a default installation.
     *
     * The regression this pins: the shipped default read
     * `config('logging.default')`, which returns NULL because Laravel loads
     * config files alphabetically and `firewall.php` comes before
     * `logging.php`. The firewall enforced perfectly and reported nothing.
     *
     * Read from the file rather than from `config()`, because the base
     * TestCase sets the channel to NULL to keep the suite's own logging quiet —
     * so asserting on the resolved value would assert on the test harness.
     */
    #[Test]
    public function the_shipped_default_log_channel_resolves(): void
    {
        $shipped = require dirname(__DIR__, 2) . '/config/firewall.php';

        $this->assertIsArray($shipped);
        $this->assertIsArray($shipped['logger']);
        $this->assertSame(
            'stack',
            $shipped['logger']['channel'],
            'A default installation must log somewhere.'
        );
    }

    #[Test]
    public function it_binds_every_service(): void
    {
        $this->assertInstanceOf(FirewallFactory::class, $this->app->make(FirewallFactory::class));
        $this->assertInstanceOf(Settings::class, $this->app->make(Settings::class));
        $this->assertInstanceOf(TrustedProxies::class, $this->app->make(TrustedProxies::class));
        $this->assertInstanceOf(LogHandlers::class, $this->app->make(LogHandlers::class));
        $this->assertInstanceOf(IntegrationDoctor::class, $this->app->make(IntegrationDoctor::class));
        $this->assertInstanceOf(FirewallResponder::class, $this->app->make(FirewallResponder::class));
        $this->assertInstanceOf(Firewall::class, $this->app->make(Firewall::class));
    }

    #[Test]
    public function the_firewall_is_the_same_instance_within_one_request(): void
    {
        $this->assertSame($this->app->make(Firewall::class), $this->app->make(Firewall::class));
    }

    /**
     * The Octane answer, asserted rather than described.
     *
     * A scoped binding is what makes the panic switch work: Octane flushes
     * scoped instances between requests, so the panic file is re-read. This
     * asserts the binding is registered in the container's scoped list, which
     * is the property Octane acts on — checking that two `make()` calls return
     * the same object would pass for a plain singleton too and prove nothing.
     */
    #[Test]
    public function the_firewall_is_scoped_so_octane_rebuilds_it_per_request(): void
    {
        $this->assertContains(Firewall::class, $this->scopedInstances());
    }

    #[Test]
    #[DefineEnvironment('persistInstance')]
    public function persist_instance_binds_a_true_singleton_instead(): void
    {
        $this->assertNotContains(Firewall::class, $this->scopedInstances());

        // Still one instance per request under PHP-FPM, so the difference is
        // invisible there — which is why the binding list is what gets
        // asserted rather than the behaviour of two make() calls.
        $this->assertSame($this->app->make(Firewall::class), $this->app->make(Firewall::class));
    }

    #[Test]
    public function it_appends_the_middleware_after_trust_proxies(): void
    {
        $kernel = $this->app->make(HttpKernelContract::class);
        $this->assertInstanceOf(HttpKernel::class, $kernel);

        $stack = $this->globalMiddleware($kernel);

        $this->assertContains(EvaluateFirewall::class, $stack);
        $this->assertGreaterThan(
            array_search(TrustProxies::class, $stack, true),
            array_search(EvaluateFirewall::class, $stack, true),
            'The firewall must evaluate after TrustProxies or every IP rule reads a spoofable address.'
        );
    }

    #[Test]
    #[DefineEnvironment('withoutGlobalMiddleware')]
    public function it_does_not_register_global_middleware_when_disabled(): void
    {
        $kernel = $this->app->make(HttpKernelContract::class);
        $this->assertInstanceOf(HttpKernel::class, $kernel);

        $this->assertNotContains(EvaluateFirewall::class, $this->globalMiddleware($kernel));
    }

    #[Test]
    public function it_registers_the_challenge_route(): void
    {
        $route = $this->app->make('router')->getRoutes()->getByName('firewall.challenge');

        $this->assertNotNull($route);
        $this->assertSame(['POST'], $route->methods());
        $this->assertContains(EvaluateFirewall::class, $route->gatherMiddleware());
    }

    /**
     * The route must not pick up the `web` group, or CSRF rejects every solve.
     */
    #[Test]
    public function the_challenge_route_carries_no_csrf_middleware(): void
    {
        $route = $this->app->make('router')->getRoutes()->getByName('firewall.challenge');

        $this->assertNotNull($route);
        $this->assertSame([EvaluateFirewall::class], $route->gatherMiddleware());
    }

    #[Test]
    #[DefineEnvironment('withoutChallengeRoute')]
    public function it_skips_the_challenge_route_when_disabled(): void
    {
        $this->assertNull($this->app->make('router')->getRoutes()->getByName('firewall.challenge'));
    }

    #[Test]
    #[DefineEnvironment('withBlankChallengePath')]
    public function it_skips_the_challenge_route_when_the_path_is_blank(): void
    {
        $this->assertNull($this->app->make('router')->getRoutes()->getByName('firewall.challenge'));
    }

    #[Test]
    public function it_loads_the_package_views(): void
    {
        $this->assertTrue($this->app->make('view')->exists('firewall::block'));
        $this->assertTrue($this->app->make('view')->exists('firewall::challenge'));
    }

    #[Test]
    public function it_registers_the_artisan_commands(): void
    {
        $commands = array_keys($this->app->make('Illuminate\Contracts\Console\Kernel')->all());

        foreach ([
            'firewall:block',
            'firewall:blocks',
            'firewall:check',
            'firewall:doctor',
            'firewall:health',
            'firewall:init',
            'firewall:log-prune',
            'firewall:migrate',
            'firewall:find-reference',
            'firewall:rule',
            'firewall:sources',
            'firewall:unblock',
        ] as $command) {
            $this->assertContains($command, $commands);
        }
    }

    /**
     * The renderable safety net, for exceptions raised outside the middleware.
     *
     * A host may call `evaluate()` from its own code — a controller protecting
     * one action, a job checking an inbound webhook. Without this, a block
     * would reach Laravel's handler as a plain `RuntimeException` and render as
     * a 500: the wrong status, a stack trace while APP_DEBUG is on, and an
     * error-tracker alert for the firewall doing its job.
     */
    #[Test]
    public function a_block_thrown_outside_the_middleware_still_renders_as_a_block(): void
    {
        Route::get('/manual-block', static function (): never {
            throw new FirewallBlockedException('Blocked by hand', 403);
        });

        $response = $this->get('/manual-block');

        $response->assertStatus(403);
        $response->assertSee('Blocked by hand');
    }

    #[Test]
    public function a_challenge_thrown_outside_the_middleware_renders_the_interstitial(): void
    {
        config(['firewall.challenge.secret' => 'long-enough-secret-for-hmac-signing-here']);

        Route::get('/manual-challenge', static function (): never {
            throw new ChallengeRequiredException('Challenge required');
        });

        $this->get('/manual-challenge')
            ->assertOk()
            ->assertSee('action="/_firewall/challenge"', false);
    }

    #[Test]
    public function a_solved_challenge_thrown_outside_the_middleware_redirects(): void
    {
        Route::post('/manual-solve', static function (): never {
            throw new ChallengeSolvedException('a-token', '/somewhere');
        });

        $this->post('/manual-solve')
            ->assertStatus(303)
            ->assertRedirect('/somewhere');
    }

    /**
     * The registration guards, exercised on a container missing each binding.
     *
     * White-box on purpose: these are the branches that let the package boot
     * inside a bespoke or console-only bootstrap, and there is no way to reach
     * them through a Testbench application, which binds all three. Invoking the
     * private methods is the narrowest way to prove the guards return quietly
     * rather than throwing — the alternative is leaving them untested and
     * finding out from a bug report.
     */
    #[Test]
    public function it_registers_no_middleware_without_an_http_kernel(): void
    {
        unset($this->app[HttpKernelContract::class]);

        $this->assertNull($this->invokeOnProvider('registerMiddleware'));
    }

    #[Test]
    public function it_registers_no_middleware_when_the_kernel_is_not_lumen_shaped(): void
    {
        $this->app->instance(HttpKernelContract::class, new \stdClass());

        $this->assertNull($this->invokeOnProvider('registerMiddleware'));
    }

    #[Test]
    public function it_registers_no_challenge_route_without_a_router(): void
    {
        unset($this->app['router']);

        $this->assertNull($this->invokeOnProvider('registerChallengeRoute'));
    }

    #[Test]
    public function it_registers_no_challenge_route_when_the_router_is_not_one(): void
    {
        $this->app->instance('router', new \stdClass());

        $this->assertNull($this->invokeOnProvider('registerChallengeRoute'));
    }

    #[Test]
    public function it_registers_no_renderables_without_an_exception_handler(): void
    {
        unset($this->app[ExceptionHandler::class]);

        $this->assertNull($this->invokeOnProvider('registerRenderables'));
    }

    /**
     * An application with its own handler simply does not get the safety net.
     *
     * `renderable()` is on Laravel's concrete handler, not on the
     * `ExceptionHandler` contract, so this cannot be assumed.
     */
    #[Test]
    public function it_registers_no_renderables_on_a_handler_without_renderable(): void
    {
        $this->app->instance(ExceptionHandler::class, new class () implements ExceptionHandler {
            public function report(\Throwable $e): void
            {
            }

            public function shouldReport(\Throwable $e): bool
            {
                return false;
            }

            public function render($request, \Throwable $e): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response();
            }

            public function renderForConsole($output, \Throwable $e): void
            {
            }
        });

        $this->assertNull($this->invokeOnProvider('registerRenderables'));
    }

    /**
     * A container with no Blade factory is refused, not worked around.
     *
     * The responder renders both of its pages through Blade, so there is no
     * degraded mode to fall back to — and a message naming the binding beats
     * a `Call to a member function make() on stdClass` from inside a block.
     */
    #[Test]
    public function it_refuses_to_build_the_responder_without_a_view_factory(): void
    {
        $this->app->forgetInstance(FirewallResponder::class);
        $this->app->instance('view', new \stdClass());

        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/"view" binding is stdClass/');

        $this->app->make(FirewallResponder::class);
    }

    /**
     * Invoke one of the provider's private registration methods.
     */
    private function invokeOnProvider(string $method): mixed
    {
        $provider = new FirewallServiceProvider($this->app);

        return (new \ReflectionMethod(FirewallServiceProvider::class, $method))->invoke($provider);
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function persistInstance($app): void
    {
        $app['config']->set('firewall.octane.persist_instance', true);
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function withoutGlobalMiddleware($app): void
    {
        $app['config']->set('firewall.middleware.global', false);
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function withoutChallengeRoute($app): void
    {
        $app['config']->set('firewall.middleware.register_challenge_route', false);
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function withBlankChallengePath($app): void
    {
        $app['config']->set('firewall.challenge.path', '/');
    }

    /**
     * The abstracts the container will flush between Octane requests.
     *
     * `Container::$scopedInstances` has no accessor, so this is read
     * reflectively. That is the property Octane's `flush` acts on, and
     * asserting on it is the only way to tell a scoped binding from a
     * singleton — under PHP-FPM the two behave identically, which is exactly
     * why the difference is easy to get wrong and worth a test.
     *
     * @return array<int, string>
     */
    private function scopedInstances(): array
    {
        $property = new \ReflectionProperty(\Illuminate\Container\Container::class, 'scopedInstances');

        /** @var array<int, string> */
        return $property->getValue($this->app);
    }

    /**
     * The kernel's global middleware stack.
     *
     * Read reflectively because `Kernel::$middleware` is protected and there is
     * no accessor. Confined to the tests: production code positions itself with
     * `pushMiddleware()` and never inspects the stack, which is the difference
     * between using a framework internal and depending on one.
     *
     * @return array<int, string>
     */
    private function globalMiddleware(HttpKernel $kernel): array
    {
        $property = new \ReflectionProperty(HttpKernel::class, 'middleware');

        /** @var array<int, string> */
        return $property->getValue($kernel);
    }
}
