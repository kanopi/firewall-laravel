<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Laravel\Config\LogHandlers;
use Kanopi\Firewall\Laravel\Config\TrustedProxies;
use Kanopi\Firewall\Laravel\Console\BlockAddCommand;
use Kanopi\Firewall\Laravel\Console\BlockCommand;
use Kanopi\Firewall\Laravel\Console\CheckCommand;
use Kanopi\Firewall\Laravel\Console\DoctorCommand;
use Kanopi\Firewall\Laravel\Console\FindReferenceCommand;
use Kanopi\Firewall\Laravel\Console\HealthCommand;
use Kanopi\Firewall\Laravel\Console\InitCommand;
use Kanopi\Firewall\Laravel\Console\LogPruneCommand;
use Kanopi\Firewall\Laravel\Console\MigrateCommand;
use Kanopi\Firewall\Laravel\Console\RuleCommand;
use Kanopi\Firewall\Laravel\Console\SourcesCommand;
use Kanopi\Firewall\Laravel\Console\UnblockCommand;
use Illuminate\Http\Request;
use Kanopi\Firewall\Laravel\Diagnostics\IntegrationDoctor;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\Http\FirewallResponder;
use Symfony\Component\HttpFoundation\Response;
use Kanopi\Firewall\Laravel\Http\Middleware\EvaluateFirewall;
use Kanopi\Firewall\Laravel\Support\BlockManager;
use Kanopi\Firewall\Laravel\Support\Settings;
use Kanopi\Firewall\Utility\BlockList;

/**
 * Register the firewall with Laravel.
 */
final class FirewallServiceProvider extends ServiceProvider
{
    /**
     * The Artisan wrappers around kanopi/firewall's bin/ scripts.
     *
     * @var array<int, class-string<\Illuminate\Console\Command>>
     */
    private const COMMANDS = [
        BlockAddCommand::class,
        BlockCommand::class,
        CheckCommand::class,
        DoctorCommand::class,
        FindReferenceCommand::class,
        HealthCommand::class,
        InitCommand::class,
        LogPruneCommand::class,
        MigrateCommand::class,
        RuleCommand::class,
        SourcesCommand::class,
        UnblockCommand::class,
    ];

    /**
     * Register bindings.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/firewall.php', 'firewall');

        $this->app->singleton(FirewallFactory::class);

        $this->app->bind(Settings::class, fn (): Settings => Settings::for($this->app));

        $this->app->bind(TrustedProxies::class, fn (): TrustedProxies => $this->factory()->trustedProxies());

        $this->app->bind(LogHandlers::class, fn (): LogHandlers => $this->factory()->logHandlers());

        // `BlockList` is the library's own public reader/writer for the block
        // list, and it takes the same config inputs `Firewall::create()` does —
        // so it resolves the same storage backend the middleware is using
        // rather than a second opinion about where blocks live.
        $this->app->bind(BlockList::class, fn (): BlockList => new BlockList(
            $this->factory()->translator()->configs()
        ));

        $this->app->bind(BlockManager::class, fn (): BlockManager => new BlockManager(
            $this->app->make(BlockList::class)
        ));

        $this->app->bind(IntegrationDoctor::class, fn (): IntegrationDoctor => new IntegrationDoctor(
            Settings::for($this->app),
            $this->factory()->translator(),
            $this->factory()->trustedProxies(),
            $this->factory()->logHandlers(),
            $this->app->runningInConsole()
        ));

        $this->app->singleton(FirewallResponder::class, fn (): FirewallResponder => new FirewallResponder(
            Settings::for($this->app),
            $this->viewFactory()
        ));
    }

    /**
     * Bind the firewall itself.
     *
     * Bound in `boot()` rather than `register()`, alone among this package's
     * bindings, because the choice between `scoped()` and `singleton()` is
     * structural — it cannot be deferred to the first resolution — and it
     * depends on a config value that another service provider's `register()`
     * is still entitled to change. Deciding in `boot()` means the decision
     * sees the final configuration. Nothing resolves the firewall before then:
     * the middleware and the Artisan commands both run after every provider
     * has booted.
     *
     * `scoped()` rather than `singleton()`, and that is the whole Octane answer
     * in one word. A scoped binding behaves exactly like a singleton under
     * PHP-FPM and mod_php — one instance for the one request the process
     * serves — and is flushed between requests under Octane.
     *
     * The reason it has to be flushed is the panic switch. `PanicSwitch::read()`
     * runs in the `Firewall` constructor: one `stat()` per instance, which the
     * library documents as one per request. An instance that outlived the
     * request would keep reporting the mode it read when the worker booted, so
     * writing `log` to the panic file during an incident would change nothing
     * until every worker had been restarted — which is the one moment that is
     * least acceptable, and it would fail silently, because a panic file that
     * does nothing looks exactly like a panic file that has not been reached
     * for yet.
     *
     * Two other pieces of per-instance state make the same argument:
     *
     *  - **Failed rules are never retried.** A plugin whose constructor threw
     *    is recorded as failed and skipped for the life of the instance. Under
     *    a persistent singleton, a Redis blip during worker boot would disable
     *    a rate limit rule until the worker was recycled.
     *  - **Degraded backends are recorded at construction.** A backend that
     *    reconnects is not re-checked, so a health endpoint would go on
     *    reporting a store as unreachable long after it came back.
     *
     * What a scoped binding costs is real: the config is re-merged and the
     * plugin registry rebuilt each request, which is work Octane exists to
     * avoid. The library mitigates most of it — `Config::load()` caches the
     * merged result per file set, and plugins are constructed lazily — and
     * `firewall.octane.persist_instance` opts into a true singleton for a
     * deployment that has measured the difference and has no panic file.
     */
    private function registerFirewall(): void
    {
        $builder = fn (): Firewall => $this->factory()->make();

        if (Settings::for($this->app)->flag('firewall.octane.persist_instance', false)) {
            $this->app->singleton(Firewall::class, $builder);

            return;
        }

        $this->app->scoped(Firewall::class, $builder);
    }

    /**
     * Bootstrap the package.
     */
    public function boot(): void
    {
        $this->registerFirewall();

        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'firewall');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/firewall.php' => $this->app->configPath('firewall.php'),
            ], 'firewall-config');

            $this->publishes([
                __DIR__ . '/../resources/views' => $this->app->resourcePath('views/vendor/firewall'),
            ], 'firewall-views');

            $this->commands(self::COMMANDS);
        }

        $this->registerMiddleware();
        $this->registerChallengeRoute();
        $this->registerRenderables();
    }

    /**
     * Append the middleware to the global stack.
     *
     * `pushMiddleware()` appends, which is what makes the ordering correct:
     * `TrustProxies` is at the front of Laravel's global stack, so anything
     * appended runs after it and reads a client IP that is safe to make
     * decisions about.
     *
     * The alternative was splicing in immediately after `TrustProxies`, which
     * would be marginally earlier and therefore cheaper — the firewall would
     * reject a request before `TrimStrings` walked the input. It lost on two
     * counts. There is no public API for inserting at an index, so it would
     * mean reflecting into `Kernel::$middleware` and rewriting it, which is a
     * poor thing to do to a framework internal for a saving measured in
     * microseconds. And appending is already before routing, before the
     * session, before authentication and before any application code — which
     * is the part that actually matters.
     */
    private function registerMiddleware(): void
    {
        if (!Settings::for($this->app)->flag('firewall.middleware.global', true)) {
            return;
        }

        if (!$this->app->bound(HttpKernelContract::class)) {
            // No HTTP kernel: a console-only or bespoke bootstrap. Nothing to
            // register, and nothing wrong — the Artisan commands and the
            // Firewall binding are the useful half in that context.
            return;
        }

        $kernel = $this->app->make(HttpKernelContract::class);

        if ($kernel instanceof HttpKernel) {
            $kernel->pushMiddleware(EvaluateFirewall::class);
        }
    }

    /**
     * Guarantee the challenge submission path can reach the firewall.
     *
     * The POST to `challenge.path` is the only way out of a challenge. If it
     * does not reach `evaluate()`, a challenged visitor is locked out
     * permanently — and nothing reports it, because from the firewall's point
     * of view that visitor simply stopped coming back with a valid token.
     *
     * With global middleware this is already true: global middleware runs
     * before routing, so the POST is intercepted before Laravel looks for a
     * route. This route exists for the per-route registration case, and is
     * harmless in the global one because the global pass gets there first.
     *
     * Three details that are each load-bearing:
     *
     *  - **No route group**, so `VerifyCsrfToken` never runs. The interstitial
     *    is rendered by the challenge provider and cannot carry a Laravel CSRF
     *    token, so the `web` group would reject every submission with a 419.
     *  - **The action aborts with 404.** It is only reached when the firewall
     *    did *not* intercept, which means challenges are not configured — and
     *    then this path should look like what it is: nothing.
     *  - **Registered only when a path is configured**, so clearing
     *    `challenge.path` removes the route rather than binding `POST /`.
     */
    private function registerChallengeRoute(): void
    {
        $settings = Settings::for($this->app);

        if (!$settings->flag('firewall.middleware.register_challenge_route', true)) {
            return;
        }

        $path = $settings->text('firewall.challenge.path');

        if (trim($path, '/') === '') {
            return;
        }

        if (!$this->app->bound('router')) {
            return;
        }

        $router = $this->app->make('router');

        if (!$router instanceof Router) {
            return;
        }

        $router->post($path, static fn (): never => abort(404))
            ->middleware(EvaluateFirewall::class)
            ->name('firewall.challenge');
    }

    /**
     * Render the firewall's exceptions even when they arrive outside the middleware.
     *
     * The middleware catches all three itself, so this is not the primary path
     * — it is the safety net for a host that calls `evaluate()` from its own
     * code (a controller protecting one action, a job that checks an inbound
     * webhook). Without it those exceptions reach Laravel's handler as plain
     * `RuntimeException`s and render as a 500, which for a *block* means an
     * attacker gets a stack trace in debug mode and the site owner gets an
     * error-tracker alert for the firewall doing its job.
     *
     * Registered defensively: `renderable()` is on Laravel's concrete handler,
     * not on the `ExceptionHandler` contract, so an application that swapped in
     * its own handler simply does not get the net.
     */
    private function registerRenderables(): void
    {
        if (!$this->app->bound(ExceptionHandler::class)) {
            return;
        }

        $handler = $this->app->make(ExceptionHandler::class);

        if (!method_exists($handler, 'renderable')) {
            return;
        }

        $responder = fn (): FirewallResponder => $this->responder();

        $handler->renderable(static fn (FirewallBlockedException $e, Request $request): Response =>
            $responder()->block($request, $e));

        $handler->renderable(static fn (ChallengeSolvedException $e, Request $request): Response =>
            $responder()->solved($request, $e));

        $handler->renderable(static fn (ChallengeRequiredException $e, Request $request): Response =>
            $responder()->challenge($request, $e));
    }

    /**
     * The firewall factory.
     *
     * A method rather than a repeated `$this->app->make(...)` so that the
     * binding closures below read as intent instead of container plumbing.
     * No narrowing needed: resolving by class name is typed by the container
     * contract, unlike the string-keyed bindings that `viewFactory()` handles.
     */
    private function factory(): FirewallFactory
    {
        return $this->app->make(FirewallFactory::class);
    }

    private function responder(): FirewallResponder
    {
        return $this->app->make(FirewallResponder::class);
    }

    private function viewFactory(): ViewFactory
    {
        $views = $this->app->make('view');

        if (!$views instanceof ViewFactory) {
            throw new IntegrationException(sprintf(
                'The container\'s "view" binding is %s, not a %s. The firewall renders its '
                . 'block and challenge responses through Blade.',
                get_debug_type($views),
                ViewFactory::class
            ));
        }

        return $views;
    }
}
