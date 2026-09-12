<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel;

use Illuminate\Contracts\Events\Dispatcher as IlluminateDispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Log\LogManager;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Laravel\Config\ConfigTranslator;
use Kanopi\Firewall\Laravel\Config\LogHandlers;
use Kanopi\Firewall\Laravel\Config\TrustedProxies;
use Kanopi\Firewall\Laravel\Events\DispatcherBridge;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\Support\PackagePaths;
use Kanopi\Firewall\Laravel\Support\Settings;
use Kanopi\Firewall\Laravel\Support\StorageDirectories;
use Psr\Log\LoggerInterface;

/**
 * Build a configured `Firewall` from Laravel's container and config.
 *
 * Separate from the service provider so that the assembly can be exercised
 * without a booted framework, and so that the Artisan commands — which need the
 * same translated configuration but hand it to a subprocess rather than to
 * `create()` — can reuse the translation without building a firewall at all.
 */
final class FirewallFactory
{
    public function __construct(private readonly Application $app)
    {
    }

    /**
     * Build the firewall.
     *
     * @throws IntegrationException
     *   When the configuration cannot be translated, or when the mode override
     *   did not take.
     */
    public function make(): Firewall
    {
        $translator = $this->translator();

        // Before `create()`, which is where a missing storage directory
        // surfaces: `FileStorage` creates its data file but not the directory
        // holding it, and the default this package publishes is two levels
        // below storage_path(). Without this a freshly published config fails
        // on its first request, and with the default fail-closed policy that
        // is every request until somebody runs mkdir.
        $this->storageDirectories()->ensureFor($this->settings()->section('firewall.storage'));

        $firewall = Firewall::create(
            $translator->configs(),
            $translator->overrides(),
            $this->dispatcher()
        );

        $this->assertModeIsDeliverable($firewall, $translator);

        return $firewall;
    }

    /**
     * The translator for the current configuration.
     *
     * Rebuilt on each call rather than memoised. Under Octane the factory
     * itself is a singleton, and a memoised translator would hold the trusted
     * proxy posture read during the first request the worker served — which is
     * the wrong value for every request after it, because `TrustProxies` sets
     * that state per request.
     */
    public function translator(): ConfigTranslator
    {
        $settings = $this->settings();

        return new ConfigTranslator(
            $settings->section('firewall'),
            $this->presetDirectory(),
            $this->trustedProxies()->posture(),
            $this->logHandlers()->all(),
            $this->managedRulesPath()
        );
    }

    /**
     * Refuse to run a firewall that would call exit() mid-request.
     *
     * The invariant is one line long: the *effective* mode must never be
     * `block`. That is the only mode in which the library writes its own
     * response and calls `exit()`, and under Laravel that abandons the request
     * mid-stack — nothing is rendered, terminating middleware never runs, and
     * the session, the queue and anything else deferred to the end of the
     * request are silently dropped. The symptom is a truncated page, which
     * reads as a crash rather than as a firewall block.
     *
     * Checking the effective mode rather than the configured one matters,
     * because there are two independent ways to arrive at `block`:
     *
     *  1. **The override did not land.** `Config::load()` applies overrides
     *     through PropertyAccess inside a `try { } catch (\Exception) { }`, so
     *     an override it cannot write is dropped in silence — which happens
     *     when a config input holds a non-array, non-null value at `global:`.
     *     Almost every override failing that way is a cosmetic loss. This one
     *     is not.
     *  2. **A panic file asked for it.** The panic switch overrides the mode
     *     after the override has been applied, so the configured mode can be
     *     perfectly correct while the effective one is `block`. An earlier
     *     version of this check compared `getConfiguredMode()` and would have
     *     passed straight over that case.
     *
     * Failing to boot is the better failure in both cases: it happens on the
     * first request after the change, with a message naming the cause.
     *
     * @throws IntegrationException
     */
    private function assertModeIsDeliverable(Firewall $firewall, ConfigTranslator $translator): void
    {
        if ($firewall->getMode() !== FirewallMode::Block) {
            return;
        }

        $panic = $firewall->getPanicSwitch();

        if ($panic['active'] && $panic['mode'] === FirewallMode::Block) {
            throw new IntegrationException(sprintf(
                'The firewall panic file at %s asks for mode "block". Under Laravel the only '
                . 'modes that can be delivered are "exception", "log" and "disabled" — "block" '
                . 'makes the library write its own response and call exit(), which would '
                . 'abandon the request mid-stack. Write "exception" to the panic file to '
                . 'enforce, or "log" to observe.',
                (string) ($panic['path'] ?? '(unknown path)')
            ));
        }

        throw new IntegrationException(sprintf(
            'The firewall was asked to run in "%s" mode and is running in "block". The mode '
            . 'override did not take, so the library would write its own response and call '
            . 'exit() instead of letting Laravel render one. Check that nothing in '
            . 'firewall.presets or firewall.configs sets `global` to a value that is neither '
            . 'a mapping nor empty — an override cannot be written into a scalar, and the '
            . 'library discards one it cannot write.',
            $translator->effectiveMode()->value
        ));
    }

    /**
     * Creates the storage directories this package's own defaults point at.
     */
    public function storageDirectories(): StorageDirectories
    {
        return new StorageDirectories($this->app->storagePath());
    }

    /**
     * The trusted-proxy bridge.
     */
    public function trustedProxies(): TrustedProxies
    {
        return new TrustedProxies($this->settings());
    }

    /**
     * The log handler bridge.
     */
    public function logHandlers(): LogHandlers
    {
        $loggerConfig = $this->settings()->section('firewall.logger');
        $name = $loggerConfig['channel'] ?? null;

        return new LogHandlers(
            $loggerConfig,
            is_string($name) && $name !== '' ? $this->channel($name) : null
        );
    }

    /**
     * Resolve a Laravel log channel, or NULL when it cannot be resolved.
     *
     * A channel name that does not exist throws out of `LogManager`. Caught,
     * because the destination of the firewall's own log records is not worth
     * refusing traffic over — the firewall still evaluates, and
     * `firewall:doctor` reports that it is logging nowhere.
     */
    private function channel(string $name): ?LoggerInterface
    {
        if (!$this->app->bound('log')) {
            return null;
        }

        try {
            $manager = $this->app->make('log');

            return $manager instanceof LogManager ? $manager->channel($name) : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The PSR-14 dispatcher to hand the firewall, or NULL when unavailable.
     *
     * NULL disables the mechanism inside the library at the cost of one null
     * check per decision, which is what a console command without a bound
     * dispatcher should get.
     */
    private function dispatcher(): ?DispatcherBridge
    {
        if (!$this->app->bound('events')) {
            return null;
        }

        $events = $this->app->make('events');

        return $events instanceof IlluminateDispatcher ? new DispatcherBridge($events) : null;
    }

    /**
     * The `presets/` directory of the installed library.
     */
    private function presetDirectory(): string
    {
        $configured = $this->settings()->text('firewall.artisan.preset_path');

        return $configured !== '' ? $configured : PackagePaths::presets();
    }

    /**
     * Where `firewall:rule` keeps the rules it writes, or NULL if switched off.
     *
     * Handed to the translator rather than merged into `configs` here, so that
     * "this file is expected to be absent" stays a fact the translator knows
     * about instead of one every consumer has to remember.
     */
    private function managedRulesPath(): ?string
    {
        $managed = $this->settings()->text('firewall.artisan.managed_rules');

        return $managed === '' ? null : $managed;
    }

    /**
     * The typed reader over Laravel's config repository.
     *
     * Rebuilt per call for the same reason `translator()` is: under Octane the
     * factory outlives the request, and a held reference would be to whichever
     * repository instance existed when the worker booted.
     */
    private function settings(): Settings
    {
        return Settings::for($this->app);
    }
}
