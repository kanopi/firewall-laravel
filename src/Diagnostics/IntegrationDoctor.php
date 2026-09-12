<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Diagnostics;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Laravel\Config\ConfigTranslator;
use Kanopi\Firewall\Laravel\Config\LogHandlers;
use Kanopi\Firewall\Laravel\Config\TrustedProxies;
use Kanopi\Firewall\Laravel\Http\Middleware\EvaluateFirewall;
use Kanopi\Firewall\Laravel\Support\Settings;

/**
 * Diagnose the parts of the setup that only exist because this is Laravel.
 *
 * `kanopi/firewall`'s own `Doctor` checks the firewall: storage reachability,
 * GeoIP freshness, rules that will not build. It cannot check the framework
 * around it, and the framework is where this integration's failures live —
 * every one of them silent, and every one of them leaving a firewall that
 * looks like it is working.
 *
 * Each check below corresponds to a way the integration can be wired up wrong
 * without anything complaining at the time.
 *
 * Findings use the library's `Diagnosis` type so that `firewall:doctor` can
 * print one list rather than two, and so a `--json` consumer sees one shape.
 */
final class IntegrationDoctor
{
    /**
     * @param bool $runningInConsole
     *   Whether this is an Artisan invocation rather than a web request.
     *   Passed in rather than read from the application, because it decides
     *   whether the middleware-ordering check can say anything at all — from
     *   the console no HTTP middleware has run, so an empty trusted-proxy list
     *   means nothing. `Application::runningInConsole()` memoises its answer
     *   per instance, so a test could not vary it; taking it as an argument
     *   makes both branches reachable, and this class then needs no
     *   application at all.
     * @param string $sapi
     *   The PHP SAPI name. Passed in for the same reason: the library
     *   short-circuits on a CLI SAPI, so this decides a finding — and a test
     *   suite always runs under `cli`, which would leave the other half of
     *   that finding permanently unexercised.
     */
    public function __construct(
        private readonly Settings $settings,
        private readonly ConfigTranslator $translator,
        private readonly TrustedProxies $trustedProxies,
        private readonly LogHandlers $logHandlers,
        private readonly bool $runningInConsole = false,
        private readonly string $sapi = PHP_SAPI
    ) {
    }

    /**
     * Run every integration check.
     *
     * @return array<int, Diagnosis>
     */
    public function run(): array
    {
        return array_merge(
            [$this->checkEnabled()],
            [$this->checkMode()],
            $this->checkCliSapi(),
            $this->checkTrustedProxies(),
            $this->checkMiddleware(),
            $this->checkChallenge(),
            $this->checkOctane(),
            $this->checkConfigInputs(),
            [$this->checkLogging()]
        );
    }

    /**
     * Is the firewall switched on?
     */
    private function checkEnabled(): Diagnosis
    {
        if (!$this->settings->flag('firewall.enabled', true)) {
            return Diagnosis::warning(
                'The firewall is disabled',
                'firewall.enabled is false, so the middleware is a no-op and no rule is '
                . 'evaluated. Every check below describes configuration that is not in use.'
            );
        }

        return Diagnosis::ok('The firewall is enabled');
    }

    /**
     * Is the configured mode one that Laravel can actually deliver?
     */
    private function checkMode(): Diagnosis
    {
        $configured = $this->translator->configuredMode();
        $effective = $this->translator->effectiveMode();

        if ($configured === FirewallMode::Disabled) {
            return Diagnosis::warning(
                'Mode is "disabled" — no request is evaluated',
                'Rules are loaded and storage is opened, but evaluation is skipped. Use '
                . 'firewall.enabled = false to avoid the setup cost entirely, or "log" to '
                . 'observe without enforcing.'
            );
        }

        if ($this->translator->modeWasTranslated()) {
            return Diagnosis::ok(
                sprintf('Mode "%s" is delivered as "%s"', $configured->value, $effective->value),
                'The library writes its own response and calls exit() in "block" mode, which '
                . 'would abandon the Laravel request mid-stack. This integration runs it in '
                . '"exception" mode and renders the same status and message through a Blade '
                . 'view instead. Nothing to do — this line exists so that "block" in config '
                . 'and "exception" in the logs are not read as a disagreement.'
            );
        }

        return Diagnosis::ok(sprintf('Mode is "%s"', $effective->value));
    }

    /**
     * Will the library short-circuit because the SAPI is a CLI one?
     *
     * `evaluate()` returns TRUE immediately when `PHP_SAPI === 'cli'` for every
     * mode except `exception`. That is deliberate and correct for Artisan and
     * queue workers, which have no visitor to protect — but Octane on
     * RoadRunner or Swoole also runs under `cli` while serving real HTTP
     * traffic. In `log` mode that means the firewall observes nothing and says
     * nothing, which is indistinguishable from a quiet week.
     *
     * `artisan serve` is deliberately *not* in that list. It runs under
     * `cli-server`, not `cli`, so the short-circuit does not apply and `log`
     * mode works there. That was verified rather than reasoned about — the
     * integration script in `tests/Integration/install.sh` drives a real
     * `artisan serve` and asserts that the decision reaches the log — because
     * the intuitive answer is the wrong one, and telling an operator their
     * development environment is unprotected when it is not would send them
     * looking for a problem that does not exist.
     *
     * @return array<int, Diagnosis>
     */
    private function checkCliSapi(): array
    {
        $mode = $this->translator->effectiveMode();

        // `exception` opts out of the library's CLI short-circuit entirely,
        // which is exactly why this integration forces it for enforcement.
        // `disabled` evaluates nothing under any SAPI, so the short-circuit
        // changes nothing about it either. Neither has anything to report.
        if ($mode === FirewallMode::Exception || $mode === FirewallMode::Disabled) {
            return [];
        }

        if ($this->sapi !== 'cli') {
            return [Diagnosis::ok(sprintf('SAPI is "%s" — no CLI short-circuit', $this->sapi))];
        }

        return [Diagnosis::error(
            sprintf('Mode "%s" evaluates nothing under a CLI SAPI', $mode->value),
            'The library returns early when PHP_SAPI is "cli" in every mode except '
            . '"exception". This process is running under a CLI SAPI, so no rule is being '
            . 'evaluated and no observation is being logged. Harmless if this is an Artisan '
            . 'command or a queue worker, which is what the short-circuit is for. It is not '
            . 'harmless under Octane on RoadRunner or Swoole, whose workers also run as '
            . '"cli" while serving real traffic: use mode "block" (delivered as "exception") '
            . 'to enforce there. `artisan serve` is unaffected — it runs as "cli-server", so '
            . '"log" mode does evaluate.',
            'docs/configuration/global.md#mode'
        )];
    }

    /**
     * Is the client IP the firewall reads trustworthy?
     *
     * @return array<int, Diagnosis>
     */
    private function checkTrustedProxies(): array
    {
        $declared = $this->trustedProxies->declared();
        $inForce = $this->trustedProxies->inForce();

        if ($declared === null && $inForce === []) {
            return [Diagnosis::warning(
                'No trusted proxies are configured',
                'Laravel declares no trusted proxies, so $request->getClientIp() returns the '
                . 'connecting address and X-Forwarded-For is ignored. Correct if nothing sits '
                . 'in front of this application — say so with global.behind_proxy = false to '
                . 'silence the library\'s per-request warning. If a load balancer or CDN does '
                . 'sit in front, configure TrustProxies: until then every IP rule matches the '
                . 'proxy rather than the visitor.',
                'docs/configuration/global.md#trusted-proxies'
            )];
        }

        // Run from Artisan, no HTTP middleware has executed, so an empty
        // in-force list is expected and says nothing about the web stack. Only
        // the declaration is checkable here.
        if ($this->runningInConsole) {
            return [Diagnosis::ok(
                'Trusted proxies are configured',
                'Ordering against TrustProxies cannot be checked from the console — no HTTP '
                . 'middleware has run. It is verified on every web request instead, and '
                . 'reported at error level when wrong.'
            )];
        }

        if ($this->trustedProxies->isSpoofable()) {
            return [Diagnosis::error(
                'The firewall middleware runs before TrustProxies',
                'Trusted proxies are declared but not in force at the point the firewall '
                . 'evaluates, so every rule reads the proxy address as the client address and '
                . 'a forged X-Forwarded-For is accepted from anyone. Set '
                . 'firewall.middleware.global = true and let this package position the '
                . 'middleware, or move EvaluateFirewall after TrustProxies yourself.',
                'docs/configuration/global.md#trusted-proxies'
            )];
        }

        return [Diagnosis::ok(
            'Trusted proxies are in force before the firewall runs',
            sprintf('%d proxy entr%s trusted.', count($inForce), count($inForce) === 1 ? 'y' : 'ies')
        )];
    }

    /**
     * Is the middleware registered at all, and where?
     *
     * @return array<int, Diagnosis>
     */
    private function checkMiddleware(): array
    {
        if ($this->settings->flag('firewall.middleware.global', true)) {
            return [Diagnosis::ok(
                'The firewall middleware is registered globally',
                'It runs before routing, so it sees every request — including one for a path '
                . 'with no route, which is most of what a firewall is for.'
            )];
        }

        return [Diagnosis::warning(
            'The firewall middleware is not registered globally',
            'firewall.middleware.global is false, so ' . EvaluateFirewall::class . ' must be '
            . 'placed by hand. Two things to verify: it runs after TrustProxies, and a request '
            . 'for an unrouted path still reaches it — route middleware runs after routing, so '
            . 'a probe for /wp-login.php would 404 without ever being evaluated or recorded.'
        )];
    }

    /**
     * Can a challenged visitor actually solve the challenge?
     *
     * Two ways to be locked out permanently, both silent:
     *
     *  - The POST to `challenge.path` never reaches the firewall, because route
     *    middleware runs after routing and no route matches.
     *  - A plugin names its own `metadata.challenge_provider`, which this
     *    integration cannot render in `exception` mode: the exception the
     *    library throws does not say which plugin matched, so the default
     *    provider is rendered instead and the visitor is asked to solve the
     *    wrong challenge.
     *
     * @return array<int, Diagnosis>
     */
    private function checkChallenge(): array
    {
        $plugins = $this->challengePlugins();

        if ($plugins === []) {
            return [];
        }

        $findings = [];
        $global = $this->settings->flag('firewall.middleware.global', true);
        $route = $this->settings->flag('firewall.middleware.register_challenge_route', true);
        $path = $this->settings->text('firewall.challenge.path', '/_firewall/challenge');

        if (!$global && !$route) {
            $findings[] = Diagnosis::error(
                'A challenged visitor can never solve the challenge',
                sprintf(
                    'Rules use response: challenge, but the middleware is not global and '
                    . 'firewall.middleware.register_challenge_route is false — so nothing '
                    . 'routes a POST to %s to the firewall. It will 404, the visitor will '
                    . 'never get a pass token, and they stay challenged forever. Set one of '
                    . 'the two to true.',
                    $path
                )
            );
        } else {
            $findings[] = Diagnosis::ok(
                sprintf('Challenge submissions to %s reach the firewall', $path),
                $global
                    ? 'Global middleware runs before routing, so the POST is intercepted '
                    . 'before Laravel looks for a route and before VerifyCsrfToken could '
                    . 'reject a form that cannot carry a token.'
                    : 'A dedicated POST route carries the firewall middleware and no route '
                    . 'group, so VerifyCsrfToken never sees the submission.'
            );
        }

        if ($this->settings->text('firewall.challenge.secret') === '') {
            $findings[] = Diagnosis::error(
                'Challenge rules are configured with no challenge.secret',
                'The secret signs the pass token. Firewall::create() refuses to start without '
                . 'one, so this is a boot failure rather than a runtime surprise — set '
                . 'FIREWALL_CHALLENGE_SECRET to a long random string.'
            );
        }

        return $findings;
    }

    /**
     * Does the Octane binding contradict the panic switch?
     *
     * @return array<int, Diagnosis>
     */
    private function checkOctane(): array
    {
        $persist = $this->settings->flag('firewall.octane.persist_instance', false);
        $panicFile = $this->settings->text('firewall.global.panic_file');
        $hasPanicFile = $panicFile !== '';

        if (!$persist) {
            return $hasPanicFile
                ? [Diagnosis::ok(
                    'The panic switch will take effect on the next request',
                    'The firewall is bound as a scoped instance, so it is rebuilt per request '
                    . 'under Octane and the panic file is re-read each time.'
                )]
                : [];
        }

        if ($hasPanicFile) {
            return [Diagnosis::error(
                'The panic switch cannot work with firewall.octane.persist_instance',
                sprintf(
                    'global.panic_file is set to %s, but the firewall is bound as a true '
                    . 'singleton. The panic file is read once per Firewall instance, so under '
                    . 'Octane it is read when the worker boots and never again — writing to it '
                    . 'during an incident would do nothing until every worker was restarted. '
                    . 'Set firewall.octane.persist_instance = false, or unset the panic file so '
                    . 'nobody reaches for a switch that is not connected.',
                    $panicFile
                ),
                'docs/configuration/global.md#panic-switch'
            )];
        }

        return [Diagnosis::warning(
            'The firewall is bound as a persistent singleton',
            'firewall.octane.persist_instance is true: config is parsed and plugins are built '
            . 'once per worker rather than per request. Do not set global.panic_file while this '
            . 'is on — it would be read once at worker boot and never take effect.'
        )];
    }

    /**
     * Do the configured presets and config files exist?
     *
     * The library loads config leniently: a path it cannot read is logged and
     * skipped, and the firewall starts with a partial — possibly empty —
     * ruleset that allows everything. `presets` is validated by the translator
     * and throws, so only `configs` needs reporting here.
     *
     * @return array<int, Diagnosis>
     */
    private function checkConfigInputs(): array
    {
        $missing = $this->translator->missingConfigs();

        if ($missing === []) {
            return [];
        }

        $requireConfig = $this->settings->flag('firewall.global.require_config', false);

        return [Diagnosis::error(
            sprintf('%d configured config file%s missing', count($missing), count($missing) === 1 ? ' is' : 's are'),
            sprintf(
                'Not readable: %s. The rules in them are NOT active. %s',
                implode(', ', $missing),
                $requireConfig
                    ? 'global.require_config is true, so this is also a boot failure.'
                    : 'global.require_config is false, so the firewall starts without them and '
                    . 'logs an error per request. Set it to true in production to make this '
                    . 'fail the deploy instead.'
            ),
            'docs/configuration/global.md#requiring-the-config-to-load'
        )];
    }

    /**
     * Is the firewall's own logging going anywhere?
     *
     * A firewall with no log handlers still enforces, so this is a warning
     * rather than an error — but it is the warning that matters most when
     * something later goes wrong, because every other diagnosis the library
     * produces at runtime is delivered as a log line.
     */
    private function checkLogging(): Diagnosis
    {
        $handlers = $this->logHandlers->all();
        $channel = $this->logHandlers->channelName();

        if ($handlers !== []) {
            return Diagnosis::ok(
                sprintf('Firewall logs to %d handler%s', count($handlers), count($handlers) === 1 ? '' : 's'),
                $channel === null
                    ? null
                    : sprintf('Borrowed from the "%s" log channel, under the channel name "firewall".', $channel)
            );
        }

        return Diagnosis::warning(
            'The firewall has no log handlers',
            $channel === null
                ? 'firewall.logger.channel is unset and no handlers are configured, so every '
                . 'block, every rule that failed to build and every degraded backend is '
                . 'reported to nowhere.'
                : sprintf(
                    'The "%s" log channel resolved to no Monolog handlers — it may not exist, '
                    . 'or may use a driver that is not Monolog-backed. Firewall log records are '
                    . 'being discarded.',
                    $channel
                )
        );
    }

    /**
     * Rule entries using `response: challenge`.
     *
     * Read from the Laravel config only. Presets and YAML files can also
     * declare challenge rules, and those are not inspected here — parsing them
     * would mean re-implementing the library's include resolution. The library's
     * own Doctor sees the merged result, and `firewall:doctor` runs both.
     *
     * @return array<int, array<string, mixed>>
     */
    private function challengePlugins(): array
    {
        return array_values(array_filter(
            $this->settings->listOfSections('firewall.plugins'),
            static fn (array $plugin): bool => ($plugin['response'] ?? null) === 'challenge'
                && ($plugin['enable'] ?? true) !== false
        ));
    }
}
