<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Laravel\Diagnostics\IntegrationDoctor;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

/**
 * The Laravel-specific checks.
 *
 * Each one corresponds to a way this integration can be wired up wrong without
 * anything complaining at the time — which is the only kind of check worth
 * having here, since the library's own `Doctor` already covers the firewall.
 */
final class IntegrationDoctorTest extends TestCase
{
    #[Test]
    public function a_default_installation_reports_no_errors(): void
    {
        $this->assertSame([], $this->errors());
    }

    #[Test]
    public function it_reports_a_disabled_firewall_as_a_warning(): void
    {
        config(['firewall.enabled' => false]);

        $this->assertFindingMatches(Diagnosis::WARNING, '/firewall is disabled/', $this->diagnose());
    }

    /**
     * The mode translation is reported as OK, on purpose.
     *
     * An operator reading `mode: block` in config and `exception` in a log line
     * needs to be told the two agree. Silence here would leave them looking for
     * a bug that is not there.
     */
    #[Test]
    public function it_explains_that_block_is_delivered_as_exception(): void
    {
        $this->assertFindingMatches(Diagnosis::OK, '/"block" is delivered as "exception"/', $this->diagnose());
    }

    #[Test]
    public function it_reports_disabled_mode_as_a_warning(): void
    {
        config(['firewall.global.mode' => 'disabled']);

        $this->assertFindingMatches(Diagnosis::WARNING, '/no request is evaluated/', $this->diagnose());
    }

    #[Test]
    public function it_reports_a_plain_exception_mode_without_comment(): void
    {
        config(['firewall.global.mode' => 'exception']);

        $this->assertFindingMatches(Diagnosis::OK, '/Mode is "exception"/', $this->diagnose());
    }

    /**
     * Trap 2: `log` mode under a CLI SAPI evaluates nothing.
     *
     * The test suite runs under `cli`, which is the same condition Octane on
     * RoadRunner or Swoole is in while serving real traffic. `artisan serve` is
     * `cli-server` and is not affected — see the SAPI table in the README.
     */
    #[Test]
    public function it_reports_log_mode_under_a_cli_sapi_as_an_error(): void
    {
        config(['firewall.global.mode' => 'log']);

        $this->assertFindingMatches(Diagnosis::ERROR, '/evaluates nothing under a CLI SAPI/', $this->diagnose());
    }

    /**
     * Under a non-CLI SAPI, `log` mode is reported as fine.
     *
     * The suite always runs under `cli`, so the SAPI is a constructor argument
     * — otherwise the other half of this finding would never be exercised, and
     * an integration running under PHP-FPM would be getting advice nobody had
     * ever seen.
     */
    #[Test]
    public function it_reports_log_mode_under_php_fpm_as_fine(): void
    {
        config(['firewall.global.mode' => 'log']);

        $this->assertFindingMatches(
            Diagnosis::OK,
            '/SAPI is "fpm-fcgi" — no CLI short-circuit/',
            $this->diagnoseAs(sapi: 'fpm-fcgi')
        );
    }

    #[Test]
    public function it_says_nothing_about_the_sapi_when_the_mode_is_disabled(): void
    {
        config(['firewall.global.mode' => 'disabled']);

        $this->assertNoFindingMentions('SAPI');
    }

    #[Test]
    public function it_warns_when_no_trusted_proxies_are_configured(): void
    {
        $this->assertFindingMatches(Diagnosis::WARNING, '/No trusted proxies are configured/', $this->diagnose());
    }

    /**
     * From the console, ordering cannot be checked, and the report says so.
     *
     * No HTTP middleware has run, so an empty in-force list means nothing about
     * the web stack. Reporting it as a failure would make `firewall:doctor`
     * unusable as a deploy gate — it would fail every time.
     */
    #[Test]
    public function it_declines_to_judge_ordering_from_the_console(): void
    {
        config(['trustedproxy.proxies' => ['10.0.0.1']]);

        $this->assertFindingMatches(
            Diagnosis::OK,
            '/cannot be checked from the console/',
            $this->diagnose()
        );
    }

    #[Test]
    public function it_reports_proxies_in_force_during_a_web_request(): void
    {
        config(['trustedproxy.proxies' => ['10.0.0.1']]);
        SymfonyRequest::setTrustedProxies(['10.0.0.1'], SymfonyRequest::HEADER_X_FORWARDED_FOR);

        $findings = $this->runAsWebRequest();

        $this->assertFindingMatches(Diagnosis::OK, '/in force before the firewall runs/', $findings);
    }

    #[Test]
    public function it_reports_the_ordering_bug_during_a_web_request(): void
    {
        config(['trustedproxy.proxies' => ['10.0.0.1']]);
        SymfonyRequest::setTrustedProxies([], SymfonyRequest::HEADER_X_FORWARDED_FOR);

        $findings = $this->runAsWebRequest();

        $this->assertFindingMatches(Diagnosis::ERROR, '/runs before TrustProxies/', $findings);
    }

    #[Test]
    public function it_reports_global_middleware_registration(): void
    {
        $this->assertFindingMatches(Diagnosis::OK, '/registered globally/', $this->diagnose());
    }

    #[Test]
    public function it_warns_when_the_middleware_is_not_global(): void
    {
        config(['firewall.middleware.global' => false]);

        $this->assertFindingMatches(Diagnosis::WARNING, '/not registered globally/', $this->diagnose());
    }

    #[Test]
    public function it_says_nothing_about_challenges_when_no_rule_challenges(): void
    {
        $this->assertNoFindingMentions('challenge');
    }

    /**
     * Trap 4: a challenged visitor that can never solve.
     */
    #[Test]
    public function it_reports_a_challenge_that_can_never_be_solved(): void
    {
        $this->challengeRule();
        config([
            'firewall.middleware.global' => false,
            'firewall.middleware.register_challenge_route' => false,
        ]);

        $this->assertFindingMatches(Diagnosis::ERROR, '/can never solve the challenge/', $this->diagnose());
    }

    #[Test]
    public function it_confirms_the_submission_path_is_reachable_globally(): void
    {
        $this->challengeRule();

        $this->assertFindingMatches(Diagnosis::OK, '/reach the firewall/', $this->diagnose());
    }

    #[Test]
    public function it_confirms_the_submission_path_is_reachable_by_route(): void
    {
        $this->challengeRule();
        config(['firewall.middleware.global' => false]);

        $findings = $this->diagnose();

        $this->assertFindingMatches(Diagnosis::OK, '/reach the firewall/', $findings);
        $this->assertFindingMatches(Diagnosis::OK, '/VerifyCsrfToken never sees/', $findings);
    }

    #[Test]
    public function it_reports_a_challenge_rule_with_no_secret(): void
    {
        $this->challengeRule();
        config(['firewall.challenge.secret' => '']);

        $this->assertFindingMatches(Diagnosis::ERROR, '/no challenge\.secret/', $this->diagnose());
    }

    #[Test]
    public function a_disabled_challenge_rule_is_ignored(): void
    {
        $this->challengeRule(['enable' => false]);

        foreach ($this->diagnose() as $finding) {
            $this->assertStringNotContainsStringIgnoringCase('challenge', $finding->title);
        }
    }

    /**
     * A rule naming its own provider is no longer reported at all.
     *
     * Until 2.26 this was an error: `ChallengeRequiredException` carried no
     * provider, so the interstitial was always rendered from
     * `challenge.provider` and a rule asking for a different one showed the
     * wrong challenge. The exception carries it now, so the check that warned
     * about it is gone and so is the limitation.
     */
    #[Test]
    public function a_rule_naming_its_own_provider_is_supported(): void
    {
        $this->challengeRule(['metadata' => ['challenge_provider' => 'turnstile'], 'name' => 'login-gate']);

        $this->assertSame([], $this->errors());
    }

    #[Test]
    public function it_confirms_the_panic_switch_is_connected(): void
    {
        config(['firewall.global.panic_file' => '/var/run/firewall/panic']);

        $this->assertFindingMatches(Diagnosis::OK, '/take effect on the next request/', $this->diagnose());
    }

    /**
     * The Octane trap: a panic file that cannot possibly work.
     */
    #[Test]
    public function it_reports_a_panic_file_that_a_persistent_singleton_would_defeat(): void
    {
        config([
            'firewall.octane.persist_instance' => true,
            'firewall.global.panic_file' => '/var/run/firewall/panic',
        ]);

        $this->assertFindingMatches(Diagnosis::ERROR, '/panic switch cannot work/', $this->diagnose());
    }

    #[Test]
    public function it_warns_about_a_persistent_singleton_even_with_no_panic_file(): void
    {
        config(['firewall.octane.persist_instance' => true]);

        $this->assertFindingMatches(Diagnosis::WARNING, '/persistent singleton/', $this->diagnose());
    }

    #[Test]
    public function a_default_installation_says_nothing_about_octane(): void
    {
        $this->assertNoFindingMentions('octane');
        $this->assertNoFindingMentions('singleton');
    }

    #[Test]
    public function it_reports_a_configured_config_file_that_is_missing(): void
    {
        config(['firewall.configs' => ['/no/such/rules.yml']]);

        $findings = $this->diagnose();

        $this->assertFindingMatches(Diagnosis::ERROR, '/config file is missing/', $findings);
        $this->assertFindingMatches(Diagnosis::ERROR, '/require_config is false/', $findings);
    }

    #[Test]
    public function it_notes_when_require_config_already_makes_that_fatal(): void
    {
        config([
            'firewall.configs' => ['/no/such/rules.yml', '/nor/this.yml'],
            'firewall.global.require_config' => true,
        ]);

        $this->assertFindingMatches(Diagnosis::ERROR, '/configured config files are missing/', $this->diagnose());
        $this->assertFindingMatches(Diagnosis::ERROR, '/also a boot failure/', $this->diagnose());
    }

    #[Test]
    public function it_warns_when_the_firewall_logs_nowhere(): void
    {
        $this->assertFindingMatches(Diagnosis::WARNING, '/no log handlers/', $this->diagnose());
    }

    #[Test]
    public function it_confirms_where_the_firewall_logs(): void
    {
        config(['firewall.logger.channel' => 'single']);

        $findings = $this->diagnose();

        $this->assertFindingMatches(Diagnosis::OK, '/Firewall logs to \d+ handler/', $findings);
        $this->assertFindingMatches(Diagnosis::OK, '/Borrowed from the "single" log channel/', $findings);
    }

    /**
     * A channel that resolves but carries no Monolog handlers is named.
     *
     * Not reachable by naming a channel that does not exist: Laravel falls
     * back to its emergency logger, which has a handler, so the firewall would
     * actually be logging. The reachable case is a `custom` driver returning a
     * PSR-3 logger that is not Monolog — see the fixture.
     */
    /**
     * Declarative handlers with no channel are reported without naming one.
     */
    #[Test]
    public function it_reports_declarative_handlers_without_a_channel(): void
    {
        config([
            'firewall.logger.channel' => null,
            'firewall.logger.handlers' => [['class' => \Monolog\Handler\NullHandler::class]],
        ]);

        $findings = $this->diagnose();

        $this->assertFindingMatches(Diagnosis::OK, '/Firewall logs to 1 handler/', $findings);

        foreach ($findings as $finding) {
            if (str_contains($finding->title, 'Firewall logs to')) {
                $this->assertNull($finding->detail, 'There is no channel to name.');
            }
        }
    }

    #[Test]
    public function it_names_the_channel_that_resolved_to_nothing(): void
    {
        config([
            'logging.channels.bespoke' => [
                'driver' => 'custom',
                'via' => \Kanopi\Firewall\Laravel\Tests\Fixtures\HandlerlessLogger::class,
            ],
            'firewall.logger.channel' => 'bespoke',
        ]);

        $this->assertFindingMatches(
            Diagnosis::WARNING,
            '/"bespoke" log channel resolved to no Monolog handlers/',
            $this->diagnose()
        );
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function challengeRule(array $overrides = []): void
    {
        config([
            'firewall.challenge.secret' => 'long-enough-secret-for-hmac-signing-here',
            'firewall.plugins' => [array_merge([
                'plugin' => \Kanopi\Firewall\Plugins\Url::class,
                'response' => 'challenge',
                'name' => 'gate',
                'config' => ['path:/gated'],
            ], $overrides)],
        ]);
    }

    /**
     * Run the checks with the environment facts overridden.
     *
     * @return array<int, Diagnosis>
     */
    private function diagnoseAs(bool $runningInConsole = true, string $sapi = PHP_SAPI): array
    {
        $factory = $this->app->make(\Kanopi\Firewall\Laravel\FirewallFactory::class);

        return (new IntegrationDoctor(
            \Kanopi\Firewall\Laravel\Support\Settings::for($this->app),
            $factory->translator(),
            $factory->trustedProxies(),
            $factory->logHandlers(),
            $runningInConsole,
            $sapi
        ))->run();
    }

    /**
     * Run the checks as a web request would.
     *
     * `Application::runningInConsole()` memoises its answer, and Testbench
     * boots a console application, so the web branch cannot be reached by
     * changing the environment. The doctor takes the fact as a constructor
     * argument for exactly this reason — the ordering check is the one finding
     * that only means something during a request.
     *
     * @return array<int, Diagnosis>
     */
    private function runAsWebRequest(): array
    {
        return $this->diagnoseAs(runningInConsole: false);
    }

    /**
     * @return array<int, Diagnosis>
     */
    private function diagnose(): array
    {
        return $this->app->make(IntegrationDoctor::class)->run();
    }

    /**
     * @return array<int, Diagnosis>
     */
    private function errors(): array
    {
        return array_values(array_filter(
            $this->diagnose(),
            static fn (Diagnosis $diagnosis): bool => $diagnosis->status === Diagnosis::ERROR
        ));
    }

    /**
     * Assert that no finding's title mentions a word.
     */
    private function assertNoFindingMentions(string $word): void
    {
        $mentions = array_values(array_filter(
            array_map(
                static fn (Diagnosis $diagnosis): string => $diagnosis->title,
                $this->diagnose()
            ),
            static fn (string $title): bool => stripos($title, $word) !== false
        ));

        $this->assertSame([], $mentions, sprintf('Expected nothing to be reported about "%s".', $word));
    }

    /**
     * @param array<int, Diagnosis> $findings
     */
    private function assertFindingMatches(string $status, string $pattern, array $findings): void
    {
        foreach ($findings as $finding) {
            if ($finding->status !== $status) {
                continue;
            }

            $haystack = $finding->title . "\n" . ($finding->detail ?? '');

            if (preg_match($pattern, $haystack) === 1) {
                $this->addToAssertionCount(1);

                return;
            }
        }

        $this->fail(sprintf(
            "No %s finding matched %s.\nFindings:\n%s",
            $status,
            $pattern,
            implode("\n", array_map(
                static fn (Diagnosis $d): string => sprintf('  [%s] %s', $d->status, $d->title),
                $findings
            ))
        ));
    }
}
