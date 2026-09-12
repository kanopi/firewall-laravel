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
use PHPUnit\Framework\Attributes\Test;

/**
 * The Artisan wrappers, exercised against the real bin/ scripts.
 *
 * These genuinely fork a PHP process and run the library's own script, which
 * makes them the slowest tests here and the only ones that can catch what
 * matters most about this layer: that the YAML this package writes out of a PHP
 * config array is something the scripts can actually consume. A test that
 * stubbed the subprocess would assert that the arguments were assembled, which
 * is the half that has never been wrong.
 */
final class ConsoleTest extends TestCase
{
    /**
     * The command that proves the config dump round-trips.
     *
     * `firewall-check --lint` loads the configuration and reports what is wrong
     * with the rules. Reaching a verdict at all means the dumped YAML parsed,
     * the storage type resolved, and the rules built — so this one assertion
     * covers the whole translation path end to end.
     */
    #[Test]
    public function check_lints_the_effective_configuration(): void
    {
        $this->blockIp('198.51.100.1');

        $this->artisan('firewall:check', ['--lint' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function check_reports_a_request_that_would_be_blocked(): void
    {
        $this->blockIp('198.51.100.1');

        $this->artisan('firewall:check', ['--ip' => '198.51.100.1', '--url' => '/'])
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function check_reports_a_request_that_would_be_allowed(): void
    {
        $this->blockIp('198.51.100.1');

        $this->artisan('firewall:check', ['--ip' => '203.0.113.9', '--url' => '/'])
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * The rules the command sees are the rules the middleware sees.
     *
     * This is the assertion that the whole subprocess arrangement is worth
     * having: `firewall:check` says a request would be blocked, and the
     * middleware then blocks it. If the config dump drifted from the runtime
     * translation, the two would disagree — and a checker that confidently
     * answers the wrong question is worse than no checker.
     */
    #[Test]
    public function check_agrees_with_what_the_middleware_does(): void
    {
        $this->blockIp('198.51.100.1');

        \Illuminate\Support\Facades\Route::get('/probe', static fn (): string => 'through');
        \Illuminate\Http\Middleware\TrustProxies::at(['127.0.0.1']);

        $this->artisan('firewall:check', ['--ip' => '198.51.100.1', '--url' => '/probe'])
            ->assertExitCode(FirewallCommand::EXIT_ERROR);

        $this->get('/probe', ['X-Forwarded-For' => '198.51.100.1'])->assertStatus(400);
    }

    #[Test]
    public function check_passes_repeatable_headers_through(): void
    {
        // Matched on the raw header rather than through the UserAgent plugin.
        // What is being tested is that a repeatable `--header` reaches the
        // script, and routing that through device-detector's client-name
        // parsing would make the assertion depend on which version of that
        // database happened to be installed — a test that fails for reasons
        // unrelated to the thing it names.
        config(['firewall.plugins' => [[
            'plugin' => \Kanopi\Firewall\Plugins\Url::class,
            'response' => 'block',
            'name' => 'block-scanner-header',
            'config' => ['header.x-scanner@contains:sqlmap'],
        ]]]);

        $this->artisan('firewall:check', [
            '--url' => '/',
            '--header' => ['X-Scanner: sqlmap/1.8'],
        ])->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function doctor_runs_both_halves_and_reports_the_integration_first(): void
    {
        $this->artisan('firewall:doctor')
            ->expectsOutputToContain('Laravel integration checks')
            ->expectsOutputToContain('Library checks');
    }

    #[Test]
    public function doctor_fails_when_an_integration_check_fails(): void
    {
        config(['firewall.configs' => ['/no/such/rules.yml']]);

        $this->artisan('firewall:doctor', ['--integration-only' => true])
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function doctor_integration_only_skips_the_library_checks(): void
    {
        $this->artisan('firewall:doctor', ['--integration-only' => true])
            ->doesntExpectOutputToContain('Library checks')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function doctor_emits_json_when_asked(): void
    {
        $this->artisan('firewall:doctor', ['--json' => true, '--integration-only' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function doctor_can_hide_the_passing_checks(): void
    {
        $this->artisan('firewall:doctor', ['--integration-only' => true, '--quiet-checks' => true])
            ->doesntExpectOutputToContain('The firewall is enabled')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * Every check passing still prints something.
     *
     * A command that produced no output on success would be indistinguishable
     * from one that did not run.
     */
    #[Test]
    public function doctor_says_so_when_quiet_mode_has_nothing_to_report(): void
    {
        \Illuminate\Http\Middleware\TrustProxies::at(['127.0.0.1']);
        \Symfony\Component\HttpFoundation\Request::setTrustedProxies(
            ['127.0.0.1'],
            \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_FOR
        );
        config(['firewall.logger.channel' => 'single']);

        $this->artisan('firewall:doctor', ['--integration-only' => true, '--quiet-checks' => true])
            ->expectsOutputToContain('Nothing to report');
    }

    #[Test]
    public function doctor_prints_a_documentation_reference_for_a_finding_that_has_one(): void
    {
        config(['firewall.configs' => ['/no/such/rules.yml']]);

        $this->artisan('firewall:doctor', ['--integration-only' => true])
            ->expectsOutputToContain('github.com/kanopi/firewall');
    }

    /**
     * `firewall:blocks` — plural — is the listing wrapper.
     *
     * The singular `firewall:block` adds to the list and is native code rather
     * than a forwarded script; splitting them means a bare typo cannot reach
     * the destructive reading.
     */
    #[Test]
    public function blocks_lists_an_empty_blocklist(): void
    {
        $this->artisan('firewall:blocks')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function blocks_accepts_an_explicit_list_flag(): void
    {
        $this->artisan('firewall:blocks', ['--list' => true, '--json' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function blocks_accepts_a_lift_pattern(): void
    {
        $this->artisan('firewall:blocks', ['--lift' => ['198.51.100.1'], '--dry-run' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * A configuration with rules but no sources has nothing to fetch.
     *
     * A rule has to be declared first: the script exits 2 on a configuration
     * with no plugins at all, treating "nothing configured" as a config
     * problem rather than a clean run — which is the right call for a command
     * an operator points at a config file expecting it to do something.
     */
    #[Test]
    public function sources_reports_nothing_to_do_when_no_source_is_declared(): void
    {
        $this->blockIp('198.51.100.1');

        $this->artisan('firewall:sources', ['--dry-run' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * `--quiet-output`, not `--quiet`.
     *
     * Symfony Console reserves `--quiet` for its own verbosity flag, so an
     * Artisan command cannot declare it. The rename is invisible to the
     * script, which still receives `--quiet`.
     */
    #[Test]
    public function sources_forwards_the_renamed_quiet_flag(): void
    {
        $this->blockIp('198.51.100.1');

        $this->artisan('firewall:sources', ['--dry-run' => true, '--quiet-output' => true, '--force' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function migrate_reports_that_no_database_table_is_declared(): void
    {
        // Exit 2: the config declared no database-backed tables, so there is
        // nothing to migrate. Not a failure of the command — the in-memory
        // storage this suite uses has no schema.
        $this->artisan('firewall:migrate', ['--dry-run' => true])
            ->assertExitCode(FirewallCommand::EXIT_CONFIG_UNREADABLE);
    }

    #[Test]
    public function log_prune_reports_that_no_log_table_is_declared(): void
    {
        $this->artisan('firewall:log-prune', ['--dry-run' => true, '--days' => '30'])
            ->assertExitCode(FirewallCommand::EXIT_CONFIG_UNREADABLE);
    }

    #[Test]
    public function init_warns_that_publishing_the_config_is_usually_better(): void
    {
        $this->artisan('firewall:init', ['--print' => true, '--platform' => 'other', '--cdn' => 'none', '--storage' => 'file', '--mode' => 'log'])
            ->expectsOutputToContain('vendor:publish')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * The whole `firewall:rule` loop: write a rule, then see it enforced.
     *
     * The connection being tested is the one most likely to be quietly broken:
     * the command writes to a file it owns, and that file has to be loaded by
     * the running firewall for the rule to mean anything. If it were not, the
     * command would report success and change nothing.
     */
    #[Test]
    public function rule_add_writes_a_rule_that_the_firewall_then_enforces(): void
    {
        $managed = $this->managedRulesPath();

        $this->artisan('firewall:rule', [
            'action' => 'add',
            '--ip' => ['203.0.113.55'],
            '--response' => 'block',
            '--name' => 'added-by-test',
        ])->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertFileExists($managed);
        $this->assertStringContainsString('203.0.113.55', (string) file_get_contents($managed));

        // The rule is live without any further wiring, because the factory adds
        // the managed file to the firewall's config inputs as soon as it exists.
        $this->artisan('firewall:check', ['--ip' => '203.0.113.55', '--url' => '/'])
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function rule_list_names_where_each_rule_came_from(): void
    {
        $this->blockIp('198.51.100.1');

        $this->artisan('firewall:rule', ['action' => 'list'])
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function rule_remove_takes_the_name_after_the_config(): void
    {
        $this->artisan('firewall:rule', [
            'action' => 'add',
            '--ip' => ['203.0.113.56'],
            '--name' => 'to-be-removed',
        ])->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:rule', ['action' => 'remove', 'name' => 'to-be-removed'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertStringNotContainsString(
            '203.0.113.56',
            (string) file_get_contents($this->managedRulesPath())
        );
    }

    /**
     * Rules declared in `config/firewall.php` are listed, never edited.
     *
     * A command that rewrote a PHP config file would have to preserve
     * comments, `env()` calls and formatting, and would eventually fail to. So
     * it refuses by name instead, which is the more useful answer.
     */
    #[Test]
    public function rule_refuses_to_touch_a_rule_it_does_not_own(): void
    {
        $this->blockIp('198.51.100.1', ['name' => 'declared-in-php']);

        $this->artisan('firewall:rule', ['action' => 'remove', 'name' => 'declared-in-php'])
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    /**
     * The managed file is created on demand, so `add` works on a fresh install.
     *
     * Without this the script would write the rule, warn that nothing includes
     * the file, and exit non-zero — having changed the file but not the
     * firewall. The two steps are not independent, so the command does both.
     */
    #[Test]
    public function rule_creates_the_managed_file_before_using_it(): void
    {
        $this->assertFileDoesNotExist($this->managedRulesPath());

        $this->artisan('firewall:rule', ['action' => 'list'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertFileExists($this->managedRulesPath());
    }

    #[Test]
    public function rule_init_does_not_recurse(): void
    {
        $this->artisan('firewall:rule', ['action' => 'init'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertFileExists($this->managedRulesPath());
    }

    #[Test]
    public function rule_can_disable_and_re_enable_a_managed_rule(): void
    {
        $this->artisan('firewall:rule', [
            'action' => 'add',
            '--path' => ['/admin'],
            '--name' => 'toggle-me',
        ])->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:rule', ['action' => 'disable', 'name' => 'toggle-me'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:rule', ['action' => 'enable', 'name' => 'toggle-me'])
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function rule_add_can_be_rehearsed(): void
    {
        $this->artisan('firewall:rule', ['action' => 'init'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:rule', [
            'action' => 'add',
            '--rule' => ['203.0.113.99'],
            '--plugin' => 'ip',
            '--weight' => '10',
            '--name' => 'rehearsal',
            '--dry-run' => true,
            '--json' => true,
        ])->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertStringNotContainsString(
            '203.0.113.99',
            (string) file_get_contents($this->managedRulesPath())
        );
    }

    #[Test]
    public function rule_honours_an_explicit_managed_path(): void
    {
        $elsewhere = sys_get_temp_dir() . '/firewall-managed-elsewhere.yml';

        try {
            $this->artisan('firewall:rule', ['action' => 'init', '--managed' => $elsewhere])
                ->assertExitCode(FirewallCommand::EXIT_OK);

            $this->assertFileExists($elsewhere);
        } finally {
            if (is_file($elsewhere)) {
                unlink($elsewhere);
            }
        }
    }

    #[Test]
    public function a_missing_script_is_reported_rather_than_crashing(): void
    {
        config(['firewall.artisan.bin_path' => '/no/such/bin']);

        $this->artisan('firewall:doctor', ['--integration-only' => false])
            ->expectsOutputToContain('was not found at')
            ->assertExitCode(FirewallCommand::EXIT_CONFIG_UNREADABLE);
    }

    /**
     * The dumped configuration can be kept, and is the answer to "what did my
     * PHP config actually become".
     */
    #[Test]
    public function the_effective_configuration_can_be_kept_for_inspection(): void
    {
        $this->blockIp('198.51.100.1');

        $this->artisan('firewall:check', ['--lint' => true, '--keep-config' => true])
            ->expectsOutputToContain('Effective configuration written to')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        // Left behind on purpose, so clean it up here rather than in the
        // command — that is the whole point of the flag.
        foreach ((array) glob(sys_get_temp_dir() . '/firewall-effective-*') as $leftover) {
            if (is_string($leftover)) {
                @unlink($leftover);
            }
        }
    }

    /**
     * The challenge secret never lands on disk.
     *
     * A temp file is removed in a `finally`, which covers an ordinary failure
     * but not a `kill -9` or a full disk — and a signing secret left in /tmp is
     * a durable problem. So it travels in the subprocess environment and the
     * dumped YAML carries only an `%env(...)%` reference.
     */
    #[Test]
    public function the_challenge_secret_is_not_written_into_the_dumped_config(): void
    {
        config([
            'firewall.challenge.secret' => 'the-actual-signing-secret-value',
            'firewall.artisan.keep_effective_config' => true,
        ]);

        $this->artisan('firewall:check', ['--lint' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $dumps = array_filter((array) glob(sys_get_temp_dir() . '/firewall-effective-*'), 'is_string');
        $this->assertNotEmpty($dumps, 'The dump should have been kept.');

        try {
            foreach ($dumps as $dump) {
                $contents = (string) file_get_contents($dump);

                $this->assertStringNotContainsString('the-actual-signing-secret-value', $contents);
                $this->assertStringContainsString('%env(KANOPI_FIREWALL_LARAVEL_CLI_SECRET)%', $contents);
            }
        } finally {
            foreach ($dumps as $dump) {
                @unlink($dump);
            }
        }
    }

    /**
     * The presets an operator names come through as `configs:` includes.
     *
     * Resolved by the library rather than merged here, so the script sees the
     * identical merge the middleware would rather than this package's
     * approximation of it.
     */
    #[Test]
    public function presets_are_handed_to_the_script_as_includes(): void
    {
        config([
            'firewall.presets' => ['malicious-urls'],
            'firewall.artisan.keep_effective_config' => true,
        ]);

        $this->artisan('firewall:check', ['--lint' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $dumps = array_filter((array) glob(sys_get_temp_dir() . '/firewall-effective-*'), 'is_string');
        $this->assertNotEmpty($dumps);

        try {
            $contents = (string) file_get_contents((string) reset($dumps));

            $this->assertStringContainsString('configs:', $contents);
            $this->assertStringContainsString('malicious-urls.yml', $contents);
        } finally {
            foreach ($dumps as $dump) {
                @unlink($dump);
            }
        }
    }

    /**
     * Declared log handlers survive the dump; borrowed instances cannot.
     */
    #[Test]
    public function only_declarative_log_handlers_reach_the_script(): void
    {
        config([
            'firewall.logger.channel' => 'single',
            'firewall.logger.handlers' => [
                ['class' => \Monolog\Handler\NullHandler::class],
                'not-an-array',
                ['args' => ['no class key']],
            ],
            'firewall.artisan.keep_effective_config' => true,
        ]);

        $this->artisan('firewall:check', ['--lint' => true])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $dumps = array_filter((array) glob(sys_get_temp_dir() . '/firewall-effective-*'), 'is_string');
        $this->assertNotEmpty($dumps);

        try {
            $contents = (string) file_get_contents((string) reset($dumps));

            $this->assertStringContainsString('NullHandler', $contents);
            $this->assertStringNotContainsString('not-an-array', $contents);
            $this->assertStringNotContainsString('no class key', $contents);
        } finally {
            foreach ($dumps as $dump) {
                @unlink($dump);
            }
        }
    }

    /**
     * A temp directory that does not exist is reported, not worked around.
     *
     * `tempnam()` silently falls back to the system temp directory when the
     * one it is given is unusable, which is why this builds the path by hand:
     * a command that quietly wrote its configuration somewhere other than
     * where it was told is answering a question nobody asked.
     */
    #[Test]
    public function an_unwritable_temp_directory_is_reported(): void
    {
        config(['firewall.artisan.temp_path' => '/no/such/directory']);

        $this->expectException(\Kanopi\Firewall\Laravel\Exceptions\IntegrationException::class);
        $this->expectExceptionMessageMatches('/Unable to write the effective firewall configuration/');

        $this->artisan('firewall:check', ['--lint' => true])->run();
    }

    #[Test]
    public function a_configured_temp_directory_is_used(): void
    {
        $directory = sys_get_temp_dir() . '/firewall-temp-' . bin2hex(random_bytes(4));
        mkdir($directory);

        try {
            config([
                'firewall.artisan.temp_path' => $directory,
                'firewall.artisan.keep_effective_config' => true,
            ]);

            $this->artisan('firewall:check', ['--lint' => true])
                ->assertExitCode(FirewallCommand::EXIT_OK);

            $dumps = array_filter((array) glob($directory . '/firewall-effective-*.yml'), 'is_string');
            $this->assertCount(1, $dumps);
        } finally {
            foreach (array_filter((array) glob($directory . '/*'), 'is_string') as $file) {
                @unlink($file);
            }

            @rmdir($directory);
        }
    }

    /**
     * When the managed file cannot be created, the action is not attempted.
     *
     * Running `add` anyway would write nothing and report a confusing second
     * failure; returning the init exit code names the actual problem.
     *
     * The unwritable path is a directory *under a regular file*, which fails
     * with ENOTDIR for every user including root. The obvious
     * `/no/such/directory/managed.yml` is not unwritable at all when the suite
     * runs as root — which it does in a container — so this passed on macOS and
     * failed in Docker, testing the developer's permissions rather than the
     * command. Found by `tests/Integration/matrix.sh`, which is the reason that
     * script exists.
     */
    #[Test]
    public function rule_stops_when_the_managed_file_cannot_be_created(): void
    {
        $blocker = tempnam(sys_get_temp_dir(), 'fw-not-a-dir-');
        $this->assertIsString($blocker);

        try {
            config(['firewall.artisan.managed_rules' => $blocker . '/managed.yml']);

            $this->artisan('firewall:rule', ['action' => 'add', '--ip' => ['203.0.113.77']])
                ->assertExitCode(FirewallCommand::EXIT_ERROR);
        } finally {
            unlink($blocker);
        }
    }

    protected function tearDown(): void
    {
        $managed = $this->managedRulesPath();

        if (is_file($managed)) {
            unlink($managed);
        }

        parent::tearDown();
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        // Kept out of the skeleton application's config directory: the rule
        // command writes here for real, and a leftover file would silently
        // become part of the next test's ruleset.
        $app['config']->set(
            'firewall.artisan.managed_rules',
            sys_get_temp_dir() . '/firewall-managed-test.yml'
        );
    }

    private function managedRulesPath(): string
    {
        return sys_get_temp_dir() . '/firewall-managed-test.yml';
    }
}
