<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Illuminate\Events\Dispatcher;
use Illuminate\Log\LogManager;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\FirewallFactory;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

final class FirewallFactoryTest extends TestCase
{
    #[Test]
    public function it_builds_a_firewall_in_a_deliverable_mode(): void
    {
        $firewall = $this->factory()->make();

        $this->assertSame(FirewallMode::Exception, $firewall->getMode());
    }

    /**
     * The shipped defaults keep `global` a mapping, so the override cannot fail.
     *
     * Worth its own test because it is the reason the failure above needs a
     * contrived setup: the inline array is merged last and the default config
     * puts two keys in that section, so a preset declaring `global:` as a
     * scalar is overwritten rather than obeyed.
     */
    #[Test]
    public function the_shipped_defaults_protect_the_mode_override(): void
    {
        $config = $this->writeConfig("global: 'not-a-mapping'\n");

        try {
            config(['firewall.configs' => [$config]]);

            $this->assertSame(FirewallMode::Exception, $this->factory()->make()->getMode());
        } finally {
            unlink($config);
        }
    }

    /**
     * The check that stops the library calling `exit()` mid-request.
     *
     * Staged with a config file whose `global:` is a scalar. PropertyAccess
     * cannot write `[global][mode]` into a string, `Config::load()` swallows
     * the failure, and the library falls back to its own default of `block` —
     * which is the mode that writes a response and exits. Nothing about that
     * announces itself, which is why it is asserted rather than trusted.
     *
     * `firewall.global` has to be emptied for the scalar to survive. Shipped
     * defaults put `require_config` and `require_trusted_proxies` in that
     * section, and the inline array is merged last — so in a stock
     * installation the array wins and `global` is a mapping whatever a preset
     * says, which is a real defence rather than an accident. Emptying the
     * section is what an operator does when they want the library's own
     * defaults for everything in it, and that is the configuration in which
     * this can bite.
     */
    #[Test]
    public function it_refuses_to_boot_when_the_mode_override_did_not_land(): void
    {
        $config = $this->writeConfig("global: 'not-a-mapping'\n");

        try {
            config(['firewall.global' => [], 'firewall.configs' => [$config]]);

            $this->expectException(IntegrationException::class);
            $this->expectExceptionMessageMatches('/override did not take/');

            $this->factory()->make();
        } finally {
            unlink($config);
        }
    }

    /**
     * A panic file asking for `block` is refused, and says what to write instead.
     *
     * The panic switch is applied after the mode override, so the configured
     * mode can be perfectly correct while the effective one is `block`. An
     * operator reaching for the switch during an incident gets a message
     * naming the two values that would work, rather than a truncated page.
     */
    #[Test]
    public function it_refuses_a_panic_file_that_asks_for_block_mode(): void
    {
        $panic = $this->writeConfig("block\n");

        try {
            config(['firewall.global.panic_file' => $panic]);

            $this->expectException(IntegrationException::class);
            $this->expectExceptionMessageMatches('/panic file at .* asks for mode "block"/');

            $this->factory()->make();
        } finally {
            unlink($panic);
        }
    }

    #[Test]
    public function a_panic_file_asking_for_a_deliverable_mode_is_honoured(): void
    {
        $panic = $this->writeConfig("log\n");

        try {
            config(['firewall.global.panic_file' => $panic]);

            $firewall = $this->factory()->make();

            $this->assertSame(FirewallMode::Log, $firewall->getMode());
            $this->assertSame(FirewallMode::Exception, $firewall->getConfiguredMode());
        } finally {
            unlink($panic);
        }
    }

    /**
     * The translator is rebuilt per call, which matters under Octane.
     *
     * The factory is a singleton, so a memoised translator would hold the
     * trusted-proxy posture read during the first request a worker served —
     * and `TrustProxies` sets that state per request, so every request after
     * the first would be told about the first one's proxies.
     */
    #[Test]
    public function the_translator_reflects_configuration_changes(): void
    {
        $factory = $this->factory();

        $this->assertSame(FirewallMode::Exception, $factory->translator()->effectiveMode());

        config(['firewall.global.mode' => 'log']);

        $this->assertSame(FirewallMode::Log, $factory->translator()->effectiveMode());
    }

    #[Test]
    public function it_wires_laravel_listeners_into_firewall_decisions(): void
    {
        $seen = [];

        $this->app->make('events')->listen(
            \Kanopi\Firewall\Event\RequestBlocked::class,
            static function (\Kanopi\Firewall\Event\RequestBlocked $event) use (&$seen): void {
                $seen[] = $event;
            }
        );

        $this->blockIp('127.0.0.1');

        \Illuminate\Support\Facades\Route::get('/watched', static fn (): string => 'through');

        $this->get('/watched')->assertStatus(400);

        $this->assertCount(1, $seen, 'A block must reach a Laravel listener.');
    }

    /**
     * A listener that throws must not turn a block into a 500.
     *
     * The library swallows and logs it, deliberately: the verdict is already
     * decided by the time the event is announced, so a listener cannot change
     * it — and must not be able to break it either.
     */
    #[Test]
    public function a_listener_that_throws_does_not_break_the_decision(): void
    {
        $this->app->make('events')->listen(
            \Kanopi\Firewall\Event\RequestBlocked::class,
            static function (): void {
                throw new \RuntimeException('a listener exploded');
            }
        );

        $this->blockIp('127.0.0.1');

        \Illuminate\Support\Facades\Route::get('/watched', static fn (): string => 'through');

        $this->get('/watched')->assertStatus(400);
    }

    /**
     * With no dispatcher bound, the mechanism is switched off rather than fatal.
     *
     * Which is what a bespoke bootstrap or a console-only container should get.
     */
    #[Test]
    public function it_builds_without_an_event_dispatcher(): void
    {
        unset($this->app['events']);

        $this->assertInstanceOf(Firewall::class, $this->factory()->make());
    }

    #[Test]
    public function it_builds_when_the_events_binding_is_not_a_dispatcher(): void
    {
        $this->app->instance('events', new \stdClass());

        $this->assertInstanceOf(Firewall::class, $this->factory()->make());
    }

    #[Test]
    public function it_restores_a_real_dispatcher_check(): void
    {
        $this->app->instance('events', new Dispatcher($this->app));

        $this->assertInstanceOf(Firewall::class, $this->factory()->make());
    }

    /**
     * A log channel is not worth refusing traffic over.
     *
     * The firewall still evaluates every rule; `firewall:doctor` reports that
     * it is logging nowhere. Refusing here would take a site down because a
     * log destination was misnamed.
     */
    #[Test]
    public function it_builds_when_the_log_binding_is_missing(): void
    {
        config(['firewall.logger.channel' => 'single']);
        unset($this->app['log']);

        $this->assertSame([], $this->factory()->logHandlers()->all());
    }

    #[Test]
    public function it_builds_when_the_log_binding_is_not_a_log_manager(): void
    {
        config(['firewall.logger.channel' => 'single']);
        $this->app->instance('log', new \stdClass());

        $this->assertSame([], $this->factory()->logHandlers()->all());
    }

    #[Test]
    public function it_survives_a_log_manager_that_throws(): void
    {
        config(['firewall.logger.channel' => 'single']);

        $manager = new class ($this->app) extends LogManager {
            public function channel($channel = null)
            {
                throw new \RuntimeException('no such channel');
            }
        };

        $this->app->instance('log', $manager);

        $this->assertSame([], $this->factory()->logHandlers()->all());
    }

    #[Test]
    public function it_borrows_handlers_from_the_configured_channel(): void
    {
        config(['firewall.logger.channel' => 'single']);

        $this->assertNotSame([], $this->factory()->logHandlers()->all());
    }

    #[Test]
    public function an_explicit_preset_path_overrides_the_installed_one(): void
    {
        $directory = sys_get_temp_dir() . '/firewall-presets-' . bin2hex(random_bytes(4));
        mkdir($directory);
        file_put_contents($directory . '/local.yml', "plugins: []\n");

        try {
            config([
                'firewall.artisan.preset_path' => $directory,
                'firewall.presets' => ['local'],
            ]);

            $this->assertContains($directory . '/local.yml', $this->factory()->translator()->configs());
        } finally {
            unlink($directory . '/local.yml');
            rmdir($directory);
        }
    }

    #[Test]
    public function the_managed_rules_file_is_loaded_once_it_exists(): void
    {
        $managed = $this->writeConfig("plugins: []\n");

        try {
            config(['firewall.artisan.managed_rules' => $managed]);

            $this->assertContains($managed, $this->factory()->translator()->configs());
        } finally {
            unlink($managed);
        }
    }

    #[Test]
    public function an_absent_managed_rules_file_is_not_loaded_and_not_a_fault(): void
    {
        config(['firewall.artisan.managed_rules' => '/no/such/managed.yml']);

        $translator = $this->factory()->translator();

        $this->assertNotContains('/no/such/managed.yml', $translator->configs());
        $this->assertSame([], $translator->missingConfigs());
    }

    #[Test]
    public function the_managed_rules_feature_can_be_switched_off(): void
    {
        config(['firewall.artisan.managed_rules' => null]);

        $this->assertInstanceOf(Firewall::class, $this->factory()->make());
    }

    private function factory(): FirewallFactory
    {
        return new FirewallFactory($this->app);
    }

    private function writeConfig(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'firewall-test-');
        $this->assertIsString($path);
        file_put_contents($path, $contents);

        return $path;
    }
}
