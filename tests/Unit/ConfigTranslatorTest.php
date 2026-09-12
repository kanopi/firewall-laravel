<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Unit;

use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Laravel\Config\ConfigTranslator;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\Support\PackagePaths;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ConfigTranslatorTest extends TestCase
{
    #[Test]
    public function it_puts_the_mode_in_the_overrides_not_the_config(): void
    {
        $translator = $this->translator(['global' => ['mode' => 'exception']]);

        $this->assertSame(['[global][mode]' => 'exception'], $translator->overrides());
        $this->assertArrayNotHasKey('mode', $translator->inlineConfig()['global'] ?? []);
    }

    /**
     * Trap 1, at the point where it is prevented.
     *
     * `block` mode makes the library write its own response and call `exit()`.
     * Translating it to `exception` is what lets Laravel render the block
     * instead, and the translation has to be delivered as an override rather
     * than merged config — a preset carrying `global.mode: block` would
     * otherwise win the merge and reintroduce the `exit()`.
     */
    #[Test]
    public function block_mode_is_delivered_as_exception_mode(): void
    {
        $translator = $this->translator(['global' => ['mode' => 'block']]);

        $this->assertSame(FirewallMode::Block, $translator->configuredMode());
        $this->assertSame(FirewallMode::Exception, $translator->effectiveMode());
        $this->assertTrue($translator->modeWasTranslated());
        $this->assertSame(['[global][mode]' => 'exception'], $translator->overrides());
    }

    #[Test]
    public function block_is_the_default_mode(): void
    {
        $this->assertSame(FirewallMode::Block, $this->translator([])->configuredMode());
        $this->assertSame(FirewallMode::Exception, $this->translator([])->effectiveMode());
    }

    /**
     * The modes that write no response are passed through untouched.
     *
     * Reimplementing what `log` mode records would mean maintaining a second
     * copy of the library's decision reporting, and it would drift.
     */
    #[Test]
    #[DataProvider('passthroughModes')]
    public function modes_that_write_no_response_are_untouched(string $mode): void
    {
        $translator = $this->translator(['global' => ['mode' => $mode]]);

        $this->assertSame($mode, $translator->effectiveMode()->value);
        $this->assertFalse($translator->modeWasTranslated());
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function passthroughModes(): array
    {
        return ['log' => ['log'], 'exception' => ['exception'], 'disabled' => ['disabled']];
    }

    /**
     * A mistyped mode is refused rather than defaulted.
     *
     * The library defaults an unknown mode to `block`, which is right for it —
     * failing towards enforcement. Here `block` is the one mode that cannot be
     * delivered as written, so defaulting would silently produce the exact
     * behaviour this package exists to translate away.
     */
    #[Test]
    public function an_unrecognised_mode_is_refused(): void
    {
        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/"lgo" is not recognised/');

        $this->translator(['global' => ['mode' => 'lgo']])->configuredMode();
    }

    #[Test]
    public function a_non_string_mode_is_refused_by_type_name(): void
    {
        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/"array" is not recognised|array" is not recognised/');

        $this->translator(['global' => ['mode' => ['block']]])->configuredMode();
    }

    #[Test]
    public function it_resolves_preset_names_to_paths(): void
    {
        $configs = $this->translator(['presets' => ['wordpress', 'malicious-urls']])->configs();

        $this->assertSame(PackagePaths::presets() . '/wordpress.yml', $configs[0]);
        $this->assertSame(PackagePaths::presets() . '/malicious-urls.yml', $configs[1]);
        $this->assertIsArray(end($configs), 'The inline config array must come last so it wins the merge.');
    }

    /**
     * A mistyped preset name is refused, and says what is available.
     *
     * Left to the library this fails silently: config loading is lenient, so
     * `presets: ['wordpess']` logs an error and starts with no WordPress rules
     * — which looks exactly like a firewall that is working.
     */
    #[Test]
    public function a_missing_preset_is_refused_with_the_available_list(): void
    {
        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/"wordpess" does not exist/');
        $this->expectExceptionMessageMatches('/wordpress/');

        $this->translator(['presets' => ['wordpess']])->configs();
    }

    #[Test]
    public function it_ignores_non_string_preset_entries(): void
    {
        $configs = $this->translator(['presets' => [42, null, ['nested']]])->configs();

        $this->assertCount(1, $configs);
        $this->assertIsArray($configs[0]);
    }

    #[Test]
    public function it_ignores_a_presets_key_that_is_not_a_list(): void
    {
        $this->assertCount(1, $this->translator(['presets' => 'wordpress'])->configs());
    }

    #[Test]
    public function it_includes_config_files_that_exist_and_reports_the_rest(): void
    {
        $existing = tempnam(sys_get_temp_dir(), 'fw-config-');
        $this->assertIsString($existing);
        file_put_contents($existing, "global: ~\n");

        try {
            $translator = $this->translator(['configs' => [$existing, '/no/such/file.yml', 42]]);

            $this->assertContains($existing, $translator->configs());
            $this->assertNotContains('/no/such/file.yml', $translator->configs());
            $this->assertSame(['/no/such/file.yml'], $translator->missingConfigs());
        } finally {
            unlink($existing);
        }
    }

    #[Test]
    public function it_ignores_a_configs_key_that_is_not_a_list(): void
    {
        $translator = $this->translator(['configs' => 'not-a-list']);

        $this->assertCount(1, $translator->configs());
        $this->assertSame([], $translator->missingConfigs());
    }

    #[Test]
    public function it_passes_through_the_library_sections(): void
    {
        $inline = $this->translator([
            'storage' => ['type' => 'Some\Storage'],
            'challenge' => ['provider' => 'math'],
            'plugins' => [['plugin' => 'A']],
        ])->inlineConfig();

        $this->assertSame(['type' => 'Some\Storage'], $inline['storage']);
        $this->assertSame(['provider' => 'math'], $inline['challenge']);
        $this->assertSame([['plugin' => 'A']], $inline['plugins']);
    }

    /**
     * `plugins` must be the last section, so a preset's rules concatenate.
     */
    #[Test]
    public function plugins_come_after_the_other_sections(): void
    {
        $keys = array_keys($this->translator([
            'plugins' => [['plugin' => 'A']],
            'storage' => ['type' => 'S'],
            'challenge' => ['provider' => 'math'],
            'global' => ['status_code' => 403],
        ])->inlineConfig());

        $this->assertSame(count($keys) - 1, array_search('plugins', $keys, true));
    }

    #[Test]
    public function it_drops_empty_sections(): void
    {
        $inline = $this->translator(['storage' => [], 'plugins' => [], 'global' => []])->inlineConfig();

        $this->assertArrayNotHasKey('storage', $inline);
        $this->assertArrayNotHasKey('plugins', $inline);
        $this->assertArrayNotHasKey('global', $inline);
    }

    #[Test]
    public function it_ignores_sections_that_are_not_arrays(): void
    {
        $inline = $this->translator(['storage' => 'nope', 'plugins' => 5])->inlineConfig();

        $this->assertArrayNotHasKey('storage', $inline);
        $this->assertArrayNotHasKey('plugins', $inline);
    }

    #[Test]
    public function it_fills_in_the_derived_trusted_proxy_posture(): void
    {
        $inline = $this->translator([], behindProxy: true)->inlineConfig();

        $this->assertTrue($inline['global']['behind_proxy']);
    }

    /**
     * An explicit assertion in config always beats the derived value.
     *
     * `behind_proxy: false` is the one answer that silences the library's
     * warning completely, so an operator who has said it must not have it
     * overwritten by something inferred from Laravel's config.
     */
    #[Test]
    public function an_explicit_posture_wins_over_the_derived_one(): void
    {
        $inline = $this->translator(
            ['global' => ['behind_proxy' => false]],
            behindProxy: true
        )->inlineConfig();

        $this->assertFalse($inline['global']['behind_proxy']);
    }

    /**
     * A NULL is dropped so the library sees "not configured", not "false".
     */
    #[Test]
    public function null_global_values_are_dropped_rather_than_passed_as_null(): void
    {
        $inline = $this->translator([
            'global' => ['behind_proxy' => null, 'panic_file' => null, 'require_config' => false],
        ])->inlineConfig();

        $this->assertArrayNotHasKey('behind_proxy', $inline['global'] ?? []);
        $this->assertArrayNotHasKey('panic_file', $inline['global'] ?? []);
        $this->assertFalse(
            $inline['global']['require_config'],
            'An explicit false must survive: array_filter() would have stripped it.'
        );
    }

    #[Test]
    public function it_includes_the_logger_handlers_it_was_given(): void
    {
        $handlers = [['class' => 'Monolog\Handler\NullHandler']];

        $this->assertSame($handlers, $this->translator([], loggerHandlers: $handlers)->inlineConfig()['logger']);
    }

    #[Test]
    public function it_omits_the_logger_section_when_there_are_no_handlers(): void
    {
        $this->assertArrayNotHasKey('logger', $this->translator([])->inlineConfig());
    }

    #[Test]
    public function it_lists_the_available_presets(): void
    {
        $presets = $this->translator([])->availablePresets();

        $this->assertContains('wordpress', $presets);
        $this->assertContains('drupal', $presets);
        $this->assertSame($presets, array_values($presets), 'The list must be re-indexed after sorting.');
    }

    #[Test]
    public function it_reports_no_presets_when_the_directory_is_missing(): void
    {
        $translator = new ConfigTranslator([], '/no/such/presets/directory');

        $this->assertSame([], $translator->availablePresets());
    }

    /**
     * @param array<string, mixed> $config
     * @param array<int, array<string, mixed>> $loggerHandlers
     */
    private function translator(
        array $config,
        ?bool $behindProxy = null,
        array $loggerHandlers = []
    ): ConfigTranslator {
        return new ConfigTranslator($config, PackagePaths::presets(), $behindProxy, $loggerHandlers);
    }
}
