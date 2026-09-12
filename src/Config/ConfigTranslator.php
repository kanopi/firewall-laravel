<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Config;

use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;

/**
 * Turn `config/firewall.php` into the two arguments `Firewall::create()` takes.
 *
 * `create()` accepts a list of config inputs — YAML paths and/or arrays, merged
 * in order — and a separate list of PropertyAccess bracket-path overrides
 * applied after that merge. This class decides what belongs in which, and the
 * split is not arbitrary:
 *
 * - Anything an operator should be able to override from a preset or a YAML
 *   file goes in the **config inputs**, positioned last so it wins the merge.
 * - Anything the integration must guarantee regardless of what any file says
 *   goes in the **overrides**, because those are applied after every merge and
 *   cannot be outvoted.
 *
 * Exactly one setting is in the second category today: the mode. A preset — or
 * a file written by `firewall-init`, which defaults to writing one — can carry
 * `global.mode: block`, and `block` means the library writes its own response
 * and calls exit(). Under Laravel that terminates the process with no rendered
 * view, no terminating middleware and no response the framework knows about.
 * Putting the mode in the merged config would let such a file reintroduce it;
 * putting it in the overrides cannot.
 */
final class ConfigTranslator
{
    /**
     * Sections handed to the library verbatim, in the order it expects them.
     *
     * `plugins` is last deliberately. The library merges deeply, so a preset's
     * `plugins:` list and this one concatenate rather than replace — which is
     * the useful behaviour (start from a preset, add your own allow rules) and
     * is only true if ours arrives afterwards.
     */
    private const PASSTHROUGH_SECTIONS = ['global', 'storage', 'challenge', 'plugins'];

    /**
     * Modes that write a response themselves, and so cannot be passed through.
     *
     * `block` is the whole list, and the mapping is to `exception`: the same
     * decision, the same status code, delivered as something Laravel can catch
     * and render. `log` and `disabled` never write a response, so they are
     * left exactly as configured — reimplementing what `log` mode logs would
     * mean maintaining a second copy of the library's decision reporting.
     */
    private const RESPONSE_WRITING_MODES = ['block', 'lockdown'];

    /**
     * Modes that mean something beyond how a decision is delivered.
     *
     * `lockdown` is two things at once: a policy — refuse everybody but the
     * allowlist — and a delivery, which the library implements by rewriting its
     * own mode to `block`. Since 2.26 the policy has its own config key, so the
     * two can be separated: this integration takes `mode: lockdown` to mean
     * `global.lockdown: true` with the delivery it can actually use.
     *
     * Without this the mode would pass through untouched, the library would
     * rewrite it to `block`, and `FirewallFactory` would refuse to boot — safe,
     * but reporting a failed override to an operator who asked for lockdown and
     * did nothing wrong.
     *
     * @var array<string, string>
     */
    private const POLICY_MODES = ['lockdown' => '[global][lockdown]'];

    /**
     * @param array<string, mixed> $config
     *   The `firewall` config array, as Laravel resolved it.
     * @param string $presetDirectory
     *   Absolute path to kanopi/firewall's `presets/` directory.
     * @param ?bool $behindProxy
     *   The trusted-proxy posture derived from Laravel, or NULL when it could
     *   not be determined. Only used when the config leaves `behind_proxy`
     *   unset, so an explicit assertion in config always wins.
     * @param array<int, array<string, mixed>> $loggerHandlers
     *   Log handler definitions, already resolved to the library's format —
     *   including bare Monolog handler *instances* borrowed from a Laravel
     *   channel, which `LoggingFactory::create()` accepts alongside class
     *   names. Injected rather than resolved here so this class stays free of
     *   the service container and remains unit-testable without a Laravel app.
     * @param ?string $managedRules
     *   Path to the file `firewall:rule` owns, or NULL when the feature is
     *   switched off. Kept separate from `configs` rather than folded into it,
     *   for one reason: this path is expected not to exist. It is created by
     *   `firewall:rule add`, so on a fresh install it is absent — and a path
     *   in `configs` that does not exist is an operator mistake worth
     *   reporting, while this one is the normal state of a feature nobody has
     *   used yet. Merging the two would make `firewall:doctor` open with an
     *   error on every clean installation, which is the fastest way to teach
     *   people to ignore it.
     */
    public function __construct(
        private readonly array $config,
        private readonly string $presetDirectory,
        private readonly ?bool $behindProxy = null,
        private readonly array $loggerHandlers = [],
        private readonly ?string $managedRules = null
    ) {
    }

    /**
     * The config inputs for `Firewall::create()`'s first argument.
     *
     * Ordered presets, then extra YAML files, then the array built from this
     * config file — so the more specific input is always later, and later wins.
     *
     * @return array<int, string|array<string, mixed>>
     *   YAML paths and one config array.
     *
     * @throws IntegrationException
     *   When a named preset does not exist. A typo here is silent otherwise:
     *   the library loads config leniently, so `presets: ['wordpess']` would
     *   log an error and start with no WordPress rules at all, which looks
     *   exactly like a firewall that is working.
     */
    public function configs(): array
    {
        $inputs = [];

        foreach ($this->presets() as $preset) {
            $path = $this->presetDirectory . '/' . $preset . '.yml';

            if (!is_file($path)) {
                throw new IntegrationException(sprintf(
                    'Firewall preset "%s" does not exist (looked for %s). Available presets: %s.',
                    $preset,
                    $path,
                    implode(', ', $this->availablePresets())
                ));
            }

            $inputs[] = $path;
        }

        foreach ($this->extraConfigs() as $extra) {
            $inputs[] = $extra;
        }

        // After the operator's own files, so a rule added from the command
        // line is evaluated after everything declared in config — and before
        // the inline array, so a rule in `config/firewall.php` still wins.
        if ($this->managedRules !== null && is_file($this->managedRules)) {
            $inputs[] = $this->managedRules;
        }

        $inputs[] = $this->inlineConfig();

        return $inputs;
    }

    /**
     * The overrides for `Firewall::create()`'s second argument.
     *
     * @return array<string, mixed>
     *   PropertyAccess bracket paths to values.
     */
    public function overrides(): array
    {
        $overrides = ['[global][mode]' => $this->effectiveMode()->value];

        // An override rather than merged config, for the same reason the mode
        // is: `global.lockdown` is what actually refuses every visitor, and a
        // preset must not be able to reach it. Written only when the mode asked
        // for it — a host setting `global.lockdown` directly in config keeps
        // full control, including turning it off, because nothing here
        // overwrites a value it was not asked to set.
        $policy = self::POLICY_MODES[$this->configuredMode()->value] ?? null;

        if ($policy !== null) {
            $overrides[$policy] = true;
        }

        return $overrides;
    }

    /**
     * The mode the library will actually be constructed in.
     *
     * Exposed because the caller has to verify it landed. `Config::load()`
     * swallows an override it cannot apply, so a failed override is silent —
     * and the one override here is the one that stops the library calling
     * exit() in the middle of a Laravel request.
     */
    public function effectiveMode(): FirewallMode
    {
        $configured = $this->configuredMode();

        if (in_array($configured->value, self::RESPONSE_WRITING_MODES, true)) {
            return FirewallMode::Exception;
        }

        return $configured;
    }

    /**
     * The mode as written in `config/firewall.php`.
     *
     * An unrecognised value is refused rather than defaulted. The library
     * defaults an unknown mode to `block`, which is the right call for it —
     * failing towards enforcement — but here `block` is the one mode that
     * cannot be delivered as configured, so a typo would silently become the
     * mode this integration exists to translate away.
     *
     * @throws IntegrationException
     *   When `global.mode` is not one of the four documented modes.
     */
    public function configuredMode(): FirewallMode
    {
        $global = $this->section('global');
        $mode = $global['mode'] ?? 'block';

        if (!is_string($mode) || ($resolved = FirewallMode::tryFrom($mode)) === null) {
            throw new IntegrationException(sprintf(
                'Firewall mode "%s" is not recognised. Expected one of: %s.',
                is_scalar($mode) ? (string) $mode : get_debug_type($mode),
                implode(', ', array_map(
                    static fn (FirewallMode $case): string => $case->value,
                    FirewallMode::cases()
                ))
            ));
        }

        return $resolved;
    }

    /**
     * Whether the configured mode had to be translated to be deliverable.
     *
     * Reported by `firewall:doctor`, so an operator reading `mode: block` in
     * this file and `exception` in a log line can see that the two agree.
     */
    public function modeWasTranslated(): bool
    {
        return $this->configuredMode() !== $this->effectiveMode();
    }

    /**
     * Is the firewall being put into lockdown by the configured mode?
     *
     * Reported by `firewall:doctor`, because `mode: lockdown` in this config
     * file and `mode: exception` in the logs is a discrepancy an operator
     * should be able to look up rather than puzzle over — and because a
     * deployment refusing every visitor should say so out loud.
     */
    public function isLockdownMode(): bool
    {
        return array_key_exists($this->configuredMode()->value, self::POLICY_MODES);
    }

    /**
     * The array section of the config, in the library's own shape.
     *
     * @return array<string, mixed>
     */
    public function inlineConfig(): array
    {
        $inline = [];

        foreach (self::PASSTHROUGH_SECTIONS as $section) {
            $value = $this->section($section);

            // An empty section is dropped rather than passed as `[]`. The
            // library ships defaults for `challenge` in its own config.yml,
            // and `NestedArray::mergeDeepArray()` would have an empty array
            // from here contribute nothing — but a section present and empty
            // reads, in a dumped effective config, as "configured to nothing"
            // rather than "not configured", and `firewall:doctor` prints that
            // dump.
            if ($value !== []) {
                $inline[$section] = $value;
            }
        }

        // Rebuilt rather than passed through: the mode moves to the overrides
        // and the trusted-proxy posture is filled in from Laravel. Assigning
        // over the key set in the loop above keeps `global` in its original
        // position, which is the order the library's own config.yml uses.
        $globalSection = $this->globalSection();

        if ($globalSection !== []) {
            $inline['global'] = $globalSection;
        } else {
            unset($inline['global']);
        }

        if ($this->loggerHandlers !== []) {
            $inline['logger'] = $this->loggerHandlers;
        }

        return $inline;
    }

    /**
     * The `global:` section, with the trusted-proxy posture filled in.
     *
     * @return array<string, mixed>
     */
    private function globalSection(): array
    {
        $global = $this->section('global');

        // Dropped because it is delivered as an override instead, and leaving
        // it here too would put the same setting in two places that a reader
        // would then have to reconcile.
        unset($global['mode']);

        // NULL means "not configured" for every one of these, and the library
        // distinguishes an absent `behind_proxy` (posture unknown, warn) from
        // an explicit FALSE (asserted: no proxy, stay silent). Passing NULL
        // through would collapse that distinction, so unset the key entirely
        // and let the derived value or the library's own default apply.
        $global = array_filter($global, static fn ($value): bool => $value !== null);

        if (!array_key_exists('behind_proxy', $global) && $this->behindProxy !== null) {
            $global['behind_proxy'] = $this->behindProxy;
        }

        return $global;
    }

    /**
     * Preset names, as configured.
     *
     * @return array<int, string>
     */
    private function presets(): array
    {
        $presets = $this->config['presets'] ?? [];

        if (!is_array($presets)) {
            return [];
        }

        return array_values(array_filter($presets, is_string(...)));
    }

    /**
     * Extra YAML paths, as configured, keeping only ones that exist.
     *
     * A configured-but-absent path is dropped here rather than passed on,
     * because the library's reaction to a missing config input is an error log
     * on every single request — so passing one through would trade a single
     * clear diagnosis for a permanent stream of noise. It is reported once, by
     * `firewall:doctor`, through `missingConfigs()`.
     *
     * @return array<int, string>
     */
    private function extraConfigs(): array
    {
        $configs = $this->config['configs'] ?? [];

        if (!is_array($configs)) {
            return [];
        }

        return array_values(array_filter(
            array_filter($configs, is_string(...)),
            static fn (string $path): bool => is_file($path)
        ));
    }

    /**
     * Paths the operator configured under `configs` that are not readable.
     *
     * Excludes the managed rules file by construction — see the note on the
     * constructor argument for why its absence is not a fault.
     *
     * @return array<int, string>
     */
    public function missingConfigs(): array
    {
        $configs = $this->config['configs'] ?? [];

        if (!is_array($configs)) {
            return [];
        }

        return array_values(array_filter(
            array_filter($configs, is_string(...)),
            static fn (string $path): bool => !is_file($path)
        ));
    }

    /**
     * Every preset the installed library ships.
     *
     * @return array<int, string>
     */
    public function availablePresets(): array
    {
        // `?: []` rather than a separate `=== false` branch: glob() returns
        // FALSE on a read error and an empty array when the directory holds
        // nothing, and there is nothing different to do about the two — either
        // way this installation has no presets to offer.
        $found = glob($this->presetDirectory . '/*.yml') ?: [];

        $names = array_map(
            static fn (string $path): string => basename($path, '.yml'),
            $found
        );
        sort($names);

        return $names;
    }

    /**
     * One section of the config, guaranteed to be an array.
     *
     * @return array<string, mixed>
     */
    private function section(string $name): array
    {
        $value = $this->config[$name] ?? [];

        /** @var array<string, mixed> */
        return is_array($value) ? $value : [];
    }
}
