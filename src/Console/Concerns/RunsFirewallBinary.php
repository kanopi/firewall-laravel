<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Console\Concerns;

use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\FirewallFactory;
use Kanopi\Firewall\Laravel\Support\PackagePaths;
use Kanopi\Firewall\Laravel\Support\Settings;
use Symfony\Component\Process\Process;
use Symfony\Component\Yaml\Yaml;

/**
 * Run one of kanopi/firewall's `bin/` scripts against Laravel's configuration.
 *
 * ## Why a subprocess, and not a reimplementation
 *
 * Every one of those scripts is built on classes this package could call
 * directly — `Doctor`, `BlockList`, `ManagedRules`, `SchemaMigrator`,
 * `SourceManager`. Calling them would give native Artisan output, no process
 * overhead, and `--json` we controlled.
 *
 * It lost on maintenance and on truthfulness. The scripts are roughly 2,500
 * lines of argument handling, exit-code policy and output formatting, and the
 * library treats them as its operational surface — `firewall-check` exists
 * precisely because assembling the same call by hand has three edges that fail
 * quietly, and it handles all three. A parallel Laravel implementation would
 * have to re-derive those edges and would drift from them on every release,
 * silently, in the direction of being wrong. Running the real script means
 * `php artisan firewall:check` and `bin/firewall-check` cannot disagree, and
 * that an upstream fix arrives with the upstream release.
 *
 * The cost is one PHP process per invocation. These are operator commands run
 * from a terminal or a deploy step, so that is not a cost anybody notices.
 *
 * ## Why the configuration is written out as YAML
 *
 * The scripts read YAML config files; Laravel's config is a PHP array that can
 * call `env()` and `storage_path()`. So each command translates the Laravel
 * config exactly as the middleware does — same presets, same merge order, same
 * derived values — and writes the result to a temporary file for the script to
 * read. The dump is also the most direct answer to "what did my PHP config
 * actually become", which is why `--keep-config` exists.
 */
trait RunsFirewallBinary
{
    /**
     * Environment variable carrying the challenge secret to the subprocess.
     *
     * The secret is passed through the process environment and referenced from
     * the dumped YAML as `%env(...)%` rather than written into the file. A
     * temp file is deleted in a `finally`, which covers an ordinary failure but
     * not a `kill -9` or a full disk — and a signing secret left behind in
     * `/tmp` is a durable problem, whereas process environment dies with the
     * process. Both are readable by the same user and by root, so this is a
     * narrowing of exposure rather than a removal of it.
     */
    private const SECRET_ENV = 'KANOPI_FIREWALL_LARAVEL_CLI_SECRET';

    /**
     * Run a bin/ script with the effective configuration.
     *
     * @param string $script
     *   Script basename, e.g. `firewall-doctor`.
     * @param array<int, string> $arguments
     *   Arguments after the config path(s).
     * @param bool $configAsOption
     *   TRUE passes the config as `--config=PATH`, which `firewall-check`
     *   requires; FALSE passes it positionally, which every other script
     *   takes. The two conventions differ upstream, so this is not something
     *   that can be normalised away from here.
     * @param bool $withConfig
     *   FALSE runs the script with no configuration at all, for
     *   `firewall-init`, which writes a config rather than reading one.
     *
     * @return int
     *   The script's exit code, returned unchanged so a deploy step can gate
     *   on it exactly as it would gate on the script.
     */
    protected function runFirewallBinary(
        string $script,
        array $arguments = [],
        bool $configAsOption = false,
        bool $withConfig = true
    ): int {
        return $this->runFirewallBinaryWithLeadingArguments(
            $script,
            [],
            $arguments,
            $configAsOption,
            $withConfig
        );
    }

    /**
     * Run a bin/ script with arguments that must precede the config path.
     *
     * `firewall-rule` takes its action first — `bin/firewall-rule add
     * config.yml --rule=…` — so the config cannot simply follow the script
     * name as it does everywhere else.
     *
     * @param array<int, string> $leading
     *   Arguments to place before the config path.
     * @param array<int, string> $arguments
     *   Arguments to place after it.
     *
     * @see runFirewallBinary() for the parameter documentation.
     */
    protected function runFirewallBinaryWithLeadingArguments(
        string $script,
        array $leading = [],
        array $arguments = [],
        bool $configAsOption = false,
        bool $withConfig = true
    ): int {
        $binary = $this->binaryPath($script);

        if (!is_file($binary)) {
            $this->components->error(sprintf(
                'The firewall script "%s" was not found at %s. Set firewall.artisan.bin_path '
                . 'if kanopi/firewall is installed somewhere unusual.',
                $script,
                $binary
            ));

            return self::EXIT_CONFIG_UNREADABLE;
        }

        $configPath = null;

        try {
            $command = [PHP_BINARY, $binary, ...$leading];
            $environment = [];

            if ($withConfig) {
                [$configPath, $secret] = $this->writeEffectiveConfig();

                $command[] = $configAsOption ? '--config=' . $configPath : $configPath;

                if ($secret !== null) {
                    $environment[self::SECRET_ENV] = $secret;
                }
            }

            $process = new Process([...$command, ...$arguments], $this->laravel->basePath(), $environment);

            // No timeout. `firewall-sources` fetches from remote servers and
            // `firewall-migrate` runs DDL against a live database; Symfony's
            // 60-second default would kill either mid-way, and a half-applied
            // migration reported as a timeout is worse than a slow command.
            $process->setTimeout(null);

            // Streamed rather than buffered, so `firewall-doctor` on a slow
            // database prints each finding as it is reached instead of
            // appearing to hang and then producing everything at once.
            $exitCode = $process->run(function (string $type, string $buffer): void {
                $type === Process::ERR
                    ? $this->output->write('<comment>' . $buffer . '</>')
                    : $this->output->write($buffer);
            });

            if ($configPath !== null && $this->shouldKeepConfig()) {
                $this->components->info(sprintf('Effective configuration written to %s', $configPath));
                $configPath = null;
            }

            return $exitCode;
        } finally {
            if ($configPath !== null && is_file($configPath)) {
                @unlink($configPath);
            }
        }
    }

    /**
     * Write the effective configuration to a temporary YAML file.
     *
     * @return array{0: string, 1: ?string}
     *   The path written, and the challenge secret to pass by environment (or
     *   NULL when there is none to pass).
     *
     * @throws IntegrationException
     *   When the file cannot be created, or the configuration cannot be
     *   translated. Refusing is right: a command that ran against a config it
     *   could not fully write would answer a different question from the one
     *   asked, and `firewall-check` answering the wrong question confidently is
     *   worse than it failing.
     */
    protected function writeEffectiveConfig(): array
    {
        $factory = $this->laravel->make(FirewallFactory::class);
        $translator = $factory->translator();

        // The same directory creation the middleware performs, for the same
        // reason and against the same storage. Repeated here rather than
        // hidden inside `translator()` because the two entry points are
        // genuinely separate: the scripts run in their own process and never
        // resolve a `Firewall` through the container, so the middleware's call
        // cannot cover them — and a `firewall:doctor` that reports a missing
        // directory the first request would have created is reporting a
        // problem that does not exist.
        $factory->storageDirectories()->ensureFor(
            $this->settings()->section('firewall.storage')
        );

        $config = [];

        // The presets and extra YAML files come through as `configs:` includes
        // rather than being merged here. The library resolves that key itself,
        // in the same order and with the same relative-path rules it uses at
        // runtime — so the script sees the identical merge the middleware
        // would, rather than this package's approximation of it.
        $includes = [];

        foreach ($translator->configs() as $input) {
            if (is_string($input)) {
                $includes[] = $input;

                continue;
            }

            $config = $input;
        }

        if ($includes !== []) {
            $config = ['configs' => $includes] + $config;
        }

        $config['global'] = array_merge(
            is_array($config['global'] ?? null) ? $config['global'] : [],
            ['mode' => $translator->effectiveMode()->value]
        );

        [$config, $secret] = $this->externaliseSecret($config);

        $config['logger'] = $this->dumpableLogHandlers();

        if ($config['logger'] === []) {
            unset($config['logger']);
        }

        return [$this->writeYaml(Yaml::dump($config, 8, 2)), $secret];
    }

    /**
     * Write YAML to a fresh file in the configured temporary directory.
     *
     * Built by hand rather than with `tempnam()`, for two reasons that both
     * come down to being able to say what happened. `tempnam()` silently falls
     * back to the system temp directory when the one it is given is unusable,
     * so a deployment with a read-only `/tmp` — or one that deliberately
     * pointed this at `storage/` — would get a file somewhere other than where
     * it asked, or an unexplained FALSE. And a name it chooses has no
     * extension, which matters for `--keep-config`, whose whole purpose is
     * handing an operator a file to open.
     *
     * Opened with mode `x`, so an existing file is never truncated: the name
     * carries 128 bits of randomness, so a collision means something is
     * writing files into this directory to be read, and overwriting it is the
     * one response that would help them.
     *
     * The 0600 is applied after the create rather than through a umask, which
     * leaves a window in which the file exists with default permissions. That
     * window is acceptable here precisely because of the design choice above
     * it: the challenge secret travels in the process environment, not in this
     * file, so what is briefly readable is a rule set the operator could read
     * anyway.
     *
     * @throws IntegrationException
     *   When the directory does not exist or the file cannot be written.
     *   Refusing beats continuing: a command that ran against a config it
     *   could not fully write would answer a different question from the one
     *   asked, and `firewall:check` answering the wrong question confidently is
     *   worse than `firewall:check` failing.
     */
    private function writeYaml(string $yaml): string
    {
        $directory = rtrim($this->settings()->text(
            'firewall.artisan.temp_path',
            sys_get_temp_dir()
        ), '/');

        $path = sprintf('%s/firewall-effective-%s.yml', $directory, bin2hex(random_bytes(8)));

        $handle = is_dir($directory) ? @fopen($path, 'x') : false;

        if ($handle === false) {
            throw new IntegrationException(sprintf(
                'Unable to write the effective firewall configuration to %s. Set '
                . 'firewall.artisan.temp_path to a writable directory.',
                $directory
            ));
        }

        @chmod($path, 0600);
        fwrite($handle, $yaml);
        fclose($handle);

        return $path;
    }

    /**
     * Replace the challenge secret with an env reference.
     *
     * @param array<string, mixed> $config
     *
     * @return array{0: array<string, mixed>, 1: ?string}
     */
    private function externaliseSecret(array $config): array
    {
        $challenge = $config['challenge'] ?? null;
        $secret = is_array($challenge) ? ($challenge['secret'] ?? null) : null;

        if (!is_array($challenge) || !is_string($secret) || $secret === '') {
            return [$config, null];
        }

        $challenge['secret'] = '%env(' . self::SECRET_ENV . ')%';
        $config['challenge'] = $challenge;

        return [$config, $secret];
    }

    /**
     * Log handler definitions that can survive a YAML dump.
     *
     * The runtime configuration borrows live Monolog handler *instances* off a
     * Laravel log channel, which `LoggingFactory::create()` accepts and YAML
     * cannot represent. So only the declarative handlers from
     * `firewall.logger.handlers` are dumped.
     *
     * The consequence is worth stating because one command depends on it:
     * `firewall:log-prune` prunes the library's own `DatabaseHandler` rows, and
     * it can only see a handler that is declared in config. A deployment
     * logging through a borrowed Laravel channel has no `DatabaseHandler` to
     * prune, and log-prune will correctly report that there is nothing to do.
     *
     * @return array<int, array<string, mixed>>
     */
    private function dumpableLogHandlers(): array
    {
        return array_values(array_filter(
            $this->settings()->listOfSections('firewall.logger.handlers'),
            static fn (array $handler): bool => is_string($handler['class'] ?? null)
        ));
    }

    /**
     * The typed reader over Laravel's config repository.
     */
    private function settings(): Settings
    {
        return Settings::for($this->laravel);
    }

    /**
     * Absolute path to a bin/ script.
     */
    private function binaryPath(string $script): string
    {
        $configured = $this->settings()->text('firewall.artisan.bin_path');

        $directory = $configured !== '' ? rtrim($configured, '/') : PackagePaths::bin();

        return $directory . '/' . $script;
    }

    /**
     * Should the dumped configuration be left on disk?
     */
    private function shouldKeepConfig(): bool
    {
        if ($this->hasOption('keep-config') && (bool) $this->option('keep-config')) {
            return true;
        }

        return $this->settings()->flag('firewall.artisan.keep_effective_config', false);
    }

    /**
     * Build the option list to forward, keeping only the flags that were given.
     *
     * Symfony Console reports every declared option, set or not, so forwarding
     * them blindly would hand the script `--json` when the operator did not ask
     * for it and change its output format.
     *
     * @param array<int, string> $flags
     *   Boolean option names to forward when true.
     * @param array<int, string> $values
     *   Value option names to forward when non-empty.
     * @param array<int, string> $repeatable
     *   Array option names to forward once per value.
     *
     * @return array<int, string>
     */
    protected function forwardOptions(array $flags = [], array $values = [], array $repeatable = []): array
    {
        $arguments = [];

        foreach ($flags as $flag) {
            if ($this->hasOption($flag) && (bool) $this->option($flag)) {
                $arguments[] = '--' . $flag;
            }
        }

        foreach ($values as $name) {
            $value = $this->hasOption($name) ? $this->option($name) : null;

            if (is_string($value) && $value !== '') {
                $arguments[] = '--' . $name . '=' . $value;
            }
        }

        foreach ($repeatable as $name) {
            $items = $this->hasOption($name) ? $this->option($name) : null;

            // Narrowed in the `foreach` subject rather than by an early
            // `continue`: an option declared with `*` always yields an array,
            // so a separate guard would be a branch nothing can reach.
            foreach (is_array($items) ? $items : [] as $item) {
                if (is_string($item) && $item !== '') {
                    $arguments[] = '--' . $name . '=' . $item;
                }
            }
        }

        return $arguments;
    }
}
