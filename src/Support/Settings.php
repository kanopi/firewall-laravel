<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Support;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;

/**
 * Read `config/firewall.php` with the types the rest of the package expects.
 *
 * `Repository::get()` returns `mixed`, correctly — a config file is a PHP array
 * an operator edits, so any key can hold anything. Every read therefore needs a
 * type check, and doing that inline at each of the sixty-odd call sites in this
 * package produced two problems: the checks were the majority of several
 * methods, and the ones that were written as a bare `(string)` cast were not
 * checks at all. Casting `mixed` to `string` turns an array into the literal
 * `"Array"` with a warning, and NULL into `""` — so `challenge.secret`
 * accidentally set to `[]` would have read as an empty secret, and an empty
 * secret is the one value that must fail loudly.
 *
 * So the checks live here once, each returning a concrete type, and each
 * treating a value of the wrong shape as absent rather than coercing it. That
 * is the safe direction: an absent value falls back to a documented default,
 * where a coerced one becomes a plausible-looking wrong answer.
 */
final class Settings
{
    public function __construct(private readonly ConfigRepository $config)
    {
    }

    /**
     * Build from a container.
     *
     * @throws IntegrationException
     *   When `config` is not a config repository, which means the container
     *   was never bootstrapped as a Laravel application. Refusing beats
     *   returning empty settings, which would present a firewall configured
     *   with nothing as a firewall configured to allow everything.
     */
    public static function for(Container $container): self
    {
        $config = $container->get('config');

        if (!$config instanceof ConfigRepository) {
            throw new IntegrationException(sprintf(
                'The container\'s "config" binding is %s, not a %s. The firewall needs a '
                . 'bootstrapped Laravel application to read its configuration from.',
                get_debug_type($config),
                ConfigRepository::class
            ));
        }

        return new self($config);
    }

    /**
     * A string value, or the default when absent or of another type.
     */
    public function text(string $key, string $default = ''): string
    {
        $value = $this->config->get($key);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    /**
     * A boolean value, or the default when absent.
     *
     * Anything present is interpreted as a boolean, because `'false'` from an
     * unparsed env var and `0` from a hand-edited file both plainly mean false
     * — and `env()` already resolves the literal strings `'true'` and
     * `'false'`. Only a genuinely absent value takes the default.
     */
    public function flag(string $key, bool $default = false): bool
    {
        $value = $this->config->get($key);

        return $value === null ? $default : (bool) $value;
    }

    /**
     * A nullable boolean: TRUE, FALSE, or NULL for "not configured".
     *
     * Distinct from `flag()` because `global.behind_proxy` has three states and
     * the library treats them differently: an explicit FALSE asserts that
     * nothing sits in front of the deployment and silences its warning, while
     * an absent value leaves the posture unresolved and keeps warning. Passing
     * a default through `flag()` would collapse the two.
     */
    public function tristate(string $key): ?bool
    {
        $value = $this->config->get($key);

        return $value === null ? null : (bool) $value;
    }

    /**
     * An integer value, or the default when absent or non-numeric.
     */
    public function number(string $key, int $default = 0): int
    {
        $value = $this->config->get($key);

        return is_int($value) || (is_string($value) && is_numeric($value)) ? (int) $value : $default;
    }

    /**
     * A config section as a string-keyed array.
     *
     * Rebuilt key by key rather than returned as-is, so the declared return
     * type is something this method actually guarantees: a config array can
     * hold integer keys, and casting them here is a normalisation the callers
     * would otherwise each have to repeat.
     *
     * @return array<string, mixed>
     */
    public function section(string $key): array
    {
        $value = $this->config->get($key);

        if (!is_array($value)) {
            return [];
        }

        $section = [];

        foreach ($value as $name => $item) {
            $section[(string) $name] = $item;
        }

        return $section;
    }

    /**
     * A list of strings, dropping anything that is not one.
     *
     * @return array<int, string>
     */
    public function strings(string $key): array
    {
        $value = $this->config->get($key);

        if (!is_array($value)) {
            return [];
        }

        $strings = [];

        foreach ($value as $item) {
            if (is_string($item) && $item !== '') {
                $strings[] = $item;
            }
        }

        return $strings;
    }

    /**
     * A list of string-keyed arrays, dropping entries that are not arrays.
     *
     * The shape of `firewall.plugins` and `firewall.logger.handlers`: a YAML-ish
     * list of maps. A non-array entry is a hand-editing mistake, and dropping
     * it matches what the library does with the same input.
     *
     * @return array<int, array<string, mixed>>
     */
    public function listOfSections(string $key): array
    {
        $value = $this->config->get($key);

        if (!is_array($value)) {
            return [];
        }

        $list = [];

        foreach ($value as $entry) {
            if (!is_array($entry)) {
                continue;
            }

            $section = [];

            foreach ($entry as $name => $item) {
                $section[(string) $name] = $item;
            }

            $list[] = $section;
        }

        return $list;
    }

    /**
     * The value untouched, for a caller that does its own narrowing.
     */
    public function raw(string $key): mixed
    {
        return $this->config->get($key);
    }

    /**
     * The underlying repository, for the few places that need to pass it on.
     */
    public function repository(): ConfigRepository
    {
        return $this->config;
    }
}
