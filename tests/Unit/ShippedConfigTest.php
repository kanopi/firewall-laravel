<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Structural guards on the config file this package publishes.
 *
 * These assert properties of the *source*, which is unusual and is the point:
 * the bug that prompted them was invisible to every behavioural test. The
 * shipped default read `config('logging.default')`, Laravel loads config files
 * alphabetically so `firewall.php` is evaluated before `logging.php`, and the
 * call returned NULL. Out of the box the firewall logged nowhere — every block,
 * every rule that failed to build, every degraded backend discarded.
 *
 * Nothing in the PHPUnit suites could see it. Testbench sets the channel
 * explicitly, and the value being NULL is a perfectly valid configuration that
 * `LogHandlers` handles correctly. It took installing the package into a real
 * application to notice, which is exactly the kind of gap a structural
 * assertion can close cheaply and permanently.
 */
final class ShippedConfigTest extends TestCase
{
    /**
     * A config file must not call `config()`.
     *
     * Laravel evaluates config files in alphabetical order, so what any such
     * call returns depends on the callee's filename — `app.*` would resolve and
     * `logging.*` would not, from a file called `firewall.php`. The failure is
     * silent and the value it produces is indistinguishable from "the operator
     * set this to null".
     */
    #[Test]
    public function the_shipped_config_never_calls_config(): void
    {
        $this->assertDoesNotMatchRegularExpression(
            '/(?<![\w:>$])config\s*\(/',
            $this->strippedSource(),
            'config/firewall.php calls config(), which returns NULL for any file '
            . 'Laravel loads after firewall.php. Use env() instead.'
        );
    }

    /**
     * The log channel has to resolve to something on a default installation.
     *
     * The specific regression: a firewall that enforces perfectly and reports
     * nothing.
     */
    #[Test]
    public function the_default_log_channel_falls_back_to_a_real_channel(): void
    {
        $this->assertMatchesRegularExpression(
            "/'channel' => env\('FIREWALL_LOG_CHANNEL', env\('LOG_CHANNEL', 'stack'\)\)/",
            $this->source()
        );
    }

    /**
     * The published file parses.
     *
     * Not `require`d — the file calls `storage_path()` and `base_path()`, which
     * need a booted application, and the sections it produces are asserted in
     * the feature suite where one exists. This checks the thing a unit test
     * can: that the source is valid PHP, so a broken edit fails here rather
     * than as an unrelated-looking error three suites later.
     */
    #[Test]
    public function the_shipped_config_parses(): void
    {
        $check = shell_exec(sprintf(
            '%s -l %s 2>&1',
            escapeshellarg(PHP_BINARY),
            escapeshellarg($this->path())
        ));

        $this->assertIsString($check);
        $this->assertStringContainsString('No syntax errors', $check);
    }

    /**
     * Every helper the file calls has to work while config is being loaded.
     *
     * The allowlist is the point: each of these is a global function that is
     * available at config-load time, and a config file reaching for anything
     * further afield is exactly how the `config()` bug arrived. Adding a fourth
     * should be a deliberate act with this test updated alongside it.
     */
    #[Test]
    public function the_shipped_config_uses_only_the_expected_helpers(): void
    {
        preg_match_all('/(?<![\w:>$])([a-z_]+)\s*\(/', $this->strippedSource(), $matches);

        // `declare` is a language construct that happens to look like a call,
        // and `array` would be too if the file used the long form.
        $constructs = ['declare', 'array', 'isset', 'unset', 'empty', 'list'];
        $allowed = ['env', 'storage_path', 'base_path'];

        $called = array_values(array_diff(
            array_unique($matches[1]),
            $constructs,
            $allowed
        ));

        $this->assertSame(
            [],
            $called,
            'config/firewall.php calls a helper beyond ' . implode(', ', $allowed) . '.'
        );
    }

    /**
     * The file's source with comments removed.
     *
     * The comments explain why `config()` must not be called, so a naive search
     * of the raw source matches the explanation and fails the test it is
     * explaining.
     */
    private function strippedSource(): string
    {
        $stripped = '';

        foreach (token_get_all($this->source()) as $token) {
            if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            $stripped .= is_array($token) ? $token[1] : $token;
        }

        return $stripped;
    }

    private function source(): string
    {
        return (string) file_get_contents($this->path());
    }

    private function path(): string
    {
        return dirname(__DIR__, 2) . '/config/firewall.php';
    }
}
