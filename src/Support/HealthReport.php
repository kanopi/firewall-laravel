<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Support;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\FirewallMode;

/**
 * A health snapshot of the running firewall, shaped for a status endpoint.
 *
 * Reports the four things a firewall can be wrong about in a way that looks
 * identical to working:
 *
 *  1. **A rule that is not running.** A plugin whose constructor throws — a
 *     Redis host not answering, a storage path that lost its permissions — is
 *     logged and skipped, and the request is evaluated by the rules that did
 *     build. For an `allow` rule that is merely annoying; for a `block` rule it
 *     is a fail-open, and a firewall running three rules short looks exactly
 *     like a firewall running correctly.
 *  2. **A rule that is running blind.** The Redis backends catch a connection
 *     failure, log it, and answer every read as though nothing were stored. The
 *     plugin constructs, so (1) reports nothing, while a rate limit rule counts
 *     nothing and lets everything through.
 *  3. **A panic file holding the switch down.** The realistic failure is not
 *     somebody flipping it during an incident; it is nobody noticing three
 *     weeks later that it is still on.
 *  4. **A mode that is not the configured one**, which is (3) seen from the
 *     other side, plus this integration's own translation of `block` to
 *     `exception`.
 *
 * ## This is not for the request path
 *
 * `getFailedRules()` and `getDegradedBackends()` **build every rule** to answer,
 * because rules are constructed lazily and a firewall that has evaluated
 * nothing has nothing that could have failed yet. Building a rule is what opens
 * its storage connection, which is what makes the answer worth having — and
 * which is why this belongs behind a status route or in `firewall:doctor`, not
 * in a middleware. Anything it builds is reused by a later `evaluate()` in the
 * same process, so under Octane the cost is paid once per worker; under PHP-FPM
 * it is paid on the request that asked.
 */
final class HealthReport
{
    public function __construct(private readonly Firewall $firewall)
    {
    }

    /**
     * The whole snapshot.
     *
     * @return array{
     *     healthy: bool,
     *     mode: string,
     *     configured_mode: string,
     *     mode_overridden: bool,
     *     panic_switch: array{active: bool, mode: string|null, path: string|null, problem: string|null},
     *     failed_rules: array<int, array{bucket: string, plugin: string, error: string}>,
     *     degraded_backends: array<int, array<string, string>>,
     *     errors: array<int, string>,
     *     warnings: array<int, string>
     * }
     */
    public function toArray(): array
    {
        $failedRules = $this->firewall->getFailedRules();
        $degraded = $this->firewall->getDegradedBackends();
        $panic = $this->panicSwitch();

        return [
            // A degraded backend is deliberately not unhealthy. It is a
            // warning: the firewall is enforcing every rule that does not
            // depend on that store, which is more than nothing and is the
            // behaviour the library chose on purpose. A failed rule is
            // unhealthy, because that rule is not running at all.
            'healthy' => $failedRules === [],
            'mode' => $this->firewall->getMode()->value,
            'configured_mode' => $this->firewall->getConfiguredMode()->value,
            'mode_overridden' => $this->firewall->getMode() !== $this->firewall->getConfiguredMode(),
            'panic_switch' => $panic,
            'failed_rules' => $failedRules,
            'degraded_backends' => $degraded,
            'errors' => $this->errors($failedRules, $panic),
            'warnings' => $this->warnings($degraded, $panic),
        ];
    }

    /**
     * The panic switch, with the enum flattened for JSON.
     *
     * @return array{active: bool, mode: string|null, path: string|null, problem: string|null}
     */
    private function panicSwitch(): array
    {
        $panic = $this->firewall->getPanicSwitch();
        $mode = $panic['mode'];

        return [
            'active' => $panic['active'],
            'mode' => $mode instanceof FirewallMode ? $mode->value : null,
            'path' => $panic['path'],
            'problem' => $panic['problem'],
        ];
    }

    /**
     * Human-readable errors — things configured that are not happening.
     *
     * @param array<int, array{bucket: string, plugin: string, error: string}> $failedRules
     * @param array{active: bool, mode: string|null, path: string|null, problem: string|null} $panic
     *
     * @return array<int, string>
     */
    private function errors(array $failedRules, array $panic): array
    {
        $errors = [];

        foreach ($failedRules as $rule) {
            $errors[] = sprintf(
                'Firewall %s rule %s is not running: %s',
                $rule['bucket'],
                $rule['plugin'],
                $rule['error']
            );
        }

        // A panic file that exists and did nothing is an error rather than a
        // warning: somebody reached for the switch and it did not take, and
        // they are watching the site rather than the logs to find that out.
        if ($panic['problem'] !== null) {
            $errors[] = sprintf(
                'Firewall panic file at %s is present but was not applied: %s',
                $panic['path'] ?? '(unknown path)',
                $panic['problem']
            );
        }

        return $errors;
    }

    /**
     * Human-readable warnings — things running with less than they need.
     *
     * @param array<int, array<string, string>> $degraded
     * @param array{active: bool, mode: string|null, path: string|null, problem: string|null} $panic
     *
     * @return array<int, string>
     */
    private function warnings(array $degraded, array $panic): array
    {
        $warnings = [];

        foreach ($degraded as $backend) {
            // Indexed without `??` fallbacks. `DegradedBackends::record()` is
            // the only way an entry gets in and it always writes all three
            // keys, so a fallback would be unreachable code standing in for a
            // field rename — which would be a library upgrade this package has
            // to be updated for anyway, and would fail loudly here rather than
            // producing a warning reading "The firewall  is running without
            // its store:  ()".
            $warnings[] = sprintf(
                'The firewall %s is running without its store: %s (%s)',
                $backend['component'],
                $backend['error'],
                $backend['backend']
            );
        }

        if ($panic['active']) {
            $warnings[] = sprintf(
                'Firewall panic switch is ACTIVE: mode is %s instead of the configured %s. Remove %s to restore.',
                $this->firewall->getMode()->value,
                $this->firewall->getConfiguredMode()->value,
                $panic['path'] ?? '(unknown path)'
            );
        }

        return $warnings;
    }
}
