<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Http\Middleware;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Laravel\Config\TrustedProxies;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\Http\FirewallResponder;
use Kanopi\Firewall\Laravel\Support\Settings;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Evaluate the request against the firewall.
 *
 * `Illuminate\Http\Request` extends `Symfony\Component\HttpFoundation\Request`,
 * so it is handed to `evaluate()` unchanged. There is no PSR-7 bridge and no
 * request rebuilding, which matters for more than performance: a converted
 * request would lose the trusted-proxy state that Symfony holds statically on
 * the request class, and every IP-based rule reads a client address through it.
 *
 * ## Where this has to run
 *
 * After `TrustProxies`, always. `$request->getClientIp()` returns the
 * forwarded address only once `Request::setTrustedProxies()` has been called,
 * which is `TrustProxies`' single job. Run before it and every rule sees the
 * proxy's own address, which makes an IP allowlist match nobody and a per-IP
 * rate limit count the entire internet as one client — while a forged
 * `X-Forwarded-For` bypasses both.
 *
 * The ordering is checked rather than assumed. `TrustProxies` resets the
 * trusted list to empty at the top of its own `handle()`, so "no proxies in
 * force" cannot be distinguished from "TrustProxies has not run" by looking at
 * the list alone — which is exactly the state this middleware would be in if
 * it were registered first. So what the application *declares* is compared
 * against what is *in force*; disagreement is the bug, and it is reported per
 * request because middleware order is a property of the assembled stack that
 * nothing announces at boot.
 *
 * ## Why the firewall is resolved here and not injected
 *
 * Constructor injection would build the firewall when the middleware is
 * resolved, which for global middleware is before `TrustProxies` has run. The
 * library performs its trusted-proxy posture check inside `create()`, so it
 * would be checking a state that is guaranteed empty and warning on every
 * request about a deployment that is configured correctly. Resolving inside
 * `handle()` puts construction after `TrustProxies`, where the answer is true.
 */
class EvaluateFirewall
{
    public function __construct(
        private readonly Container $container,
        private readonly Settings $settings,
        private readonly FirewallResponder $responder,
        private readonly TrustedProxies $trustedProxies,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * Handle an incoming request.
     *
     * @param Closure(Request): Response $next
     *
     * @throws IntegrationException
     *   When the middleware is running before `TrustProxies` and
     *   `firewall.middleware.on_bad_order` is `throw`.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (!$this->enabled()) {
            return $next($request);
        }

        $this->guardOrdering();

        try {
            $this->container->make(Firewall::class)->evaluate($request);
        } catch (FirewallException $decision) {
            return $this->respondTo($request, $next, $decision);
        }

        // `evaluate()` returns TRUE for an allowed request and never returns
        // anything else: a blocked or challenged request leaves through one of
        // the exceptions above. The return value is therefore not worth
        // branching on, and treating a hypothetical FALSE as a block would
        // invent a decision the library did not make.
        return $next($request);
    }

    /**
     * Turn whatever the firewall threw into a response.
     *
     * One catch on the base class with an ordered dispatch, rather than a catch
     * clause per exception. That is deliberate, and 2.26 is why.
     *
     * The library's exception set grows: 2.26 added `FirewallRedirectException`
     * for `response: redirect` and `FirewallLockdownException` for lockdown
     * mode. A stack of `catch` clauses has to be extended for each one, and
     * until it is, a new terminal decision falls through to whatever clause
     * happens to be last — here that was the broken-firewall policy, which
     * would have turned a redirect rule into a 500.
     *
     * It also removes a dependency on something outside this package's control:
     * `evaluate()`'s `@throws` list. In 2.26.0 that list still names only the
     * four exceptions that predate `response: redirect`, so static analysis
     * reading it concludes a `catch (FirewallRedirectException)` is dead code.
     * It is not — the exception is raised at runtime — but a docblock is a
     * courtesy for unchecked exceptions, not a contract, and code that depends
     * on one being exhaustive is depending on the wrong thing.
     *
     * Ordered most-specific first, because `FirewallLockdownException` extends
     * `FirewallBlockedException` and both are handled by `block()`.
     *
     * @param Closure(Request): Response $next
     *
     * @throws FirewallException
     */
    private function respondTo(Request $request, Closure $next, FirewallException $decision): Response
    {
        if ($decision instanceof FirewallBlockedException) {
            // Lockdown arrives here too, by inheritance — upstream made it
            // extend the block exception so a host that already handled blocks
            // keeps working when a site enters lockdown. The responder tells
            // them apart to add `Retry-After`.
            return $this->responder->block($request, $decision);
        }

        if ($decision instanceof FirewallRedirectException) {
            return $this->responder->redirect($decision);
        }

        if ($decision instanceof ChallengeSolvedException) {
            return $this->responder->solved($request, $decision);
        }

        if ($decision instanceof ChallengeRequiredException) {
            return $this->responder->challenge($request, $decision);
        }

        // Everything left is the firewall failing rather than deciding: a
        // ConfigurationException from `create()`, a storage backend that cannot
        // be reached, a challenge rule that matched with no usable provider.
        // None of them is a verdict about this request.
        //
        // A terminal decision this package has not been taught yet also lands
        // here, and fails closed by default. That is the safe direction to be
        // wrong in — and `firewall:doctor` reports the library version, so the
        // upgrade that introduced it is findable.
        return $this->onBrokenFirewall($request, $next, $decision);
    }

    /**
     * Decide what a broken firewall does to traffic.
     *
     * The library propagates these and leaves the policy to the host, on
     * purpose — so this is where the host states it. Both answers are
     * defensible and the wrong one is expensive, which is why it is a setting
     * with no clever default rather than a judgement made here:
     *
     *  - **Fail closed** (`throw`, the default). The exception reaches Laravel's
     *    handler and the request gets a 500. Correct wherever serving
     *    unfiltered traffic is worse than serving an error — authenticated
     *    apps, checkout flows, admin surfaces. A misconfiguration then surfaces
     *    on the first request after a deploy, which is where it is cheapest to
     *    find.
     *  - **Fail open** (`allow`). Logged at `critical` and the request
     *    proceeds unfiltered. Reasonable only for public, low-risk content
     *    where availability outweighs filtering — and only if that `critical`
     *    actually pages somebody, because the site will look entirely healthy
     *    while nothing is being filtered.
     *
     * @param Closure(Request): Response $next
     *
     * @throws FirewallException
     */
    private function onBrokenFirewall(Request $request, Closure $next, FirewallException $broken): Response
    {
        if ($this->settings->text('firewall.on_boot_failure', 'throw') !== 'allow') {
            throw $broken;
        }

        $this->logger->critical('The firewall is not running; this request was NOT filtered', [
            'exception' => $broken::class,
            'error' => $broken->getMessage(),
            'path' => $request->getPathInfo(),
            'policy' => 'allow',
        ]);

        return $next($request);
    }

    /**
     * Refuse or report a stack that leaves every IP rule spoofable.
     *
     * @throws IntegrationException
     */
    private function guardOrdering(): void
    {
        if (!$this->trustedProxies->isSpoofable()) {
            return;
        }

        $message = 'The firewall middleware is running before TrustProxies. Trusted '
            . 'proxies are configured but not yet in force, so every rule will read '
            . 'the proxy address as the client address and any X-Forwarded-For header '
            . 'will be accepted from anyone. Move EvaluateFirewall after TrustProxies '
            . 'in the global middleware stack, or set firewall.middleware.global to '
            . 'true and let this package position it.';

        if ($this->settings->text('firewall.middleware.on_bad_order', 'log') === 'throw') {
            throw new IntegrationException($message);
        }

        // Logged on every affected request, not once. The same reasoning the
        // library applies to an active panic switch: there is no other state
        // anywhere that records this, and a warning that scrolls past once at
        // boot is a warning nobody reads.
        $this->logger->error($message, [
            'declared_proxies' => $this->trustedProxies->declared(),
            'proxies_in_force' => $this->trustedProxies->inForce(),
        ]);
    }

    /**
     * Is the firewall switched on at all?
     *
     * Checked before the container is asked for a `Firewall`, so a disabled
     * firewall costs one config lookup and opens no storage connection, reads
     * no YAML and builds no plugins.
     */
    private function enabled(): bool
    {
        return $this->settings->flag('firewall.enabled', true);
    }
}
