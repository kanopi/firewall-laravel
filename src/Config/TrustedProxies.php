<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Config;

use Illuminate\Http\Middleware\TrustProxies;
use Kanopi\Firewall\Laravel\Support\Settings;
use Symfony\Component\HttpFoundation\Request;

/**
 * Report Laravel's trusted-proxy posture to the firewall.
 *
 * Every firewall rule reads `$request->getClientIp()`. Symfony honours
 * `X-Forwarded-For` only after `Request::setTrustedProxies()` has been called,
 * which under Laravel is `TrustProxies`' job. So a firewall running before
 * `TrustProxies` — or in a deployment that never configured it — reads the
 * proxy's address as the client address for every request, and every IP
 * allowlist and per-IP rate limit becomes bypassable with a header anyone can
 * forge.
 *
 * The library cannot detect whether a proxy is actually in front of the
 * deployment; that is not observable from inside PHP. What it can do is ask the
 * integrator to assert it, via `global.behind_proxy`. This class answers that
 * question from Laravel's own configuration instead of making the operator
 * state the same fact twice — which is the arrangement that actually stays
 * correct, because the two would otherwise drift the first time somebody moved
 * the site behind a CDN and updated only one of them.
 *
 * ## Why the effective list, and not just the configured one
 *
 * `TrustProxies::handle()` opens by calling `setTrustedProxies([], …)` and only
 * then applies the configured list, so after it has run the effective list is
 * either empty (nothing configured) or the real thing. Before it has run the
 * list is also empty. An empty list therefore does not distinguish "no proxies
 * configured" from "TrustProxies has not run yet" — which is precisely the
 * misordering this integration has to detect. So both are read: what the
 * application *declares*, and what is *in force*. Disagreement between them is
 * the ordering bug.
 */
final class TrustedProxies
{
    /**
     * @param string $legacyMiddleware
     *   The application's own `TrustProxies` subclass, which is how Laravel 10
     *   and earlier declared trusted proxies. A parameter rather than a
     *   hardcoded string so an application that named its middleware something
     *   else is still readable — and so both outcomes of reading it, including
     *   a subclass that cannot be constructed, are reachable from a test.
     */
    public function __construct(
        private readonly Settings $settings,
        private readonly string $legacyMiddleware = 'App\\Http\\Middleware\\TrustProxies'
    ) {
    }

    /**
     * What to tell the library about `global.behind_proxy`.
     *
     * @return ?bool
     *   TRUE when a proxy is known to be in front; NULL when it cannot be
     *   determined, which leaves the library warning about an unresolved
     *   posture — the correct outcome, because it is genuinely unresolved.
     *
     *   Never FALSE. Asserting "there is no proxy" is the one answer that
     *   silences the library's warning completely, and nothing observable from
     *   here justifies it: a deployment with no trusted proxies configured is
     *   far more often one that forgot than one that has no proxy. An operator
     *   who does know can still say so with `global.behind_proxy => false`,
     *   which this never overrides.
     */
    public function posture(): ?bool
    {
        return $this->declared() !== null || $this->inForce() !== [] ? true : null;
    }

    /**
     * The trusted proxies currently in force on the Symfony request class.
     *
     * @return array<int, string>
     */
    public function inForce(): array
    {
        return array_values(Request::getTrustedProxies());
    }

    /**
     * The trusted proxies the application declares, by any of Laravel's routes.
     *
     * Three mechanisms, checked in the order Laravel itself resolves them:
     *
     *  1. `TrustProxies::at(...)`, which is what `$middleware->trustProxies()`
     *     in `bootstrap/app.php` calls on Laravel 11 and up. Held in a
     *     protected static, so it is read reflectively — a read-only peek at
     *     Laravel's own documented mechanism, wrapped so that a future rename
     *     degrades to "unknown" rather than to a fatal error.
     *  2. `config('trustedproxy.proxies')`, the published-config form.
     *  3. The `$proxies` property on an application's own `TrustProxies`
     *     subclass, which is how Laravel 10 and earlier configured it.
     *
     * @return array<int, string>|string|null
     *   NULL when the application declares nothing.
     */
    public function declared(): array|string|null
    {
        $always = $this->normalise($this->alwaysTrustProxies());

        if ($always !== null) {
            return $always;
        }

        $configured = $this->normalise($this->settings->raw('trustedproxy.proxies'));

        if ($configured !== null) {
            return $configured;
        }

        return $this->normalise($this->subclassProxies());
    }

    /**
     * Is the firewall about to read a client IP that a header could have set?
     *
     * TRUE means the application declares trusted proxies and none are in
     * force — so `TrustProxies` has not run yet, and this is the middleware
     * ordering bug rather than a configuration gap. Checked per request
     * because that is the only place the answer exists: ordering is a property
     * of the stack as assembled, and nothing reports it at boot.
     */
    public function isSpoofable(): bool
    {
        return $this->declared() !== null && $this->inForce() === [];
    }

    /**
     * `TrustProxies::$alwaysTrustProxies`, unnarrowed.
     *
     * Returns whatever the property holds and leaves narrowing to
     * `normalise()`, so there is one place that decides what counts as a
     * declaration rather than three that have to agree.
     */
    private function alwaysTrustProxies(): mixed
    {
        // One `property_exists()` answers both questions that matter here: it
        // returns FALSE for a class that does not exist as well as for one that
        // no longer declares the property, and the response to either is the
        // same. Reporting "unknown" then leaves the library warning about an
        // unresolved trusted-proxy posture, which is the right way to fail — a
        // wrong TRUE would silence the very warning that exists to catch this.
        //
        // Asked directly rather than by catching ReflectionException, which
        // would be the obvious shape and is worse: the exception is provably
        // unreachable against the installed Laravel, so static analysis flags
        // the catch as dead code.
        return property_exists(TrustProxies::class, 'alwaysTrustProxies')
            ? (new \ReflectionProperty(TrustProxies::class, 'alwaysTrustProxies'))->getValue()
            : null;
    }

    /**
     * The `$proxies` property of an application's own TrustProxies subclass.
     *
     * How Laravel 10 and earlier configured trusted proxies. Instantiating the
     * middleware to read a protected property is not free of risk — a
     * subclass with a constructor requiring dependencies would throw — so
     * anything thrown is treated as "cannot tell", which leaves the library
     * warning about an unresolved posture rather than asserting a wrong one.
     */
    private function subclassProxies(): mixed
    {
        if (!class_exists($this->legacyMiddleware)) {
            return null;
        }

        try {
            // Reflected on the *base* class and read off an instance of the
            // subclass. `$proxies` is declared by
            // Illuminate\Http\Middleware\TrustProxies and inherited, so this
            // reads exactly the same storage as reflecting the subclass would —
            // and it does so against a class name that is known to exist,
            // rather than a string that may or may not name one.
            $property = new \ReflectionProperty(TrustProxies::class, 'proxies');
            $middleware = new $this->legacyMiddleware();

            return $middleware instanceof TrustProxies ? $property->getValue($middleware) : null;
        } catch (\Throwable) {
            // Constructing the middleware is the part that can fail: a subclass
            // whose constructor takes dependencies throws here. Treated as
            // "cannot tell" for the same reason as above — a firewall that
            // guesses TRUE would stop warning about the one thing it cannot
            // verify.
            return null;
        }
    }

    /**
     * Reduce a declaration to a list of strings, a string, or "not declared".
     *
     * An empty array and an empty string both mean nothing was declared, which
     * is why they collapse to NULL: `TrustProxies` treats them the same way,
     * and a caller distinguishing them would be reading a difference that has
     * no effect on what gets trusted.
     *
     * @return array<int, string>|string|null
     */
    private function normalise(mixed $value): array|string|null
    {
        if (is_string($value)) {
            return $value === '' ? null : $value;
        }

        if (!is_array($value)) {
            return null;
        }

        $proxies = [];

        foreach ($value as $proxy) {
            if (is_string($proxy) && $proxy !== '') {
                $proxies[] = $proxy;
            }
        }

        return $proxies === [] ? null : $proxies;
    }
}
