<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Http;

use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Http\Request;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\Firewall\Laravel\Support\Settings;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * Turn the firewall's three request-time exceptions into Laravel responses.
 *
 * These exist only in `exception` mode, which is the mode this integration
 * always runs the library in when enforcement is wanted. In its default `block`
 * mode the library writes the response itself and calls `exit()`; everything
 * here is the Laravel-rendered equivalent of what it would have written.
 */
final class FirewallResponder
{
    /**
     * Cookie lifetime used when the submission carried no usable TTL.
     *
     * The same fallback the library applies, and it has to be the same: the
     * token's own expiry is set from the posted TTL inside `evaluate()`, so a
     * cookie that outlived the token would leave a visitor holding a pass that
     * is silently refused, and one that expired first would re-challenge
     * somebody whose token was still good.
     */
    private const DEFAULT_TTL = 3600;

    public function __construct(
        private readonly Settings $settings,
        private readonly ViewFactory $views
    ) {
    }

    /**
     * Render a block.
     *
     * The status code is the plugin's, not a fixed 403: rules can specify
     * their own, and a config that says 429 for a rate limit and 403 for an IP
     * ban means it.
     *
     * The message is the library's interpolated banning message. It is passed
     * to the view as data and escaped there — it can contain the client's own
     * IP address and the requested URL through the library's template tokens,
     * which makes it attacker-influenced text.
     */
    public function block(Request $request, FirewallBlockedException $exception): Response
    {
        $status = $exception->getStatusCode();
        $headers = $this->retryAfterHeaders($exception);

        if ($this->wantsJson($request)) {
            return new \Illuminate\Http\JsonResponse([
                'message' => $exception->getMessage(),
            ], $status, $headers + $this->noStoreHeaders());
        }

        return $this->render(
            $this->viewName('block'),
            [
                'message' => $exception->getMessage(),
                'status' => $status,
                'request' => $request,
                // The view can say "try again in a few minutes" rather than
                // "you are blocked", which is the difference between a lockdown
                // and a ban for the customer reading it.
                'retry_after' => $exception instanceof FirewallLockdownException
                    ? $exception->getRetryAfter()
                    : null,
            ],
            $status,
            $headers
        );
    }

    /**
     * Send the visitor somewhere instead of refusing them.
     *
     * `response: redirect`, added in 2.26 — the gentler end of a terminal
     * decision: a status page, a notice, a contact form for somebody who
     * believes they were caught wrongly. A block tells a visitor nothing and
     * leaves them nowhere to go, which is right for a scanner and poor for a
     * false positive.
     *
     * The location is taken from the exception without further sanitising, and
     * that is deliberate rather than an omission. It comes from the rule's
     * `metadata.redirect_to` — operator-authored configuration — and the
     * library never builds it from the request, so it cannot become an open
     * redirect. Re-sanitising it here would be a second implementation of a
     * rule that has to agree with the first, and this one would be wrong: an
     * operator redirecting to another host is doing something legitimate that
     * the challenge flow's same-origin rule would refuse.
     */
    public function redirect(FirewallRedirectException $exception): Response
    {
        return new \Illuminate\Http\RedirectResponse(
            $exception->getLocation(),
            $exception->getStatusCode(),
            // A redirect a rule chose is about this visitor right now, so a
            // shared cache must not serve it to the next one.
            $this->noStoreHeaders()
        );
    }

    /**
     * `Retry-After`, when the refusal is a lockdown rather than a ban.
     *
     * Only lockdown carries one: it is temporary by design, and saying when to
     * come back is the whole difference from a block. A ban has no honest
     * answer to that question.
     *
     * @return array<string, string>
     */
    private function retryAfterHeaders(FirewallBlockedException $exception): array
    {
        if (!$exception instanceof FirewallLockdownException) {
            return [];
        }

        $retryAfter = $exception->getRetryAfter();

        return $retryAfter > 0 ? ['Retry-After' => (string) $retryAfter] : [];
    }

    /**
     * Render the challenge interstitial.
     *
     * Served with 200, matching what the library writes in `block` mode. A 4xx
     * would be more descriptive of "you may not have this yet", and it loses
     * because the interstitial is a working page that the visitor is meant to
     * interact with: search engines, caches and error-tracking middleware all
     * treat a 4xx body as a failure to be discarded or reported, and any of
     * them doing so breaks the round-trip.
     *
     * `Cache-Control: no-store` matters more than the status. The interstitial
     * carries per-visitor signed state; a shared cache holding one would serve
     * the same challenge — and in a stateless provider, the same answer — to
     * everyone behind it.
     */
    public function challenge(Request $request, ChallengeRequiredException $exception): Response
    {
        if ($this->wantsJson($request)) {
            // No interstitial for an API client: it has no browser to solve it
            // in. 403 with a machine-readable body says "you are being
            // challenged and this channel cannot carry one", which a client
             // can act on. Rendering the HTML into a JSON client's response
            // would just be an unreadable body behind a 200.
            return new \Illuminate\Http\JsonResponse([
                'message' => $exception->getMessage(),
                'challenge' => [
                    'path' => $this->settings->text('firewall.challenge.path', '/_firewall/challenge'),
                    'header' => $this->settings->text('firewall.challenge.header_name'),
                ],
            ], Response::HTTP_FORBIDDEN, $this->noStoreHeaders());
        }

        $body = $this->interstitial($request, $exception);

        return $this->render(
            $this->viewName('challenge'),
            ['body' => $body, 'request' => $request],
            Response::HTTP_OK,
            $this->noStoreHeaders()
        );
    }

    /**
     * Issue the pass token and send the visitor where they were going.
     *
     * `getRedirect()` is already sanitized by the library to a same-origin,
     * non-protocol-relative path, so it is safe to redirect to without further
     * checking — and re-sanitizing it here would be a second implementation of
     * a rule that has to agree with the first.
     */
    public function solved(Request $request, ChallengeSolvedException $exception): Response
    {
        $ttl = $this->postedTtl($request);

        if ($this->wantsJson($request)) {
            $response = new \Illuminate\Http\JsonResponse([
                'token' => $exception->getToken(),
                'redirect' => $exception->getRedirect(),
            ], Response::HTTP_OK, $this->noStoreHeaders());
        } else {
            $response = new \Illuminate\Http\RedirectResponse(
                $exception->getRedirect(),
                Response::HTTP_SEE_OTHER,
                $this->noStoreHeaders()
            );
        }

        $cookieName = $this->settings->text('firewall.challenge.cookie_name');

        if ($cookieName !== '') {
            // Attributes mirror what the library sets in `block` mode:
            // HttpOnly so script cannot read the pass, Secure so it is never
            // sent in clear, SameSite=Strict so a cross-site request cannot
            // spend it. Not set through Laravel's cookie jar, which would
            // encrypt the value via EncryptCookies — the firewall verifies
            // this cookie's HMAC itself, before Laravel's middleware has a
            // chance to decrypt it, so an encrypted value would never verify.
            $response->headers->setCookie(Cookie::create($cookieName)
                ->withValue($exception->getToken())
                ->withExpires(time() + $ttl)
                ->withPath('/')
                ->withSecure(true)
                ->withHttpOnly(true)
                ->withSameSite(Cookie::SAMESITE_STRICT));
        }

        return $response;
    }

    /**
     * Render the interstitial body.
     *
     * One call, because since 2.26 the exception carries everything needed:
     * the provider that was actually chosen for the matched rule, and the
     * render context the firewall would have used — including the signed
     * `provider_token` that tells a submission which provider it answers.
     *
     * ## What this replaced, and why it was wrong
     *
     * Before 2.26 `ChallengeRequiredException` carried only a message, so this
     * package rebuilt a provider from `challenge.provider` and rendered with a
     * context it assembled itself. That worked for the common case and was
     * quietly wrong for the one the feature exists for: a rule naming its own
     * `metadata.challenge_provider` got the *default* provider's interstitial,
     * so a visitor was asked to solve the wrong challenge and the pass token
     * they earned did not open the rule that stopped them. Signing the
     * provider token needed a private domain-separation prefix, so there was no
     * way to fix it here — it needed the library change that 2.26 made.
     *
     * `firewall:doctor` used to report per-plugin providers as unsupported.
     * That check is gone, because they are supported now.
     */
    private function interstitial(Request $request, ChallengeRequiredException $exception): string
    {
        try {
            return $exception->renderInterstitial($request);
        } catch (FirewallException) {
            // Thrown when no provider was resolved — which means the firewall
            // could not have rendered it either, and `Firewall::create()`
            // refuses to start in that state. Reaching here means the
            // configuration changed under a running worker. An empty body with
            // the challenge view is a poor page and a truthful one; throwing
            // would turn a challenge into a 500.
            return '';
        }
    }

    /**
     * The TTL the interstitial posted back, clamped the way the library clamps it.
     *
     * Read off the raw parameter bag rather than through `$request->input()`,
     * because `InputBag::get()` throws when the value is an array and this
     * field is attacker-chosen — it arrives on the interstitial's own POST.
     */
    private function postedTtl(Request $request): int
    {
        $raw = $request->request->all()[ChallengeProviderInterface::TTL_FIELD] ?? null;

        if (!is_string($raw) || $raw === '') {
            return self::DEFAULT_TTL;
        }

        $ttl = max(0, (int) $raw);

        return $ttl > 0 ? $ttl : self::DEFAULT_TTL;
    }

    /**
     * Render a view, falling back to plain text if it is missing.
     *
     * A published view that was deleted, or a `firewall.views.*` entry naming
     * a view that does not exist, must not turn a block into a 500 — the whole
     * point of the block is that this request is not to be served, and a 500 is
     * both the wrong status and a page that leaks a stack trace in debug mode.
     *
     * @param array<string, mixed> $data
     * @param array<string, string> $headers
     */
    private function render(string $view, array $data, int $status, array $headers = []): Response
    {
        if (!$this->views->exists($view)) {
            $message = isset($data['message']) && is_string($data['message'])
                ? $data['message']
                : '';

            return new Response($message, $status, ['Content-Type' => 'text/plain; charset=utf-8'] + $headers);
        }

        return new Response(
            $this->views->make($view, $data)->render(),
            $status,
            ['Content-Type' => 'text/html; charset=utf-8'] + $headers
        );
    }

    /**
     * Should this client get JSON instead of a page?
     *
     * `expectsJson()` covers an explicit `Accept: application/json` and
     * Laravel's own AJAX detection. A visitor's browser navigating to a page
     * gets the page; an API client or SPA fetch gets a body it can parse
     * rather than an HTML document it will log as a parse error.
     */
    private function wantsJson(Request $request): bool
    {
        return $request->expectsJson();
    }

    /**
     * @return array<string, string>
     */
    private function noStoreHeaders(): array
    {
        return ['Cache-Control' => 'no-store, private'];
    }

    private function viewName(string $key): string
    {
        return $this->settings->text('firewall.views.' . $key, 'firewall::' . $key);
    }
}
