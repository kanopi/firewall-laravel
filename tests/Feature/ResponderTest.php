<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Illuminate\Http\Request;
use Kanopi\Firewall\Challenge\ChallengeProviderRegistry;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Laravel\Http\FirewallResponder;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Turning the firewall's exceptions into responses.
 */
final class ResponderTest extends TestCase
{
    #[Test]
    public function it_renders_a_block_through_the_published_view(): void
    {
        $response = $this->responder()->block(
            Request::create('/'),
            new FirewallBlockedException('Access denied for 203.0.113.9', 403)
        );

        $this->assertSame(403, $response->getStatusCode());
        $this->assertStringContainsString('Request blocked', (string) $response->getContent());
        $this->assertStringContainsString('Access denied for 203.0.113.9', (string) $response->getContent());
    }

    /**
     * The banning message is escaped, because it can contain visitor input.
     *
     * The library interpolates template tokens into it — the client's own IP
     * and the URL they asked for — so a request for
     * `/<script>alert(1)</script>` reaches this view as text an attacker chose.
     */
    #[Test]
    public function the_banning_message_is_escaped(): void
    {
        $response = $this->responder()->block(
            Request::create('/'),
            new FirewallBlockedException('Blocked: <script>alert(1)</script>', 403)
        );

        $body = (string) $response->getContent();

        $this->assertStringNotContainsString('<script>alert(1)</script>', $body);
        $this->assertStringContainsString('&lt;script&gt;', $body);
    }

    /**
     * A missing view must not turn a block into a 500.
     *
     * A 500 is both the wrong status — the request was refused, not broken —
     * and a page that leaks a stack trace while `APP_DEBUG` is on.
     */
    #[Test]
    public function a_missing_block_view_falls_back_to_plain_text(): void
    {
        config(['firewall.views.block' => 'no-such-view']);

        $response = $this->responder()->block(
            Request::create('/'),
            new FirewallBlockedException('Refused', 403)
        );

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('Refused', $response->getContent());
        $this->assertStringStartsWith('text/plain', (string) $response->headers->get('Content-Type'));
    }

    #[Test]
    public function a_missing_challenge_view_falls_back_without_a_message(): void
    {
        config(['firewall.views.challenge' => 'no-such-view']);
        $this->configureChallenge();

        $response = $this->responder()->challenge(
            Request::create('/gated'),
            $this->challengeException()
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('', $response->getContent());
    }

    #[Test]
    public function it_renders_the_interstitial_from_the_configured_provider(): void
    {
        $this->configureChallenge();

        $response = $this->responder()->challenge(
            Request::create('/gated'),
            $this->challengeException()
        );

        $body = (string) $response->getContent();

        $this->assertStringContainsString('action="/_firewall/challenge"', $body);
        $this->assertStringContainsString('value="/gated"', $body);
        // The signed provider token the firewall chose, carried through rather
        // than reassembled — the whole point of the 2.26 exception change.
        $this->assertStringContainsString('math.signed-by-the-firewall', $body);
    }

    /**
     * A challenge with no usable secret renders an empty body, not a 500.
     *
     * `Firewall::create()` refuses to start in that state, so reaching here
     * means the configuration changed under a running worker. An empty page is
     * a poor answer and a truthful one; throwing would turn a challenge into a
     * server error.
     */
    /**
     * An exception carrying no provider renders an empty body, not a 500.
     *
     * The library raises one in that shape only when it could not resolve a
     * provider — a state `Firewall::create()` refuses to start in, so reaching
     * it means the configuration changed under a running worker.
     * `renderInterstitial()` throws a ConfigurationException; swallowing it is
     * deliberate. An empty page is a poor answer and a truthful one, and
     * turning a challenge into a server error is worse.
     */
    #[Test]
    public function a_challenge_carrying_no_provider_renders_an_empty_body(): void
    {
        $response = $this->responder()->challenge(
            Request::create('/gated'),
            new ChallengeRequiredException('Challenge required')
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('', trim((string) $response->getContent()));
    }

    /**
     * A rule's own provider is honoured, not the configured default.
     *
     * This is what 2.26 fixed and what this package could not do before it. The
     * exception now names the provider the matched rule asked for, so a rule
     * using `metadata.challenge_provider` gets *its* interstitial — where
     * previously every challenge rendered `challenge.provider` regardless, and
     * the pass token a visitor earned did not open the rule that stopped them.
     */
    #[Test]
    public function a_per_rule_provider_is_rendered_rather_than_the_default(): void
    {
        config([
            'firewall.challenge.secret' => 'long-enough-secret-for-hmac-signing-here',
            // The default is deliberately something else, so rendering the
            // default would be visible rather than coincidentally identical.
            'firewall.challenge.provider' => 'altcha',
        ]);

        $response = $this->responder()->challenge(
            Request::create('/gated'),
            $this->challengeException('math')
        );

        $body = (string) $response->getContent();

        // The math provider asks an arithmetic question; altcha does not.
        $this->assertStringContainsString('challenge_answer', $body);
        $this->assertStringContainsString('math.signed-by-the-firewall', $body);
    }

    #[Test]
    public function it_redirects_a_solved_challenge_and_sets_the_pass_cookie(): void
    {
        $response = $this->responder()->solved(
            Request::create('/_firewall/challenge', 'POST', ['ttl' => '600']),
            new ChallengeSolvedException('the-token', '/gated')
        );

        $this->assertSame(303, $response->getStatusCode());
        $this->assertSame('/gated', $response->headers->get('Location'));

        $cookie = $response->headers->getCookies()[0];
        $this->assertSame('fw_challenge_pass', $cookie->getName());
        $this->assertSame('the-token', $cookie->getValue());
    }

    /**
     * The cookie lifetime comes from the TTL the interstitial posted back.
     *
     * It has to match the token's own expiry, which `evaluate()` set from the
     * same field. A cookie that outlived the token would leave a visitor
     * holding a pass that is silently refused; one that expired first would
     * re-challenge somebody whose token was still good.
     */
    #[Test]
    public function the_pass_cookie_expiry_follows_the_posted_ttl(): void
    {
        $response = $this->responder()->solved(
            Request::create('/_firewall/challenge', 'POST', ['ttl' => '600']),
            new ChallengeSolvedException('the-token', '/gated')
        );

        $expires = $response->headers->getCookies()[0]->getExpiresTime();

        $this->assertGreaterThan(time() + 500, $expires);
        $this->assertLessThanOrEqual(time() + 600, $expires);
    }

    /**
     * A TTL that is absent, empty, non-numeric or an array falls back to an hour.
     *
     * Every one of these is attacker-chosen: they arrive on the interstitial's
     * own POST. The array case is the one that matters most — reading it
     * through `$request->input()` would throw out of `InputBag::get()`.
     *
     * @param array<string, mixed> $payload
     */
    #[Test]
    #[DataProvider('unusableTtls')]
    public function an_unusable_posted_ttl_falls_back_to_an_hour(array $payload): void
    {
        $response = $this->responder()->solved(
            Request::create('/_firewall/challenge', 'POST', $payload),
            new ChallengeSolvedException('the-token', '/gated')
        );

        $expires = $response->headers->getCookies()[0]->getExpiresTime();

        $this->assertGreaterThan(time() + 3500, $expires);
        $this->assertLessThanOrEqual(time() + 3600, $expires);
    }

    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function unusableTtls(): array
    {
        return [
            'absent' => [[]],
            'empty' => [['ttl' => '']],
            'words' => [['ttl' => 'an hour']],
            'zero' => [['ttl' => '0']],
            'negative' => [['ttl' => '-60']],
            'array' => [['ttl' => ['3600']]],
        ];
    }

    #[Test]
    public function the_pass_cookie_can_be_switched_off(): void
    {
        config(['firewall.challenge.cookie_name' => '']);

        $response = $this->responder()->solved(
            Request::create('/_firewall/challenge', 'POST'),
            new ChallengeSolvedException('the-token', '/gated')
        );

        $this->assertSame([], $response->headers->getCookies());
    }

    #[Test]
    public function a_solving_api_client_gets_json_rather_than_a_redirect(): void
    {
        $request = Request::create('/_firewall/challenge', 'POST');
        $request->headers->set('Accept', 'application/json');

        $response = $this->responder()->solved($request, new ChallengeSolvedException('t', '/gated'));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringContainsString('"token":"t"', (string) $response->getContent());

        // The cookie is set for a JSON client too: an SPA using the header
        // delivery path still benefits from it on any full page load.
        $this->assertNotSame([], $response->headers->getCookies());
    }

    #[Test]
    public function a_custom_view_name_is_honoured(): void
    {
        $this->app->make('view')->addNamespace('fixtures', __DIR__ . '/../Fixtures/views');
        config(['firewall.views.block' => 'fixtures::custom-block']);

        $response = $this->responder()->block(
            Request::create('/'),
            new FirewallBlockedException('Refused', 403)
        );

        $this->assertStringContainsString('A HOST OVERRODE THIS', (string) $response->getContent());
        $this->assertStringContainsString('Refused', (string) $response->getContent());
    }

    /**
     * A challenge exception shaped the way the firewall raises one.
     *
     * Since 2.26 the exception carries the provider and the render context, and
     * `renderInterstitial()` uses them — so an exception built with only a
     * message renders nothing at all. Constructing a realistic one here is not
     * ceremony: it is the difference between exercising the render path and
     * asserting that an empty string is empty.
     */
    private function challengeException(string $providerName = 'math'): ChallengeRequiredException
    {
        $secret = 'long-enough-secret-for-hmac-signing-here';
        $tokens = new TokenManager($secret, $providerName, $providerName);
        $registry = new ChallengeProviderRegistry($tokens, $providerName, []);
        $provider = $registry->get($providerName);

        return new ChallengeRequiredException(
            'Challenge required by plugin: gate',
            null,
            $provider,
            $providerName,
            [
                'submit_url' => '/_firewall/challenge',
                'redirect_to' => '/gated',
                'ttl' => '3600',
                'cookie_name' => 'fw_challenge_pass',
                'header_name' => 'X-Firewall-Challenge',
                'provider_token' => 'math.signed-by-the-firewall',
            ]
        );
    }

    private function configureChallenge(): void
    {
        config(['firewall.challenge.secret' => 'long-enough-secret-for-hmac-signing-here']);
    }

    private function responder(): FirewallResponder
    {
        return $this->app->make(FirewallResponder::class);
    }
}
