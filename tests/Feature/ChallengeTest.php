<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Illuminate\Testing\TestResponse;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\Test;

/**
 * The challenge round-trip, end to end.
 *
 * This is trap 4: the POST to `challenge.path` must reach the firewall and must
 * not be routed by the application. If it does not, a challenged visitor can
 * never solve and is locked out permanently — and nothing reports it, because
 * from the firewall's side that visitor simply never comes back with a valid
 * token.
 *
 * The math provider is used because it is the only shipped provider that can be
 * solved without a third-party service, and it can be solved here honestly: the
 * expected answer travels in the signed `challenge_state` field, so the test
 * reads it out of the rendered interstitial exactly as a browser would read the
 * question, and posts it back through the real signing and verification path.
 * Nothing is stubbed — the HMAC is real, the token is real, and the cookie the
 * visitor gets back is the one the firewall will actually accept.
 */
final class ChallengeTest extends TestCase
{
    private const SECRET = 'test-secret-that-is-long-enough-to-be-a-real-hmac-key';

    protected function defineRoutes($router): void
    {
        $router->get('/gated', static fn (): string => 'through');
    }

    protected function setUp(): void
    {
        parent::setUp();

        // Set here rather than in `defineEnvironment()`, because Testbench runs
        // the `#[DefineEnvironment]` attribute methods *before*
        // `defineEnvironment()` — so a per-test override placed in an attribute
        // would be silently overwritten by the shared setup. Both values are
        // read when the firewall is built, which is lazily inside the
        // middleware, so setting them at runtime is equivalent and cannot be
        // clobbered.
        $this->gateThePage();
    }

    /**
     * One challenge rule covering /gated, with a real signing secret.
     */
    private function gateThePage(): void
    {
        config([
            'firewall.challenge.secret' => self::SECRET,
            'firewall.plugins' => [[
                'plugin' => \Kanopi\Firewall\Plugins\Url::class,
                'response' => 'challenge',
                'name' => 'gate-the-page',
                'config' => ['path:/gated'],
            ]],
        ]);
    }

    #[Test]
    public function a_challenged_visitor_gets_the_interstitial(): void
    {
        $response = $this->get('/gated');

        // 200, matching what the library writes in `block` mode. A 4xx would
        // read better as a status but breaks the round-trip: caches and error
        // trackers treat a 4xx body as a failure to discard or report, and the
        // interstitial is a working page the visitor has to interact with.
        $response->assertOk();
        $response->assertDontSee('through');
        $response->assertHeader('Cache-Control', 'no-store, private');
        $response->assertSee('action="/_firewall/challenge"', false);
        $response->assertSee(MathChallengeProvider::ANSWER_FIELD, false);
    }

    #[Test]
    public function solving_the_challenge_issues_a_pass_cookie_and_redirects_back(): void
    {
        $interstitial = $this->get('/gated');

        $response = $this->postSolution($interstitial, $this->answerFrom($interstitial));

        $response->assertStatus(303);
        $response->assertRedirect('/gated');

        $cookie = $this->passCookie($response);
        $this->assertNotNull($cookie, 'The firewall must issue a pass cookie on a correct answer.');
        $this->assertTrue($cookie->isHttpOnly(), 'Script must not be able to read the pass token.');
        $this->assertTrue($cookie->isSecure(), 'The pass token must never travel in clear.');
        $this->assertSame('strict', strtolower((string) $cookie->getSameSite()));
    }

    /**
     * The whole point: the token actually opens the gate.
     *
     * Everything before this could pass while the issued token was worth
     * nothing — a wrong audience, a wrong provider scope, a cookie name that
     * does not match the one the firewall reads. This is the assertion that a
     * challenged visitor can get through.
     */
    #[Test]
    public function the_pass_token_lets_the_visitor_through(): void
    {
        $interstitial = $this->get('/gated');
        $solved = $this->postSolution($interstitial, $this->answerFrom($interstitial));

        $cookie = $this->passCookie($solved);
        $this->assertNotNull($cookie);

        $this->withUnencryptedCookie((string) $cookie->getName(), (string) $cookie->getValue())
            ->get('/gated')
            ->assertOk()
            ->assertSee('through');
    }

    #[Test]
    public function a_wrong_answer_serves_the_interstitial_again(): void
    {
        $interstitial = $this->get('/gated');

        $response = $this->postSolution($interstitial, '-1');

        $response->assertOk();
        $response->assertSee(MathChallengeProvider::ANSWER_FIELD, false);

        $this->assertNull(
            $this->passCookie($response),
            'A rejected solution must not issue a pass token.'
        );
    }

    /**
     * A wrong answer must not say *why* it was wrong.
     *
     * The library throws the same `ChallengeRequiredException` for "you have
     * not solved one yet" and "your answer was wrong", deliberately: telling a
     * bot which of the two happened is free information. This asserts the
     * integration does not reintroduce the distinction in the response.
     */
    #[Test]
    public function a_wrong_answer_is_indistinguishable_from_a_first_visit(): void
    {
        $first = $this->get('/gated');
        $rejected = $this->postSolution($first, '-1');

        $this->assertSame($first->getStatusCode(), $rejected->getStatusCode());
    }

    #[Test]
    public function an_api_client_is_told_it_is_challenged_rather_than_shown_a_page(): void
    {
        $response = $this->getJson('/gated');

        $response->assertStatus(403);

        $body = (array) $response->json();
        $this->assertArrayHasKey('challenge', $body);
        $this->assertIsArray($body['challenge']);
        $this->assertSame('/_firewall/challenge', $body['challenge']['path']);
        $this->assertSame('X-Firewall-Challenge', $body['challenge']['header']);
    }

    #[Test]
    public function a_solving_api_client_gets_the_token_as_json(): void
    {
        $interstitial = $this->get('/gated');

        $response = $this->postJson('/_firewall/challenge', $this->solutionPayload(
            $interstitial,
            $this->answerFrom($interstitial)
        ));

        $response->assertOk();

        $body = (array) $response->json();
        $this->assertArrayHasKey('token', $body);
        $this->assertSame('/gated', $body['redirect']);
    }

    /**
     * Trap 4 with global middleware turned off.
     *
     * Route middleware runs after routing, so without the dedicated route the
     * POST below would 404 and the visitor would be stuck forever. The route
     * this package registers is what stops that.
     */
    #[Test]
    #[DefineEnvironment('withoutGlobalMiddleware')]
    public function the_submission_still_reaches_the_firewall_without_global_middleware(): void
    {
        // The interstitial cannot be reached by a GET here — the page itself is
        // unprotected without global middleware — so the challenge state is
        // generated by rendering the interstitial through the responder, which
        // is the same code path the middleware uses.
        // Rendered through a real firewall evaluation rather than a
        // hand-built exception: since 2.26 the interstitial comes from the
        // provider and context the exception carries, so an exception
        // assembled here would render nothing and prove nothing.
        $firewall = $this->app->make(\Kanopi\Firewall\Firewall::class);
        $html = '';

        try {
            $firewall->evaluate(\Illuminate\Http\Request::create('/gated'));
        } catch (\Kanopi\Firewall\Exception\ChallengeRequiredException $required) {
            $html = (string) $this->app
                ->make(\Kanopi\Firewall\Laravel\Http\FirewallResponder::class)
                ->challenge(\Illuminate\Http\Request::create('/gated'), $required)
                ->getContent();
        }

        $this->assertNotSame('', $html, 'The challenge rule should have raised an interstitial.');
        $state = $this->extract($html, MathChallengeProvider::STATE_FIELD);

        $response = $this->post('/_firewall/challenge', [
            MathChallengeProvider::ANSWER_FIELD => $this->solveState($state),
            MathChallengeProvider::STATE_FIELD => $state,
            MathChallengeProvider::REDIRECT_FIELD => '/gated',
            MathChallengeProvider::TTL_FIELD => '3600',
        ]);

        $response->assertStatus(303);
        $this->assertNotNull($this->passCookie($response));
    }

    /**
     * The registered route is unreachable while challenges are configured…
     * and a plain 404 once they are not, rather than a 500 or a blank 200.
     */
    #[Test]
    public function the_challenge_route_is_a_404_when_no_rule_challenges(): void
    {
        config(['firewall.plugins' => []]);

        // The route exists but is only ever reached when the firewall did not
        // intercept, which means challenges are not configured. A 404 is then
        // the truthful answer: nothing lives at this path. The alternative — an
        // empty 200 — would advertise a firewall endpoint on every site running
        // this package whether or not it uses challenges.
        $this->post('/_firewall/challenge')->assertNotFound();
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function withoutGlobalMiddleware($app): void
    {
        $app['config']->set('firewall.middleware.global', false);
    }

    /**
     * POST a solution built from a rendered interstitial.
     */
    private function postSolution(TestResponse $interstitial, string $answer): TestResponse
    {
        return $this->post('/_firewall/challenge', $this->solutionPayload($interstitial, $answer));
    }

    /**
     * @return array<string, string>
     */
    private function solutionPayload(TestResponse $interstitial, string $answer): array
    {
        $html = (string) $interstitial->getContent();

        return [
            MathChallengeProvider::ANSWER_FIELD => $answer,
            MathChallengeProvider::STATE_FIELD => $this->extract($html, MathChallengeProvider::STATE_FIELD),
            MathChallengeProvider::REDIRECT_FIELD => $this->extract($html, MathChallengeProvider::REDIRECT_FIELD),
            MathChallengeProvider::TTL_FIELD => $this->extract($html, MathChallengeProvider::TTL_FIELD),
        ];
    }

    /**
     * The correct answer to the question in a rendered interstitial.
     *
     * The expected answer is the first half of the signed `challenge_state`
     * field, which is how the provider stays stateless between rendering and
     * verifying. Reading it is not cheating past the challenge: the signature
     * is still verified server-side, so this exercises the real HMAC path.
     * Parsing the rendered arithmetic instead would test the question's
     * formatting rather than the round-trip.
     */
    private function answerFrom(TestResponse $interstitial): string
    {
        return $this->solveState($this->extract((string) $interstitial->getContent(), MathChallengeProvider::STATE_FIELD));
    }

    private function solveState(string $state): string
    {
        $this->assertStringContainsString('|', $state, 'The signed challenge state is malformed.');

        return explode('|', $state, 2)[0];
    }

    /**
     * Pull a hidden input's value out of the interstitial.
     */
    private function extract(string $html, string $field): string
    {
        $matched = preg_match(
            '/name="' . preg_quote($field, '/') . '"[^>]*value="([^"]*)"/',
            $html,
            $matches
        );

        $this->assertSame(1, $matched, sprintf('The interstitial carries no "%s" field.', $field));

        return htmlspecialchars_decode($matches[1], ENT_QUOTES);
    }

    /**
     * The pass-token cookie from a response, if it set one.
     */
    private function passCookie(TestResponse $response): ?\Symfony\Component\HttpFoundation\Cookie
    {
        $name = (string) config('firewall.challenge.cookie_name');

        foreach ($response->baseResponse->headers->getCookies() as $cookie) {
            if ($cookie->getName() === $name) {
                return $cookie;
            }
        }

        return null;
    }
}
