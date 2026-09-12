<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Illuminate\Support\Facades\Route;
use Kanopi\Firewall\Event\RequestMarked;
use Kanopi\Firewall\Event\RequestRecorded;
use Kanopi\Firewall\Event\RequestRedirected;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use Kanopi\Firewall\Plugins\Url;
use PHPUnit\Framework\Attributes\Test;

/**
 * The response types `kanopi/firewall` 2.26 added: redirect, record and mark.
 *
 * Before 2.26 a rule could only allow, block or challenge. The three below are
 * the other things an operator wants: send them somewhere, write it down
 * without acting on it, and label the request for the application to read.
 *
 * Two of them need nothing from this package and one very much does, which is
 * the distinction these tests exist to hold:
 *
 * - `redirect` raises `FirewallRedirectException`, a class this middleware had
 *   never heard of. Unhandled it falls through to the "the firewall is broken"
 *   policy — a 500 by default, or an unfiltered pass-through when configured to
 *   fail open. Neither is a redirect.
 * - `record` and `mark` are non-terminal: the request carries on. They need no
 *   middleware change at all, and the marks land as request attributes the
 *   application can read *because* Laravel's own request object is handed
 *   through rather than converted.
 */
final class ResponseTypesTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        $router->get('/watched', static fn (): string => 'through');
        $router->get('/honeypot', static fn (): string => 'through');
        $router->get('/moved', static fn (): string => 'through');
    }

    /**
     * A redirect rule sends the visitor, rather than refusing them.
     *
     * The assertion that matters is the status: a 302 means the exception was
     * recognised. A 500 would mean it reached the broken-firewall policy.
     */
    #[Test]
    public function a_redirect_rule_redirects(): void
    {
        $this->redirectRule('https://status.example.test/notice');

        $response = $this->get('/moved');

        $response->assertStatus(302);
        $response->assertRedirect('https://status.example.test/notice');
        $response->assertDontSee('through');
    }

    /**
     * An off-site destination is honoured rather than reduced to the root.
     *
     * The challenge flow's redirect is attacker-influenced and is forced
     * same-origin. This one is not: it comes from the rule's
     * `metadata.redirect_to`, which is operator-authored configuration, and
     * sending a caught visitor to a status page on another host is the normal
     * use. Applying the challenge rule here would break that for no gain.
     */
    #[Test]
    public function a_redirect_may_leave_the_application(): void
    {
        $this->redirectRule('https://help.example.test/why-was-i-blocked');

        $this->get('/moved')->assertRedirect('https://help.example.test/why-was-i-blocked');
    }

    #[Test]
    public function a_redirect_is_not_cached_by_a_shared_cache(): void
    {
        $this->redirectRule('/notice');

        // A redirect a rule chose is about this visitor now; a shared cache
        // serving it to the next one would redirect somebody nothing matched.
        $this->get('/moved')->assertHeader('Cache-Control', 'no-store, private');
    }

    #[Test]
    public function a_redirect_rule_honours_a_permanent_status(): void
    {
        $this->redirectRule('/notice', 301);

        $this->get('/moved')->assertStatus(301);
    }

    #[Test]
    public function a_redirect_reaches_laravel_listeners(): void
    {
        $seen = [];
        $this->app->make('events')->listen(
            RequestRedirected::class,
            static function (RequestRedirected $event) use (&$seen): void {
                $seen[] = $event;
            }
        );

        $this->redirectRule('/notice');
        $this->get('/moved');

        $this->assertCount(1, $seen, 'A redirect decision must reach a Laravel listener.');
    }

    /**
     * A record rule writes the offence down and serves the request anyway.
     *
     * This is what a honeypot needs: the rule catching a scanner on a wired
     * URL wants it on the block list for *next* time. Refusing the fetch it is
     * already serving would tell the scanner exactly which URL is wired, which
     * is the one thing a honeypot must not do.
     */
    #[Test]
    public function a_record_rule_does_not_interrupt_the_request(): void
    {
        config(['firewall.plugins' => [[
            'plugin' => Url::class,
            'response' => 'record',
            'name' => 'honeypot',
            'config' => ['path:/honeypot'],
        ]]]);

        $this->get('/honeypot')->assertOk()->assertSee('through');
    }

    #[Test]
    public function a_record_reaches_laravel_listeners(): void
    {
        $seen = [];
        $this->app->make('events')->listen(
            RequestRecorded::class,
            static function (RequestRecorded $event) use (&$seen): void {
                $seen[] = $event;
            }
        );

        config(['firewall.plugins' => [[
            'plugin' => Url::class,
            'response' => 'record',
            'name' => 'honeypot',
            'config' => ['path:/honeypot'],
        ]]]);

        $this->get('/honeypot')->assertOk();

        $this->assertCount(1, $seen);
    }

    /**
     * A mark labels the request and the application can read it.
     *
     * This works with no code in this package, and the reason is a decision
     * made at the very start: `Illuminate\Http\Request` extends the Symfony
     * request, so it is handed to `evaluate()` unchanged. The library sets its
     * attributes on that same object, so they are still there when the
     * controller runs. A PSR-7 bridge would have copied the request and thrown
     * the marks away.
     */
    #[Test]
    public function a_mark_is_readable_by_the_application(): void
    {
        Route::get('/marked', static function (\Illuminate\Http\Request $request): array {
            return [
                'marks' => $request->attributes->get('firewall.marks', []),
                'suspicious' => (bool) $request->attributes->get('firewall.mark.suspicious', false),
                'header' => $request->headers->get('X-Suspicious', ''),
            ];
        });

        config(['firewall.plugins' => [[
            'plugin' => Url::class,
            'response' => 'mark',
            'name' => 'watch-this-path',
            // `mark_as`, not the rule's `name`. The attribute is named from
            // metadata, falling back to the *plugin type* — so without this the
            // mark is called "URL", which is the class that matched rather than
            // what it means. Worth knowing: a rule named for the operator's
            // benefit does not name the signal the application reads.
            'metadata' => ['mark_as' => 'suspicious', 'mark_header' => 'X-Suspicious'],
            'config' => ['path:/marked'],
        ]]]);

        $this->getJson('/marked')
            ->assertOk()
            ->assertJson([
                'marks' => ['suspicious'],
                'suspicious' => true,
                // The header is set on the *request*, so an application behind
                // a proxy can read it the same way it reads any other header.
                'header' => 'suspicious',
            ]);
    }

    #[Test]
    public function a_marked_request_is_still_served(): void
    {
        config(['firewall.plugins' => [[
            'plugin' => Url::class,
            'response' => 'mark',
            'name' => 'watch-this-path',
            'metadata' => ['mark_as' => 'suspicious'],
            'config' => ['path:/watched'],
        ]]]);

        $this->get('/watched')->assertOk()->assertSee('through');
    }

    #[Test]
    public function a_mark_reaches_laravel_listeners(): void
    {
        $seen = [];
        $this->app->make('events')->listen(
            RequestMarked::class,
            static function (RequestMarked $event) use (&$seen): void {
                $seen[] = $event;
            }
        );

        config(['firewall.plugins' => [[
            'plugin' => Url::class,
            'response' => 'mark',
            'name' => 'watch-this-path',
            'metadata' => ['mark_as' => 'suspicious'],
            'config' => ['path:/watched'],
        ]]]);

        $this->get('/watched')->assertOk();

        $this->assertCount(1, $seen);
    }

    /**
     * Configure one redirect rule.
     */
    private function redirectRule(string $destination, ?int $status = null): void
    {
        $metadata = ['redirect_to' => $destination];

        if ($status !== null) {
            $metadata['redirect_status'] = $status;
        }

        config(['firewall.plugins' => [[
            'plugin' => Url::class,
            'response' => 'redirect',
            'name' => 'send-them-somewhere',
            'metadata' => $metadata,
            'config' => ['path:/moved'],
        ]]]);
    }
}
