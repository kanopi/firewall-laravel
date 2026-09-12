<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\FirewallMode;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use Kanopi\Firewall\Plugins\IpAddress;
use PHPUnit\Framework\Attributes\Test;

/**
 * Lockdown, added to the library in 2.26.
 *
 * Deny by default: nobody is served but an explicit allowlist. What an operator
 * wants when a site is being hammered and serving nobody beats serving the
 * attacker.
 *
 * It needed work here because of how the library delivers it. `mode: lockdown`
 * is shorthand — the constructor sets its lockdown flag and then rewrites its
 * own mode to `block`, which is the one mode that writes a response and calls
 * `exit()`. Passed through untouched, this package's boot guard would have
 * caught that and refused to start, reporting a failed mode override to an
 * operator who had asked for lockdown and done nothing wrong.
 *
 * Since 2.26 the policy has its own config key, so the two axes separate: this
 * integration translates `mode: lockdown` into `global.lockdown: true` with a
 * delivery Laravel can render.
 */
final class LockdownTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        $router->get('/anything', static fn (): string => 'through');
    }

    /**
     * `mode: lockdown` boots, rather than tripping the delivery guard.
     *
     * The regression this pins is a refusal to start, which on a fresh deploy
     * is every request 500ing with a message about an override that did not
     * take — for a mode the operator set deliberately.
     */
    #[Test]
    public function lockdown_mode_boots(): void
    {
        config(['firewall.global.mode' => 'lockdown']);

        $this->assertSame(FirewallMode::Exception, $this->app->make(Firewall::class)->getMode());
    }

    #[Test]
    public function lockdown_mode_refuses_a_visitor(): void
    {
        config(['firewall.global.mode' => 'lockdown']);

        $this->get('/anything')->assertStatus(503)->assertDontSee('through');
    }

    /**
     * The allowlist still gets through — that is the whole point of it.
     */
    #[Test]
    public function an_allowed_address_is_still_served_in_lockdown(): void
    {
        config([
            'firewall.global.mode' => 'lockdown',
            'firewall.global.lockdown_allow' => ['127.0.0.1'],
        ]);

        $this->get('/anything')->assertOk()->assertSee('through');
    }

    /**
     * A lockdown refusal says when to come back; a ban does not.
     *
     * Lockdown is temporary by design, so `Retry-After` is the honest
     * difference from a block — and a block has no truthful answer to the
     * question.
     */
    #[Test]
    public function a_lockdown_response_carries_retry_after(): void
    {
        config(['firewall.global.mode' => 'lockdown']);

        $response = $this->get('/anything');

        $response->assertStatus(503);
        $this->assertNotNull(
            $response->headers->get('Retry-After'),
            'A lockdown is temporary, so it should say when to try again.'
        );
    }

    #[Test]
    public function a_plain_block_carries_no_retry_after(): void
    {
        $this->blockIp('127.0.0.1');

        $response = $this->get('/anything');

        $response->assertStatus(400);
        $this->assertNull(
            $response->headers->get('Retry-After'),
            'A ban has no honest answer to "when can I come back?".'
        );
    }

    /**
     * The policy can be set directly, leaving the mode alone.
     *
     * `global.lockdown` is an independent axis in 2.26, so a host running
     * `mode: exception` does not have to give that up to enter lockdown. This
     * package passes the key through untouched and overrides it only when the
     * *mode* asked for lockdown — so an operator setting it directly keeps
     * control, including turning it back off.
     */
    #[Test]
    public function lockdown_can_be_set_without_using_the_mode(): void
    {
        config([
            'firewall.global.mode' => 'block',
            'firewall.global.lockdown' => true,
        ]);

        $this->get('/anything')->assertStatus(503);
    }

    #[Test]
    public function lockdown_is_off_by_default(): void
    {
        $this->get('/anything')->assertOk()->assertSee('through');
    }

    /**
     * An explicit `lockdown: false` is not overridden by anything here.
     */
    #[Test]
    public function lockdown_can_be_switched_off_explicitly(): void
    {
        config([
            'firewall.global.mode' => 'block',
            'firewall.global.lockdown' => false,
        ]);

        $this->get('/anything')->assertOk();
    }

    /**
     * The doctor reports lockdown, because a site refusing everybody should say so.
     */
    #[Test]
    public function the_translator_reports_lockdown_mode(): void
    {
        config(['firewall.global.mode' => 'lockdown']);

        $translator = $this->app->make(\Kanopi\Firewall\Laravel\FirewallFactory::class)->translator();

        $this->assertTrue($translator->isLockdownMode());
        $this->assertTrue($translator->modeWasTranslated());
        $this->assertSame(FirewallMode::Exception, $translator->effectiveMode());
        $this->assertTrue($translator->overrides()['[global][lockdown]']);
    }

    #[Test]
    public function a_normal_mode_is_not_reported_as_lockdown(): void
    {
        $translator = $this->app->make(\Kanopi\Firewall\Laravel\FirewallFactory::class)->translator();

        $this->assertFalse($translator->isLockdownMode());
        $this->assertArrayNotHasKey('[global][lockdown]', $translator->overrides());
    }

    /**
     * An allow rule is not the lockdown allowlist.
     *
     * Worth asserting because the two look interchangeable and are not:
     * `lockdown_allow` is consulted by the lockdown gate, which sits ahead of
     * the rule buckets. A `response: allow` rule does not open a lockdown.
     */
    #[Test]
    public function an_allow_rule_does_not_open_a_lockdown(): void
    {
        config([
            'firewall.global.mode' => 'lockdown',
            'firewall.plugins' => [[
                'plugin' => IpAddress::class,
                'response' => 'allow',
                'name' => 'office',
                'config' => ['127.0.0.1'],
            ]],
        ]);

        $this->get('/anything')->assertStatus(503);
    }
}
