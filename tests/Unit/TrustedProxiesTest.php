<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Unit;

use Illuminate\Config\Repository;
use Illuminate\Http\Middleware\TrustProxies;
use Kanopi\Firewall\Laravel\Config\TrustedProxies;
use Kanopi\Firewall\Laravel\Support\Settings;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * A generated-style TrustProxies with an actual proxy list.
 *
 * Declared here rather than under `tests/Laravel/app/` because it must NOT be
 * discoverable as `App\Http\Middleware\TrustProxies` — that name is the one
 * the bridge looks for by default, and a fixture there carrying a proxy list
 * would change the trusted-proxy posture for every other test in the suite.
 */
final class ConfiguredTrustProxies extends \Illuminate\Http\Middleware\TrustProxies
{
    /**
     * @var array<int, string>|string|null
     */
    protected $proxies = ['172.16.0.1'];
}

/**
 * The trusted-proxy bridge.
 *
 * Every assertion here is ultimately about one thing: whether
 * `$request->getClientIp()` can be trusted when a firewall rule reads it. Get
 * this wrong and an IP allowlist matches the proxy instead of the visitor
 * while a forged `X-Forwarded-For` sails through — a failure with no symptom
 * until somebody uses it.
 */
final class TrustedProxiesTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->reset();
    }

    protected function tearDown(): void
    {
        $this->reset();
        parent::tearDown();
    }

    #[Test]
    public function it_reads_proxies_declared_by_trust_proxies_at(): void
    {
        TrustProxies::at(['10.0.0.1', '10.0.0.2']);

        $this->assertSame(['10.0.0.1', '10.0.0.2'], $this->bridge()->declared());
    }

    #[Test]
    public function it_reads_proxies_declared_as_a_string(): void
    {
        TrustProxies::at('*');

        $this->assertSame('*', $this->bridge()->declared());
    }

    #[Test]
    public function it_reads_proxies_from_the_published_config(): void
    {
        $this->assertSame(
            ['192.0.2.1'],
            $this->bridge(['trustedproxy' => ['proxies' => ['192.0.2.1']]])->declared()
        );
    }

    #[Test]
    public function it_reports_nothing_declared_when_nothing_is(): void
    {
        $this->assertNull($this->bridge()->declared());
    }

    /**
     * An empty declaration means the same as no declaration.
     *
     * `TrustProxies` treats both identically, so distinguishing them here
     * would be reading a difference with no effect on what gets trusted.
     */
    #[Test]
    public function an_empty_declaration_is_the_same_as_none(): void
    {
        $this->assertNull($this->bridge(['trustedproxy' => ['proxies' => []]])->declared());
        $this->assertNull($this->bridge(['trustedproxy' => ['proxies' => '']])->declared());
    }

    #[Test]
    public function it_drops_non_string_entries_from_a_declaration(): void
    {
        $this->assertSame(
            ['10.0.0.1'],
            $this->bridge(['trustedproxy' => ['proxies' => ['10.0.0.1', 42, null, '']]])->declared()
        );
    }

    #[Test]
    public function it_ignores_a_declaration_of_the_wrong_type(): void
    {
        $this->assertNull($this->bridge(['trustedproxy' => ['proxies' => 42]])->declared());
    }

    #[Test]
    public function it_reads_the_proxies_in_force(): void
    {
        Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_X_FORWARDED_FOR);

        $this->assertSame(['10.0.0.1'], $this->bridge()->inForce());
    }

    /**
     * The posture is TRUE when a proxy is known about, and never FALSE.
     *
     * Asserting "there is no proxy" is the one answer that silences the
     * library's warning outright, and nothing observable from here justifies
     * it: a deployment with no trusted proxies configured is far more often
     * one that forgot than one that has none.
     */
    #[Test]
    public function the_posture_is_true_when_proxies_are_declared(): void
    {
        $this->assertTrue($this->bridge(['trustedproxy' => ['proxies' => ['10.0.0.1']]])->posture());
    }

    #[Test]
    public function the_posture_is_true_when_proxies_are_merely_in_force(): void
    {
        Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_X_FORWARDED_FOR);

        $this->assertTrue($this->bridge()->posture());
    }

    #[Test]
    public function the_posture_is_unknown_rather_than_false_when_nothing_is_configured(): void
    {
        $this->assertNull($this->bridge()->posture());
    }

    /**
     * The ordering bug, isolated.
     *
     * Declared but not in force is the exact state the middleware sees when it
     * runs before `TrustProxies` — and it is not distinguishable by looking at
     * the in-force list alone, because `TrustProxies::handle()` opens by
     * resetting that list to empty.
     */
    #[Test]
    public function a_declaration_with_nothing_in_force_is_spoofable(): void
    {
        $bridge = $this->bridge(['trustedproxy' => ['proxies' => ['10.0.0.1']]]);

        $this->assertTrue($bridge->isSpoofable());
    }

    #[Test]
    public function it_is_not_spoofable_once_the_proxies_are_applied(): void
    {
        Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_X_FORWARDED_FOR);

        $this->assertFalse($this->bridge(['trustedproxy' => ['proxies' => ['10.0.0.1']]])->isSpoofable());
    }

    /**
     * Nothing declared is not spoofable, because there is nothing to lose.
     *
     * `getClientIp()` returns the connecting address and forwarding headers
     * are ignored entirely — which is safe, if possibly wrong about who the
     * visitor is. The library warns about that separately.
     */
    #[Test]
    public function nothing_declared_is_not_reported_as_spoofable(): void
    {
        $this->assertFalse($this->bridge()->isSpoofable());
    }

    /**
     * Laravel 10 and earlier kept the proxy list on a generated middleware.
     *
     * Read off an instance of the application's own subclass, through a
     * reflection on the base class that declares the property. Supporting it
     * is not optional while this package claims Laravel 10 — that is where the
     * list lives there, and missing it would mean reporting "no proxies
     * configured" on every Laravel 10 deployment behind a load balancer.
     */
    #[Test]
    public function it_reads_proxies_from_a_generated_trust_proxies_subclass(): void
    {
        $this->assertNull(
            $this->bridge()->declared(),
            'The fixture leaves $proxies null, as a generated file does.'
        );

        $bridge = new TrustedProxies(
            new Settings(new Repository([])),
            ConfiguredTrustProxies::class
        );

        $this->assertSame(['172.16.0.1'], $bridge->declared());
    }

    /**
     * A subclass that cannot be constructed reports "cannot tell", not a crash.
     *
     * Applications do give this middleware dependencies. Reading its property
     * has to survive a constructor we cannot call — and the answer has to be
     * NULL rather than an assumed TRUE, so the library keeps warning about the
     * one thing it cannot verify.
     */
    #[Test]
    public function a_subclass_that_cannot_be_constructed_is_reported_as_unknown(): void
    {
        $bridge = new TrustedProxies(
            new Settings(new Repository([])),
            \App\Http\Middleware\UnconstructableTrustProxies::class
        );

        $this->assertNull($bridge->declared());
        $this->assertNull($bridge->posture());
    }

    #[Test]
    public function a_legacy_middleware_class_that_does_not_exist_is_ignored(): void
    {
        $bridge = new TrustedProxies(new Settings(new Repository([])), 'App\\No\\Such\\Middleware');

        $this->assertNull($bridge->declared());
    }

    /**
     * `TrustProxies::at()` wins over the published config, as Laravel resolves it.
     */
    #[Test]
    public function the_always_trust_list_wins_over_the_published_config(): void
    {
        TrustProxies::at(['10.0.0.1']);

        $this->assertSame(
            ['10.0.0.1'],
            $this->bridge(['trustedproxy' => ['proxies' => ['192.0.2.1']]])->declared()
        );
    }

    /**
     * @param array<string, mixed> $config
     */
    private function bridge(array $config = []): TrustedProxies
    {
        return new TrustedProxies(new Settings(new Repository($config)));
    }

    private function reset(): void
    {
        TrustProxies::flushState();
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);
    }
}
