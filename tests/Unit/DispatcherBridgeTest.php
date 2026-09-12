<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Unit;

use Illuminate\Container\Container;
use Illuminate\Events\Dispatcher;
use Kanopi\Firewall\Event\RequestAllowed;
use Kanopi\Firewall\Laravel\Events\DispatcherBridge;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;

final class DispatcherBridgeTest extends TestCase
{
    #[Test]
    public function it_is_a_psr14_dispatcher(): void
    {
        $this->assertInstanceOf(
            EventDispatcherInterface::class,
            new DispatcherBridge(new Dispatcher(new Container()))
        );
    }

    #[Test]
    public function it_hands_the_event_to_laravel_listeners_under_its_class_name(): void
    {
        $events = new Dispatcher(new Container());
        $seen = null;

        $events->listen(RequestAllowed::class, static function (RequestAllowed $event) use (&$seen): void {
            $seen = $event;
        });

        $event = new RequestAllowed(Request::create('/'));

        (new DispatcherBridge($events))->dispatch($event);

        $this->assertSame($event, $seen);
    }

    /**
     * PSR-14 requires the same event object back, not the listener results.
     *
     * Laravel's `dispatch()` returns an array of listener return values, which
     * is a different contract. Returning that instead would break any PSR-14
     * consumer — and the firewall discards the return in any case, which is
     * why nothing a listener returns can change a verdict.
     */
    #[Test]
    public function it_returns_the_event_it_was_given(): void
    {
        $events = new Dispatcher(new Container());
        $events->listen(RequestAllowed::class, static fn (): string => 'a listener result');

        $event = new RequestAllowed(Request::create('/'));

        $this->assertSame($event, (new DispatcherBridge($events))->dispatch($event));
    }
}
