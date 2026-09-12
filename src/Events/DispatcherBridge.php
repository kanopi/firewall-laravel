<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Events;

use Illuminate\Contracts\Events\Dispatcher as IlluminateDispatcher;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Present Laravel's event dispatcher as the PSR-14 one the firewall wants.
 *
 * `Firewall::create()` takes a `Psr\EventDispatcher\EventDispatcherInterface`
 * as its third argument. Laravel's dispatcher is not one: PSR-14 is
 * `dispatch(object $event): object`, and Laravel's is
 * `dispatch($event, $payload = [], $halt = false)` returning an array of
 * listener results or NULL. The signatures are close enough that the adapter
 * is four lines and far enough that Laravel's cannot be passed directly.
 *
 * Because Laravel dispatches an object event under its own class name,
 * listeners register against the library's event classes with no further
 * ceremony:
 *
 *     Event::listen(RequestBlocked::class, function (RequestBlocked $event) {
 *         // …
 *     });
 *
 * ## What a listener cannot do
 *
 * The firewall's events are read-only by design. A listener cannot change a
 * verdict — the decision is already made when the event is announced, and the
 * announcement happens after the block is recorded and before the response is
 * written precisely so that it happens at all. A listener that throws is
 * caught by the library and logged at `error`, never propagated.
 *
 * Two consequences worth stating plainly, because both are easy to build
 * against by accident:
 *
 *  - **Returning FALSE from a listener does not halt anything.** Laravel treats
 *    a FALSE return as "stop propagating to later listeners", and that much
 *    still works, but it has no effect on the firewall's decision.
 *  - **Do not put anything load-bearing in a listener.** An audit trail that
 *    must exist, a counter something else reads — those need to be written
 *    somewhere that fails loudly. A swallowed exception here is invisible to
 *    the request.
 *
 * Events are the right place for what is genuinely advisory: a StatsD counter,
 * a Slack notification, a queued job for enrichment.
 */
final class DispatcherBridge implements EventDispatcherInterface
{
    public function __construct(private readonly IlluminateDispatcher $events)
    {
    }

    /**
     * Announce a firewall decision to Laravel's listeners.
     *
     * @param object $event
     *   One of `Kanopi\Firewall\Event\{RequestAllowed, RequestBlocked,
     *   RequestChallenged, ChallengeSolved, ChallengeFailed}`.
     *
     * @return object
     *   The same event, as PSR-14 requires. Laravel's listener return values
     *   are deliberately discarded: PSR-14 says the dispatcher returns the
     *   event it was given, and the firewall ignores the return in any case.
     */
    public function dispatch(object $event): object
    {
        $this->events->dispatch($event);

        return $event;
    }
}
