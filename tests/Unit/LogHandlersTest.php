<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Unit;

use Illuminate\Log\Logger as IlluminateLogger;
use Kanopi\Firewall\Laravel\Config\LogHandlers;
use Monolog\Handler\NullHandler;
use Monolog\Handler\TestHandler;
use Monolog\Logger as MonologLogger;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class LogHandlersTest extends TestCase
{
    /**
     * The bridge in one assertion: a Laravel channel's handlers, reused.
     *
     * `LoggingFactory::create()` accepts a ready-made `HandlerInterface`
     * alongside a class name, which is what makes this possible without any
     * change to the library — and what makes a second firewall log file
     * unnecessary.
     */
    #[Test]
    public function it_borrows_the_handlers_off_a_laravel_channel(): void
    {
        $handler = new TestHandler();
        $channel = new IlluminateLogger(new MonologLogger('laravel', [$handler]));

        $definitions = (new LogHandlers(['channel' => 'stack'], $channel))->all();

        $this->assertSame([['class' => $handler]], $definitions);
    }

    #[Test]
    public function it_unwraps_a_bare_monolog_logger_too(): void
    {
        $handler = new TestHandler();

        $definitions = (new LogHandlers(['channel' => 'x'], new MonologLogger('m', [$handler])))->all();

        $this->assertSame([['class' => $handler]], $definitions);
    }

    /**
     * A channel that is not Monolog-backed yields nothing, and does not throw.
     *
     * A log destination is not worth refusing traffic over: the firewall still
     * evaluates every rule. `firewall:doctor` reports the silence instead.
     */
    #[Test]
    public function a_non_monolog_channel_contributes_no_handlers(): void
    {
        $this->assertSame([], (new LogHandlers(['channel' => 'x'], new NullLogger()))->all());
    }

    #[Test]
    public function no_channel_contributes_no_handlers(): void
    {
        $this->assertSame([], (new LogHandlers(['channel' => null]))->all());
        $this->assertNull((new LogHandlers(['channel' => null]))->channelName());
        $this->assertNull((new LogHandlers(['channel' => '']))->channelName());
    }

    #[Test]
    public function it_reports_the_channel_it_was_asked_to_borrow_from(): void
    {
        $this->assertSame('daily', (new LogHandlers(['channel' => 'daily']))->channelName());
    }

    /**
     * A configured handler is pushed last, so Monolog calls it first.
     *
     * Monolog invokes handlers in reverse registration order and lets one stop
     * propagation, so "last registered runs first" gives the explicitly
     * configured handler the deciding vote — which is what somebody adding one
     * by hand is asking for.
     */
    #[Test]
    public function configured_handlers_come_after_borrowed_ones(): void
    {
        $borrowed = new TestHandler();
        $channel = new MonologLogger('laravel', [$borrowed]);

        $definitions = (new LogHandlers([
            'channel' => 'stack',
            'handlers' => [['class' => NullHandler::class]],
        ], $channel))->all();

        $this->assertSame([
            ['class' => $borrowed],
            ['class' => NullHandler::class],
        ], $definitions);
    }

    #[Test]
    public function it_drops_handler_entries_that_are_not_arrays(): void
    {
        $definitions = (new LogHandlers([
            'handlers' => [['class' => NullHandler::class], 'nope', 42],
        ]))->all();

        $this->assertSame([['class' => NullHandler::class]], $definitions);
    }

    #[Test]
    public function it_ignores_a_handlers_key_that_is_not_a_list(): void
    {
        $this->assertSame([], (new LogHandlers(['handlers' => 'nope']))->all());
    }
}
