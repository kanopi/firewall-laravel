<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Config;

use Illuminate\Log\Logger as IlluminateLogger;
use Monolog\Logger as MonologLogger;
use Psr\Log\LoggerInterface;

/**
 * Resolve the firewall's Monolog handlers from a Laravel log channel.
 *
 * Both sides of this are Monolog, which makes the bridge much smaller than it
 * looks. `LoggingFactory::create()` accepts either a handler class name plus
 * constructor arguments, or a ready-made `HandlerInterface` **instance** — and
 * a Laravel channel is a Monolog logger whose handlers can be read straight
 * off it. So the whole bridge is: borrow the handlers, hand them over as
 * instances.
 *
 * Why borrow them rather than have the firewall open its own log file:
 *
 * - A second log file has a second rotation policy, a second set of
 *   permissions, and a second place to forget to ship to the log aggregator.
 *   In a container it is usually a file nobody ever reads, because the platform
 *   collects stdout and the firewall was writing to `storage/logs`.
 * - Firewall records still arrive under the Monolog channel name `firewall`,
 *   which the library sets, so they stay filterable from application records
 *   on the same stream.
 *
 * The trade-off accepted here is that the firewall's records go through the
 * *handlers*, not through Laravel's `Logger` wrapper, so Laravel's context
 * processors and `Log::withContext()` do not apply to them. The alternative was
 * to write an adapter handler delegating to `Illuminate\Log\Logger`, which
 * would pick those up — and lose the level filtering and formatting configured
 * on the channel, because a delegating handler has to accept every record to
 * pass it on. Filtering and formatting are what a log channel is configured
 * for; `withContext()` is set by application code that is not running when the
 * firewall evaluates.
 */
final class LogHandlers
{
    /**
     * @param array<string, mixed> $loggerConfig
     *   The `firewall.logger` section: a `channel` name to borrow from and/or
     *   a list of `handlers` in the library's own format.
     * @param ?LoggerInterface $channel
     *   The resolved Laravel channel, or NULL when none was configured or the
     *   channel could not be resolved. Injected rather than resolved here so
     *   this class needs no container and no facade root.
     */
    public function __construct(
        private readonly array $loggerConfig,
        private readonly ?LoggerInterface $channel = null
    ) {
    }

    /**
     * Handler definitions for the library's `logger:` section.
     *
     * Borrowed handlers come first so that an explicitly configured handler is
     * pushed last. Monolog calls handlers in reverse order of registration and
     * lets one stop propagation, so "last registered runs first" makes the
     * explicit handler the one that gets to decide — which is what somebody
     * adding a handler by hand is asking for.
     *
     * @return array<int, array<string, mixed>>
     */
    public function all(): array
    {
        $definitions = [];

        foreach ($this->borrowedHandlers() as $handler) {
            $definitions[] = ['class' => $handler];
        }

        foreach ($this->configuredHandlers() as $handler) {
            $definitions[] = $handler;
        }

        return $definitions;
    }

    /**
     * The channel name this was asked to borrow from, if any.
     */
    public function channelName(): ?string
    {
        $name = $this->loggerConfig['channel'] ?? null;

        return is_string($name) && $name !== '' ? $name : null;
    }

    /**
     * Handlers read off the Laravel channel.
     *
     * @return array<int, \Monolog\Handler\HandlerInterface>
     */
    private function borrowedHandlers(): array
    {
        $monolog = $this->monolog();

        return $monolog instanceof MonologLogger ? $monolog->getHandlers() : [];
    }

    /**
     * Unwrap Laravel's channel down to the Monolog logger inside it.
     *
     * `Illuminate\Log\Logger` is a PSR-3 decorator, not a Monolog logger, so
     * asking it for handlers directly gets nothing. A channel on a driver that
     * is not Monolog-backed — a custom driver returning some other PSR-3
     * logger — yields NULL, and the firewall then logs nowhere rather than
     * failing to boot. That is the right way round: a log destination is not
     * worth refusing traffic over, and `firewall:doctor` reports a firewall
     * with no handlers.
     */
    private function monolog(): ?MonologLogger
    {
        $logger = $this->channel;

        if ($logger instanceof IlluminateLogger) {
            $logger = $logger->getLogger();
        }

        return $logger instanceof MonologLogger ? $logger : null;
    }

    /**
     * Handler definitions written out in `firewall.logger.handlers`.
     *
     * @return array<int, array<string, mixed>>
     */
    private function configuredHandlers(): array
    {
        $handlers = $this->loggerConfig['handlers'] ?? [];

        if (!is_array($handlers)) {
            return [];
        }

        /** @var array<int, array<string, mixed>> */
        return array_values(array_filter($handlers, is_array(...)));
    }
}
