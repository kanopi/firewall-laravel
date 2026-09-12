<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Fixtures;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * A Laravel `custom` log driver that returns a logger Monolog knows nothing about.
 *
 * Exists to reach one branch of `LogHandlers`: a channel that resolves fine and
 * yields no Monolog handlers. Naming a channel that does not exist does not
 * reach it — Laravel falls back to its emergency logger, which does have a
 * handler — so the only way there is a channel backed by a non-Monolog PSR-3
 * logger, which is exactly what a `custom` driver is allowed to return.
 */
final class HandlerlessLogger
{
    /**
     * @param array<string, mixed> $config
     */
    public function __invoke(array $config): LoggerInterface
    {
        return new NullLogger();
    }
}
