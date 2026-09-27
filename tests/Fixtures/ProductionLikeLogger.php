<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Fixtures;

use Monolog\Handler\FingersCrossedHandler;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use Monolog\LogRecord;

/**
 * A Laravel `custom` log channel shaped like a real application's.
 *
 * Two things real channels carry and the suite's default (no borrowed
 * handlers at all) never did, each of which broke the firewall (#4):
 *
 *  - **A closure processor**, as a channel `tap` pushes to add a request ID.
 *    A closure cannot be serialized, and the library serializes its config
 *    input to key its cache — so a handler holding one took down every
 *    request.
 *  - **A `FingersCrossedHandler`**, which buffers records until one crosses
 *    its threshold. Serializing a Monolog handler calls `close()`, and closing
 *    this one throws its buffer away.
 *
 * `'closure' => false` in the channel config leaves the processor out, so the
 * second failure can be tested on its own. The inner `TestHandler` is kept
 * statically so a test can read what actually reached the destination.
 */
final class ProductionLikeLogger
{
    public static ?TestHandler $destination = null;

    /**
     * @param array<string, mixed> $config
     */
    public function __invoke(array $config): Logger
    {
        self::$destination = new TestHandler();

        $handler = new FingersCrossedHandler(self::$destination, Level::Error);

        if (($config['closure'] ?? true) === false) {
            return new Logger('fixture', [$handler]);
        }

        $handler->pushProcessor(static function (LogRecord $record): LogRecord {
            $record->extra['request_id'] = 'fixture';

            return $record;
        });

        return new Logger('fixture', [$handler]);
    }
}
