<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Kanopi\Firewall\Laravel\Tests\Fixtures\ProductionLikeLogger;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * The firewall borrowing handlers off a real-shaped Laravel log channel (#4).
 *
 * The rest of the suite switches borrowing off, which is how both failures
 * below went unnoticed: nothing ever handed the library a live handler.
 */
final class BorrowedLogHandlersTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'logging.channels.production_like' => [
                'driver' => 'custom',
                'via' => ProductionLikeLogger::class,
            ],
            'firewall.logger.channel' => 'production_like',
        ]);

        Route::get('/open', static fn (): string => 'served');
    }

    /**
     * A handler holding a closure must not stop the firewall from building.
     *
     * It used to throw "Serialization of 'Closure' is not allowed" out of
     * `Firewall::create()` — not a `FirewallException`, so no fail-open policy
     * caught it, and every request was a 500.
     */
    #[Test]
    public function a_closure_processor_does_not_take_requests_down(): void
    {
        $this->blockIp('198.51.100.9');

        $this->get('/open')->assertOk()->assertSee('served');

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.9'])
            ->get('/open')
            ->assertStatus(400);
    }

    /**
     * The firewall's records reach the borrowed destination, processor applied.
     */
    #[Test]
    public function firewall_records_reach_the_borrowed_handler(): void
    {
        $this->blockIp('198.51.100.9', ['name' => 'borrowed-log-test']);

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.9'])->get('/open');

        // A block is logged below the FingersCrossed threshold, so force the
        // buffer out the way a real error would.
        Log::channel('production_like')->error('flush');

        $destination = ProductionLikeLogger::$destination;
        $this->assertNotNull($destination);

        $firewallRecords = array_filter(
            $destination->getRecords(),
            static fn ($record): bool => $record->channel === 'firewall'
        );

        $this->assertNotEmpty($firewallRecords, 'No firewall record reached the borrowed handler.');
        $this->assertSame('fixture', array_values($firewallRecords)[0]->extra['request_id'] ?? null);
    }

    /**
     * Building the firewall must not close the application's own handlers.
     *
     * Serializing a Monolog handler calls `close()`, and a closed
     * `FingersCrossedHandler` discards what it had buffered — so a debug line
     * the application logged before the firewall ran vanished instead of being
     * flushed when an error arrived.
     */
    #[Test]
    public function the_applications_buffered_records_survive_the_firewall(): void
    {
        // No closure, so this fails on the close() alone rather than on the
        // serialization error the test above covers.
        config(['logging.channels.production_like.closure' => false]);

        Log::channel('production_like')->debug('logged before the firewall ran');

        $this->get('/open')->assertOk();

        Log::channel('production_like')->error('an error that flushes the buffer');

        $destination = ProductionLikeLogger::$destination;
        $this->assertNotNull($destination);
        $this->assertTrue(
            $destination->hasDebugThatContains('logged before the firewall ran'),
            'The buffered record was discarded: the firewall closed the application\'s handler.'
        );
    }
}
