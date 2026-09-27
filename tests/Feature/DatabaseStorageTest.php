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
use Kanopi\Firewall\Laravel\Console\FirewallCommand;
use Kanopi\Firewall\Laravel\Support\BlockManager;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use Kanopi\Firewall\Storage\DatabaseStorage;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\Attributes\Test;

/**
 * `DatabaseStorage` end to end, on SQLite (#17).
 *
 * The README recommends it for anything on more than one server, with
 * `firewall:migrate` in the deploy — and the rest of the suite runs on
 * `InMemoryStorage`, so nothing exercised the path a multi-server site takes:
 * migrate, earn a block over HTTP, see it from the CLI, lift it.
 */
#[RequiresPhpExtension('pdo_sqlite')]
final class DatabaseStorageTest extends TestCase
{
    private string $database;

    protected function setUp(): void
    {
        parent::setUp();

        $this->database = sys_get_temp_dir() . '/fw-db-' . bin2hex(random_bytes(6)) . '.sqlite';
        touch($this->database);

        config(['firewall.storage' => [
            'type' => DatabaseStorage::class,
            'config' => ['connection' => ['driver' => 'pdo_sqlite', 'path' => $this->database]],
        ]]);

        Route::get('/open', static fn (): string => 'served');
    }

    protected function tearDown(): void
    {
        @unlink($this->database);

        parent::tearDown();
    }

    #[Test]
    public function migrate_block_list_and_lift_against_a_real_database(): void
    {
        $this->artisan('firewall:migrate')->assertExitCode(FirewallCommand::EXIT_OK);

        $this->blockIp('198.51.100.7');

        $blocked = $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.7'])->get('/open');
        $blocked->assertStatus(400);

        $reference = [];
        preg_match('/[0-9A-F]{32}/', (string) $blocked->getContent(), $reference);
        $this->assertNotEmpty($reference, 'The block page carried no reference.');

        // Earned over HTTP, persisted, and visible to a separate reader: the
        // CLI builds its own storage instance, as it would in another process.
        $this->assertArrayHasKey('198.51.100.7', $this->app->make(BlockManager::class)->all());

        $this->artisan('firewall:find-reference', ['reference' => $reference[0]])
            ->expectsOutputToContain('198.51.100.7')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:unblock', ['ip' => '198.51.100.7'])
            ->expectsOutputToContain('Lifted 1 block')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        config(['firewall.plugins' => []]);
        $this->app->forgetInstance(\Kanopi\Firewall\Firewall::class);

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.7'])->get('/open')->assertOk();
    }
}
