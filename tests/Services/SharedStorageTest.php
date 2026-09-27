<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Services;

use Kanopi\Firewall\Laravel\Console\FirewallCommand;
use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Storage\RedisStorage;
use Kanopi\Firewall\Storage\SharedStorage;
use PHPUnit\Framework\Attributes\Test;

/**
 * `SharedStorage` over a real Redis, with a file store underneath (2.29, #17).
 */
final class SharedStorageTest extends ServicesTestCase
{
    private string $directory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->directory = sys_get_temp_dir() . '/fw-shared-' . bin2hex(random_bytes(6));
        mkdir($this->directory);
    }

    protected function tearDown(): void
    {
        foreach (array_filter((array) glob($this->directory . '/*'), 'is_string') as $file) {
            @unlink($file);
        }

        @rmdir($this->directory);

        parent::tearDown();
    }

    /**
     * A block reaches the fleet through Redis, and is mirrored locally.
     */
    #[Test]
    public function a_block_is_shared_and_mirrored_locally(): void
    {
        $this->useSharedStorage($this->redis());

        $this->artisan('firewall:block', ['ip' => '203.0.113.50'])
            ->doesntExpectOutputToContain('local copy only')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        // Read each side on its own, as another node and this node's fallback would.
        $shared = new RedisStorage(['redis' => $this->redis()]);
        $local = new FileStorage($this->localConfig());

        $this->assertNotFalse($shared->isBlocked('203.0.113.50'));
        $this->assertNotFalse($local->isBlocked('203.0.113.50'));
    }

    /**
     * With Redis unreachable, blocks still land and are enforced — locally, and said so.
     */
    #[Test]
    public function an_unreachable_shared_store_falls_back_and_says_so(): void
    {
        $this->useSharedStorage(['host' => $this->redis()['host'], 'port' => 1, 'connectTimeout' => 1]);

        $this->artisan('firewall:block', ['ip' => '203.0.113.51'])
            ->expectsOutputToContain('local copy only')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->requestFrom('203.0.113.51')->assertStatus(400);
        $this->requestFrom('203.0.113.52')->assertOk();

        $this->artisan('firewall:health')
            ->expectsOutputToContain('shared block list')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * @param array<string, mixed> $redis
     */
    private function useSharedStorage(array $redis): void
    {
        config(['firewall.storage' => [
            'type' => SharedStorage::class,
            'config' => [
                'shared' => ['type' => RedisStorage::class, 'config' => ['redis' => $redis]],
                'local' => ['type' => FileStorage::class, 'config' => $this->localConfig()],
            ],
        ]]);
    }

    /**
     * @return array{storage_file: string, offense_file: string}
     */
    private function localConfig(): array
    {
        return [
            'storage_file' => $this->directory . '/blocked.data',
            'offense_file' => $this->directory . '/offenses.data',
        ];
    }
}
