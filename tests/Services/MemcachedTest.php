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
use Kanopi\Firewall\Laravel\Support\BlockManager;
use Kanopi\Firewall\Storage\MemcachedStorage;
use PHPUnit\Framework\Attributes\Test;

/**
 * The block list on a real Memcached (2.33, #17).
 *
 * Memcached cannot list its keys, so everything beyond a single-address
 * lookup runs from the library's sharded index — which the in-process fixture
 * elsewhere in the suite only imitates.
 */
final class MemcachedTest extends ServicesTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['firewall.storage' => ['type' => MemcachedStorage::class, 'config' => ['memcached' => $this->memcached()]]]);
    }

    #[Test]
    public function a_block_earned_over_http_is_found_and_lifted_by_range(): void
    {
        $this->blockIp('198.51.100.7');
        $this->requestFrom('198.51.100.7')->assertStatus(400);

        config(['firewall.plugins' => []]);
        $this->requestFrom('198.51.100.7')->assertStatus(400);

        $this->assertArrayHasKey('198.51.100.7', $this->app->make(BlockManager::class)->all());

        $this->artisan('firewall:unblock', ['ip' => '198.51.100.0/24'])
            ->expectsOutputToContain('Lifted 1 block')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->requestFrom('198.51.100.7')->assertOk();
    }

    /**
     * A ban longer than 30 days survives the write.
     *
     * Memcached reads an expiry over 30 days as a Unix timestamp, so a 90-day
     * ban sent as seconds would be in 1970 and vanish on write. The library
     * converts it; this proves the conversion against a real server through
     * the command an operator would use.
     */
    #[Test]
    public function a_ninety_day_block_survives_the_write(): void
    {
        $this->artisan('firewall:block', ['ip' => '203.0.113.40', '--duration' => (string) (90 * 86400)])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertArrayHasKey('203.0.113.40', $this->app->make(BlockManager::class)->all());
        $this->requestFrom('203.0.113.40')->assertStatus(400);
    }

    #[Test]
    public function the_whole_list_can_be_emptied_while_the_index_is_complete(): void
    {
        $this->artisan('firewall:block', ['ip' => '203.0.113.41'])->assertExitCode(FirewallCommand::EXIT_OK);
        $this->artisan('firewall:block', ['ip' => '203.0.113.42'])->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:unblock', ['--all' => true])
            ->expectsOutputToContain('Lifted 2 blocks')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertSame([], $this->app->make(BlockManager::class)->all());
    }
}
