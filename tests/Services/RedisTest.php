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
use Kanopi\Firewall\Plugins\RateLimit;
use Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage;
use Kanopi\Firewall\Storage\RedisStorage;
use PHPUnit\Framework\Attributes\Test;

/**
 * The block list and rate limiting on a real Redis (#17).
 */
final class RedisTest extends ServicesTestCase
{
    /**
     * A block earned in one process is enforced by the next, and lifted from the CLI.
     */
    #[Test]
    public function a_block_earned_over_http_is_shared_and_lifted_from_the_cli(): void
    {
        config(['firewall.storage' => ['type' => RedisStorage::class, 'config' => ['redis' => $this->redis()]]]);
        $this->blockIp('198.51.100.7');

        $blocked = $this->requestFrom('198.51.100.7')->assertStatus(400);
        preg_match('/[0-9A-F]{32}/', (string) $blocked->getContent(), $reference);

        // The rule is gone; only the durable list in Redis can refuse this now.
        config(['firewall.plugins' => []]);
        $this->requestFrom('198.51.100.7')->assertStatus(400);
        $this->requestFrom('198.51.100.8')->assertOk();

        $this->assertArrayHasKey('198.51.100.7', $this->app->make(BlockManager::class)->all());

        $this->artisan('firewall:find-reference', ['reference' => $reference[0] ?? ''])
            ->expectsOutputToContain('198.51.100.7')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:unblock', ['ip' => '198.51.100.0/24'])
            ->expectsOutputToContain('Lifted 1 block')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->requestFrom('198.51.100.7')->assertOk();
    }

    /**
     * A rate limit counts across requests in Redis, not per process.
     */
    #[Test]
    public function a_rate_limit_is_counted_across_processes(): void
    {
        config([
            'firewall.storage' => ['type' => RedisStorage::class, 'config' => ['redis' => $this->redis()]],
            'firewall.plugins' => [[
                'plugin' => RateLimit::class,
                'response' => 'block',
                'name' => 'three-per-minute',
                'metadata' => ['storage' => [
                    'type' => RedisRateLimitStorage::class,
                    'config' => ['redis' => $this->redis()],
                ]],
                'config' => [['path' => '/open', 'rate' => 3, 'sample' => 60]],
            ]],
        ]);

        foreach (range(1, 3) as $request) {
            $this->requestFrom('203.0.113.20')->assertOk();
        }

        $this->requestFrom('203.0.113.20')->assertStatus(429);
        $this->requestFrom('203.0.113.21')->assertOk();
    }

    /**
     * An unreachable Redis degrades: requests are served, and health says so.
     */
    #[Test]
    public function an_unreachable_redis_degrades_and_is_reported(): void
    {
        $redis = ['host' => $this->redis()['host'], 'port' => 1, 'connectTimeout' => 1];
        config(['firewall.storage' => ['type' => RedisStorage::class, 'config' => ['redis' => $redis]]]);

        $this->requestFrom('203.0.113.30')->assertOk();

        $this->artisan('firewall:health')
            ->expectsOutputToContain('running without its store')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }
}
