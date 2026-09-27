<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Services;

use Illuminate\Support\Facades\Route;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use Kanopi\Firewall\Utility\DegradedBackends;

/**
 * Tests that run against real Redis and Memcached servers (#17).
 *
 * The default suites use in-memory storage and in-process fakes, which prove
 * this package's logic and nothing about what a shared store does across
 * processes: a block earned by one PHP process and enforced by another, a rate
 * limit counted across requests, a shared list that goes away mid-flight.
 *
 * Pointed at servers through `REDIS_HOST`/`REDIS_PORT` and
 * `MEMCACHED_HOST`/`MEMCACHED_PORT`, the same variables the library's own suite
 * reads. A missing server or extension skips — unless
 * `FIREWALL_SERVICES_REQUIRED=1`, which CI and `composer test:services` set, so
 * a broken environment fails instead of passing on nothing.
 *
 * Every test gets its own key prefix, so runs never see each other's data and
 * nothing has to be flushed.
 */
abstract class ServicesTestCase extends TestCase
{
    protected string $prefix;

    protected function setUp(): void
    {
        parent::setUp();

        $this->prefix = 'fw-laravel-test:' . bin2hex(random_bytes(6)) . ':';
        DegradedBackends::reset();

        Route::get('/open', static fn (): string => 'served');
    }

    protected function tearDown(): void
    {
        DegradedBackends::reset();

        parent::tearDown();
    }

    /**
     * @return array{host: string, port: int, prefix: string}
     */
    protected function redis(): array
    {
        $this->requireService('redis', 'REDIS_HOST');

        return [
            'host' => (string) getenv('REDIS_HOST'),
            'port' => (int) (getenv('REDIS_PORT') ?: 6379),
            'prefix' => $this->prefix,
        ];
    }

    /**
     * @return array{host: string, port: int, prefix: string}
     */
    protected function memcached(): array
    {
        $this->requireService('memcached', 'MEMCACHED_HOST');

        return [
            'host' => (string) getenv('MEMCACHED_HOST'),
            'port' => (int) (getenv('MEMCACHED_PORT') ?: 11211),
            'prefix' => $this->prefix,
        ];
    }

    /**
     * Build the next firewall from scratch, as the next PHP process would.
     *
     * The binding is scoped, and within one test application it would
     * otherwise be reused — which would let in-process state stand in for the
     * shared store under test.
     */
    protected function nextProcess(): void
    {
        $this->app->forgetInstance(Firewall::class);
        $this->app->forgetScopedInstances();
    }

    protected function requestFrom(string $ip): \Illuminate\Testing\TestResponse
    {
        $this->nextProcess();

        return $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/open');
    }

    private function requireService(string $extension, string $hostVariable): void
    {
        $problem = match (true) {
            !extension_loaded($extension) => sprintf('ext-%s is not loaded', $extension),
            (string) getenv($hostVariable) === '' => sprintf('%s is not set', $hostVariable),
            default => null,
        };

        if ($problem === null) {
            return;
        }

        if (getenv('FIREWALL_SERVICES_REQUIRED') === '1') {
            $this->fail(sprintf('The services suite requires %s: %s.', $extension, $problem));
        }

        $this->markTestSkipped(sprintf('%s. Run `composer test:services` to use Docker.', ucfirst($problem)));
    }
}
