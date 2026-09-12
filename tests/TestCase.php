<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests;

use Illuminate\Http\Middleware\TrustProxies;
use Kanopi\Firewall\Laravel\FirewallServiceProvider;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Utility\Config;
use Orchestra\Testbench\TestCase as Orchestra;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

/**
 * Base for the feature suite.
 *
 * Two pieces of shared setup are not conveniences and are worth naming:
 *
 *  - **Storage defaults to `InMemoryStorage`.** The shipped config uses
 *    `FileStorage` under `storage_path()`, which would have every test in this
 *    suite reading and writing one file — so a block recorded by one test would
 *    be in force for the next, and the order tests happened to run in would
 *    decide whether they passed. `FileStorage` gets its own tests with its own
 *    temporary path.
 *  - **Static state is reset between tests.** The library holds process-wide
 *    state that a normal request never has to think about: Symfony's trusted
 *    proxies live on the `Request` class, Laravel's `TrustProxies` keeps its
 *    always-trust list in a static, and the library caches merged
 *    configuration per file set. Left alone, a test that sets trusted proxies
 *    would silently fix the ordering bug that a later test is trying to prove.
 */
abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->resetStaticState();
    }

    protected function tearDown(): void
    {
        $this->resetStaticState();

        parent::tearDown();
    }

    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [FirewallServiceProvider::class];
    }

    /**
     * @param \Illuminate\Foundation\Application $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('firewall.storage', ['type' => InMemoryStorage::class]);
        $app['config']->set('firewall.logger.channel', null);
    }

    /**
     * Forget everything the library and the framework keep in statics.
     */
    protected function resetStaticState(): void
    {
        SymfonyRequest::setTrustedProxies([], SymfonyRequest::HEADER_X_FORWARDED_FOR);
        TrustProxies::flushState();
        Config::clearLoadErrors();
    }

    /**
     * Configure one rule that blocks an address, and nothing else.
     *
     * @param array<string, mixed> $overrides
     */
    protected function blockIp(string $ip, array $overrides = []): void
    {
        config(['firewall.plugins' => [array_merge([
            'plugin' => \Kanopi\Firewall\Plugins\IpAddress::class,
            'response' => 'block',
            'name' => 'test-block',
            'config' => [$ip],
        ], $overrides)]]);
    }
}
