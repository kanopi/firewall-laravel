<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Fixtures;

use Kanopi\Firewall\Storage\BestEffortEnumerationInterface;
use Kanopi\Firewall\Storage\InMemoryStorage;

/**
 * A queryable store whose enumeration index has lost part of itself.
 *
 * Stands in for `MemcachedStorage` (2.33) after an evicted index shard, which
 * reports the gap through `BestEffortEnumerationInterface`. ext-memcached is
 * not installed everywhere this suite runs, and the behaviour under test is
 * how the block commands treat a gap, not how Memcached loses one.
 */
final class GappedStorage extends InMemoryStorage implements BestEffortEnumerationInterface
{
    public function enumerationGap(): ?string
    {
        return 'index shard 7 was evicted';
    }
}
