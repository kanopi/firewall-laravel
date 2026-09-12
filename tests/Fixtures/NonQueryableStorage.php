<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Fixtures;

use Kanopi\Firewall\Storage\AbstractStorageBase;

/**
 * A storage backend that cannot be asked questions.
 *
 * Every backend the library ships implements `QueryableStorageInterface`, so
 * the branch that refuses to list or lift blocks is unreachable without a
 * backend of its own. That branch matters: a non-queryable backend answers
 * every read with an empty list, so a lift would report "0 removed" and a
 * reference lookup "no such reference" — both of which read as an answer rather
 * than as an inability to answer.
 *
 * Extends `AbstractStorageBase`, which implements only `StorageInterface`.
 * Extending `InMemoryStorage` was the first attempt and does not work: it
 * implements `QueryableStorageInterface` and a subclass inherits that.
 *
 * The nine methods below are the ones `AbstractStorageBase` declares through
 * the interface and leaves to its subclasses — omitting them is a fatal error,
 * not a warning, which is a slow thing to diagnose because PHPUnit reports it
 * as "premature end of PHP process". They are deliberately inert: this fixture
 * exists to be refused before any of them is reached, so implementing them
 * with real behaviour would be implying a contract nothing tests.
 */
final class NonQueryableStorage extends AbstractStorageBase
{
    public function set(string $key, array $value, int $expire = 0): bool
    {
        return false;
    }

    public function delete(string $key): bool
    {
        return false;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $default;
    }

    public function reset(): bool
    {
        return false;
    }

    public function exists(string $key): bool
    {
        return false;
    }

    public function expire(): bool
    {
        return false;
    }

    public function addToExpire(string $key, int $amount): bool
    {
        return false;
    }

    public function recordOffense(string $key): bool
    {
        return false;
    }

    public function countOffenses(string $key, int $start = 0, int $end = PHP_INT_MAX): int
    {
        return 0;
    }
}
