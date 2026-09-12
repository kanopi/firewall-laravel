<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace App\Http\Middleware;

use Illuminate\Http\Middleware\TrustProxies as Middleware;

/**
 * A `TrustProxies` subclass that cannot be constructed without arguments.
 *
 * Applications do subclass this middleware and do give it dependencies, so
 * reading the proxy list off an instance has to survive a constructor it
 * cannot call. The answer is "cannot tell", which leaves the library warning
 * about an unresolved posture — the safe direction, because the alternative is
 * asserting a proxy exists and silencing the warning.
 */
class UnconstructableTrustProxies extends Middleware
{
    public function __construct(private readonly \Closure $needsSomething)
    {
    }
}
