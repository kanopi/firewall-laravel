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
 * A stand-in for the `TrustProxies` a Laravel 10 application generates.
 *
 * Placed under the `App\` namespace on purpose: `TrustedProxies` looks for
 * exactly this class, because that is where Laravel 10 and earlier kept the
 * trusted-proxy list — as a property on a generated middleware rather than in
 * config. Supporting it is not optional if this package claims Laravel 10.
 *
 * `$proxies` is left NULL, which is what the generated file contains, so its
 * mere presence changes nothing for any other test.
 */
class TrustProxies extends Middleware
{
    /**
     * @var array<int, string>|string|null
     */
    protected $proxies;

    /**
     * Set the proxy list, as an application would by editing this file.
     *
     * @param array<int, string>|string|null $proxies
     */
    public function setProxies(array|string|null $proxies): void
    {
        $this->proxies = $proxies;
    }
}
