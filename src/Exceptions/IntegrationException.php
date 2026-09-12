<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Exceptions;

use Kanopi\Firewall\Exception\FirewallException;

/**
 * A problem with the Laravel integration itself, not with the firewall.
 *
 * Extends the library's own base exception rather than `\RuntimeException`
 * directly, so a host that already catches `FirewallException` — which the
 * library's documentation says is always safe to catch — keeps catching
 * everything the firewall can throw, including the parts added here. The
 * alternative was a separate hierarchy, which would have meant every
 * integrator's existing catch block silently stopped being exhaustive the day
 * they installed this package.
 *
 * Thrown for the cases the library cannot see: a preset name that does not
 * resolve, a mode this integration cannot deliver, a forced override that did
 * not land, or middleware ordering that leaves every IP rule spoofable.
 */
final class IntegrationException extends FirewallException
{
}
