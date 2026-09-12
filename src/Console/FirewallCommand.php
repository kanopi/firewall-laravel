<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Console;

use Illuminate\Console\Command;
use Kanopi\Firewall\Laravel\Console\Concerns\RunsFirewallBinary;

/**
 * Base for the Artisan wrappers around kanopi/firewall's bin/ scripts.
 *
 * Each subclass declares the options its script actually takes, rather than
 * accepting a free-form argument list and passing it through. That is more code
 * for the same behaviour, and it buys three things an operator notices:
 * `artisan firewall:block --help` describes the command instead of telling them
 * to read the script, a mistyped option is rejected by Artisan rather than
 * reaching the script and being ignored, and shell completion works.
 *
 * The exit codes are the scripts' own, forwarded unchanged, so a deploy step
 * can gate on `php artisan firewall:doctor` exactly as it would on
 * `bin/firewall-doctor`.
 */
abstract class FirewallCommand extends Command
{
    use RunsFirewallBinary;

    /**
     * Nothing wrong, or warnings only.
     */
    public const EXIT_OK = 0;

    /**
     * Something configured is not happening, or the action was refused.
     */
    public const EXIT_ERROR = 1;

    /**
     * The configuration itself could not be read, or the arguments made no sense.
     */
    public const EXIT_CONFIG_UNREADABLE = 2;

    /**
     * Changes are pending — `firewall:migrate --dry-run` only, so a deploy can
     * gate on "the schema is not current" without applying anything.
     */
    public const EXIT_PENDING = 3;
}
