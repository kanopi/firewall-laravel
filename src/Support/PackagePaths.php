<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Support;

use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;

/**
 * Locate the installed kanopi/firewall package on disk.
 *
 * Its `presets/` and `bin/` directories are both needed as real paths: presets
 * are passed to `Firewall::create()` as YAML file paths, and the `bin/` scripts
 * are executed as subprocesses by the Artisan wrappers.
 *
 * Derived from the location of `Firewall.php` via reflection rather than
 * assembled from `base_path('vendor/kanopi/firewall')`. The reflected path is
 * correct for every layout the package can actually be installed in — a
 * relocated `vendor-dir`, a Composer path repository pointing at a checkout, a
 * monorepo with the library as a sibling, or a phar — and the assembled one is
 * correct only for the default. The failure mode of guessing is also poor:
 * `presets/wordpress.yml` resolving to a path that does not exist means the
 * library loads no rules and logs about it, which looks like a working
 * firewall.
 */
final class PackagePaths
{
    private static ?string $root = null;

    /**
     * The installed library's root directory.
     */
    public static function root(): string
    {
        // Depth 2: Firewall.php sits at <root>/src/Firewall.php.
        return self::$root ??= self::locate(Firewall::class, 2);
    }

    /**
     * The directory a given number of levels above a class's own file.
     *
     * Public because it is the seam this class is built on and is useful in its
     * own right — locating the package that owns a class is the same question
     * for the library, for a preset directory, and for anything else installed
     * beside them. `$depth` is explicit rather than inferred from the
     * namespace, because how far a class sits below its package root is a fact
     * about that package's layout and not something a class name reveals.
     *
     * @param class-string $class
     *   The class to locate.
     * @param int<1, max> $depth
     *   How many directory levels up from the defining file the root is.
     *
     * @throws IntegrationException
     *   When the class was not defined by a file, which in practice means an
     *   opcache preload with `file_override`, a runtime-evaluated stub, or an
     *   internal class. Refusing is right: the alternative is a guessed path
     *   whose only symptom is silently missing rules, because the library
     *   loads config leniently and a preset it cannot read is an error log
     *   rather than a failure.
     */
    public static function locate(string $class, int $depth = 1): string
    {
        $file = (new \ReflectionClass($class))->getFileName();

        if ($file === false) {
            throw new IntegrationException(sprintf(
                'Unable to locate the package owning %s: it was not defined by a file. '
                . 'Set firewall.artisan.bin_path explicitly.',
                $class
            ));
        }

        return dirname($file, $depth);
    }

    /**
     * The directory holding the shipped rule presets.
     */
    public static function presets(): string
    {
        return self::root() . '/presets';
    }

    /**
     * The directory holding the operational scripts.
     */
    public static function bin(): string
    {
        return self::root() . '/bin';
    }

    /**
     * Forget the resolved root.
     *
     * Only for tests. The path cannot change within a process — reflection on
     * a loaded class is stable — so the cache is safe to hold across Octane
     * requests, and a test that swaps the location needs a way to invalidate it.
     */
    public static function flush(): void
    {
        self::$root = null;
    }
}
