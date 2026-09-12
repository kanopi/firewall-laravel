<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Support;

/**
 * Create the storage directories this package's own defaults point at.
 *
 * `FileStorage` creates its data file but not the directory holding it, so a
 * freshly published `config/firewall.php` — which defaults to
 * `storage/firewall/` — would refuse to start, and with the default fail-closed
 * policy that means every request 500s until somebody runs `mkdir`. A package
 * whose install instructions are "publish the config" has to work after
 * publishing the config.
 *
 * ## Only inside the application's storage path
 *
 * The rule is narrow on purpose: directories are created only for paths under
 * `storage_path()`. That covers exactly what this package suggested and
 * therefore owns. A path an operator pointed somewhere else — `/var/lib/firewall`,
 * a mounted volume — is theirs to provision, and silently creating directories
 * outside the application tree is both surprising and usually impossible
 * anyway, because the web user has no business writing there.
 *
 * A path outside `storage_path()` that does not exist is left alone and
 * reported by `php artisan firewall:doctor`, which names the directory and the
 * setting. That is the better failure: an operator who chose a path wants to
 * hear that it is wrong, not to have a different directory appear somewhere
 * they did not ask for.
 *
 * ## Best effort, deliberately
 *
 * Nothing here throws. If the directory cannot be created, `Firewall::create()`
 * fails immediately afterwards with `StorageException` — which names the file,
 * the reason and the documentation page, and is a better message than anything
 * this class could raise about a `mkdir` that returned false.
 */
final class StorageDirectories
{
    /**
     * @param string $storagePath
     *   The application's `storage_path()`, the boundary of what this will
     *   create in.
     */
    public function __construct(private readonly string $storagePath)
    {
    }

    /**
     * Create the directories a storage configuration needs.
     *
     * @param array<string, mixed> $storage
     *   The `firewall.storage` section: `type` and `config`.
     */
    public function ensureFor(array $storage): void
    {
        $config = $storage['config'] ?? null;

        if (!is_array($config)) {
            return;
        }

        // Keyed by the settings that name a file rather than by walking every
        // string in the section: a DSN, a table name and a Redis prefix are all
        // strings too, and treating one of those as a path would create a
        // directory named after a database.
        foreach (['storage_file', 'offense_file', 'file'] as $key) {
            $path = $config[$key] ?? null;

            if (is_string($path) && $path !== '') {
                $this->ensureDirectoryFor($path);
            }
        }
    }

    /**
     * Create the parent directory of a file, if it is ours to create.
     */
    private function ensureDirectoryFor(string $file): void
    {
        $directory = dirname($file);

        if (is_dir($directory) || !$this->isWithinStoragePath($directory)) {
            return;
        }

        // Recursive, because the shipped default is two levels below
        // storage_path() on a fresh install and neither level exists yet.
        //
        // 0775 is requested rather than guaranteed: the process umask is
        // applied to it, so a host with the usual 022 gets 0755 and the group
        // write bit is dropped. That is left alone deliberately — the umask is
        // the administrator's stated policy, and a package forcing a chmod
        // past it is making a permissions decision on their behalf. It matters
        // on a deployment where `artisan` and php-fpm run as different users
        // sharing a group: there, a directory created by a deploy step may not
        // be writable by the web user, and `php artisan firewall:doctor`
        // reports it as not writable rather than letting the first request
        // find out.
        @mkdir($directory, 0775, true);
    }

    /**
     * Is this directory inside the application's storage path?
     *
     * Compared after resolving `..` segments, so a configured path of
     * `storage/../../elsewhere` is correctly judged to be outside. `realpath()`
     * is no use here — the directory does not exist yet, which is the entire
     * reason this is being asked.
     */
    private function isWithinStoragePath(string $directory): bool
    {
        $storage = $this->normalise($this->storagePath);

        if ($storage === '') {
            return false;
        }

        return str_starts_with($this->normalise($directory) . '/', $storage . '/');
    }

    /**
     * Reduce a path to a comparable absolute form without touching the disk.
     */
    private function normalise(string $path): string
    {
        $absolute = str_starts_with($path, '/');
        $segments = [];

        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }

            if ($segment === '..') {
                array_pop($segments);

                continue;
            }

            $segments[] = $segment;
        }

        return ($absolute ? '/' : '') . implode('/', $segments);
    }
}
