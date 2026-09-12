<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Unit;

use Kanopi\Firewall\Laravel\Support\StorageDirectories;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Creating the storage directories this package's own defaults point at.
 *
 * `FileStorage` creates its data file but not the directory holding it, and the
 * published config defaults to `storage/firewall/`. Without this, publishing
 * the config and making one request produced a 500 — on every request, because
 * the default boot-failure policy is fail-closed. That was a real defect found
 * by installing the package into a Laravel application rather than by running
 * the test suite, which is why there is now a test for it.
 */
final class StorageDirectoriesTest extends TestCase
{
    private string $storage;

    protected function setUp(): void
    {
        parent::setUp();

        $this->storage = sys_get_temp_dir() . '/fw-storage-' . bin2hex(random_bytes(6));
        mkdir($this->storage);
    }

    protected function tearDown(): void
    {
        $this->deleteRecursively($this->storage);

        parent::tearDown();
    }

    #[Test]
    public function it_creates_the_directory_holding_the_block_list(): void
    {
        $this->directories()->ensureFor([
            'config' => ['storage_file' => $this->storage . '/firewall/blocked.data'],
        ]);

        $this->assertDirectoryExists($this->storage . '/firewall');
    }

    /**
     * Two levels deep, because that is the shipped default's shape.
     */
    #[Test]
    public function it_creates_nested_directories(): void
    {
        $this->directories()->ensureFor([
            'config' => ['storage_file' => $this->storage . '/a/b/c/blocked.data'],
        ]);

        $this->assertDirectoryExists($this->storage . '/a/b/c');
    }

    #[Test]
    public function it_creates_directories_for_every_file_setting(): void
    {
        $this->directories()->ensureFor([
            'config' => [
                'storage_file' => $this->storage . '/blocks/blocked.data',
                'offense_file' => $this->storage . '/offenses/offenses.data',
                'file' => $this->storage . '/ratelimit/counts.data',
            ],
        ]);

        $this->assertDirectoryExists($this->storage . '/blocks');
        $this->assertDirectoryExists($this->storage . '/offenses');
        $this->assertDirectoryExists($this->storage . '/ratelimit');
    }

    /**
     * The guarantee is that the directory exists and is writable here.
     *
     * Not that it carries a particular mode: `mkdir()` requests 0775 and the
     * process umask reduces it, so asserting on the bits would be asserting on
     * the umask of whoever ran the suite. The mode that matters on a
     * deployment where `artisan` and php-fpm run as different users is checked
     * where it can actually be checked — `php artisan firewall:doctor` reports
     * the storage path as writable or not.
     */
    #[Test]
    public function the_created_directory_is_writable(): void
    {
        $this->directories()->ensureFor([
            'config' => ['storage_file' => $this->storage . '/firewall/blocked.data'],
        ]);

        $this->assertDirectoryIsWritable($this->storage . '/firewall');
    }

    /**
     * A path outside the storage path is left alone, and reported instead.
     *
     * An operator who chose `/var/lib/firewall` wants to hear that it does not
     * exist, not to have a directory appear somewhere they did not ask for —
     * and the web user usually cannot write there anyway.
     * `php artisan firewall:doctor` names the directory and the setting.
     */
    #[Test]
    public function it_leaves_a_path_outside_the_storage_path_alone(): void
    {
        $elsewhere = sys_get_temp_dir() . '/fw-elsewhere-' . bin2hex(random_bytes(6));

        $this->directories()->ensureFor([
            'config' => ['storage_file' => $elsewhere . '/blocked.data'],
        ]);

        $this->assertDirectoryDoesNotExist($elsewhere);
    }

    /**
     * A traversal out of the storage path is judged on where it lands.
     *
     * `realpath()` is no use for this — the directory does not exist yet, which
     * is the entire reason the question is being asked — so the comparison
     * resolves `..` itself.
     */
    #[Test]
    public function it_resolves_traversal_before_deciding(): void
    {
        $escaped = $this->storage . '/../fw-escaped-' . bin2hex(random_bytes(6));

        $this->directories()->ensureFor([
            'config' => ['storage_file' => $escaped . '/blocked.data'],
        ]);

        $this->assertDirectoryDoesNotExist($escaped);
    }

    /**
     * A directory whose name merely starts with the storage path is outside it.
     *
     * `storage` and `storage-backup` share a prefix and share nothing else, so
     * the comparison is on path segments rather than on characters.
     */
    #[Test]
    public function a_sibling_sharing_a_name_prefix_is_outside(): void
    {
        $sibling = $this->storage . '-backup';

        $this->directories()->ensureFor([
            'config' => ['storage_file' => $sibling . '/blocked.data'],
        ]);

        $this->assertDirectoryDoesNotExist($sibling);
    }

    #[Test]
    public function an_existing_directory_is_left_untouched(): void
    {
        mkdir($this->storage . '/firewall');
        $before = fileperms($this->storage . '/firewall');

        $this->directories()->ensureFor([
            'config' => ['storage_file' => $this->storage . '/firewall/blocked.data'],
        ]);

        $this->assertSame($before, fileperms($this->storage . '/firewall'));
    }

    /**
     * Only the settings that name a file are treated as paths.
     *
     * A DSN, a table name and a Redis prefix are strings too, and creating a
     * directory named after a database would be a memorable bug.
     */
    #[Test]
    public function it_ignores_settings_that_are_not_file_paths(): void
    {
        $this->directories()->ensureFor([
            'type' => \Kanopi\Firewall\Storage\DatabaseStorage::class,
            'config' => [
                'storage_table' => 'firewall_blocked_ips',
                'connection' => ['dsn' => 'mysql://user:pass@localhost/app'],
            ],
        ]);

        $this->assertSame([], $this->childrenOf($this->storage));
    }

    /**
     * @param array<string, mixed> $storage
     */
    #[Test]
    #[DataProvider('nothingToDo')]
    public function it_does_nothing_for_a_configuration_without_file_paths(array $storage): void
    {
        $this->directories()->ensureFor($storage);

        $this->assertSame([], $this->childrenOf($this->storage));
    }

    /**
     * @return array<string, array{0: array<string, mixed>}>
     */
    public static function nothingToDo(): array
    {
        return [
            'no config key' => [['type' => 'Some\Storage']],
            'config is not an array' => [['config' => 'nope']],
            'config is empty' => [['config' => []]],
            'path is empty' => [['config' => ['storage_file' => '']]],
            'path is not a string' => [['config' => ['storage_file' => ['a']]]],
            'entirely empty' => [[]],
        ];
    }

    /**
     * With no storage path to compare against, nothing is created.
     *
     * Belt and braces for a container whose `storagePath()` is empty: the
     * boundary check has nothing to permit, so it permits nothing rather than
     * treating every path as inside.
     */
    #[Test]
    public function an_empty_storage_path_permits_nothing(): void
    {
        $target = $this->storage . '/firewall';

        (new StorageDirectories(''))->ensureFor([
            'config' => ['storage_file' => $target . '/blocked.data'],
        ]);

        $this->assertDirectoryDoesNotExist($target);
    }

    private function directories(): StorageDirectories
    {
        return new StorageDirectories($this->storage);
    }

    /**
     * @return array<int, string>
     */
    private function childrenOf(string $directory): array
    {
        $found = array_diff((array) scandir($directory), ['.', '..']);

        return array_values(array_map(strval(...), $found));
    }

    private function deleteRecursively(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }

        foreach ($this->childrenOf($path) as $child) {
            $full = $path . '/' . $child;
            is_dir($full) ? $this->deleteRecursively($full) : @unlink($full);
        }

        @rmdir($path);
    }
}
