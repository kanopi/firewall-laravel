<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Unit;

use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\Support\PackagePaths;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class PackagePathsTest extends TestCase
{
    protected function tearDown(): void
    {
        PackagePaths::flush();
        parent::tearDown();
    }

    /**
     * The paths are found by reflection, not by guessing at `vendor/`.
     *
     * Asserting the directories actually contain what is expected of them is
     * the point: a path that merely looks plausible but resolves to nothing
     * would make every preset silently fail to load, which the library reports
     * as an error log and otherwise treats as a working firewall.
     */
    #[Test]
    public function it_finds_the_installed_library(): void
    {
        $this->assertDirectoryExists(PackagePaths::root());
        $this->assertFileExists(PackagePaths::root() . '/src/Firewall.php');
    }

    #[Test]
    public function it_finds_the_presets_directory(): void
    {
        $this->assertDirectoryExists(PackagePaths::presets());
        $this->assertFileExists(PackagePaths::presets() . '/wordpress.yml');
    }

    #[Test]
    public function it_finds_the_bin_directory(): void
    {
        $this->assertDirectoryExists(PackagePaths::bin());

        foreach ([
            'firewall-block',
            'firewall-check',
            'firewall-doctor',
            'firewall-init',
            'firewall-log-prune',
            'firewall-migrate',
            'firewall-rule',
            'firewall-sources',
        ] as $script) {
            $this->assertFileExists(PackagePaths::bin() . '/' . $script);
        }
    }

    #[Test]
    public function the_resolved_root_is_cached(): void
    {
        $this->assertSame(PackagePaths::root(), PackagePaths::root());
    }

    #[Test]
    public function it_can_be_flushed(): void
    {
        $first = PackagePaths::root();
        PackagePaths::flush();

        $this->assertSame($first, PackagePaths::root());
    }

    #[Test]
    public function it_locates_the_package_owning_any_class(): void
    {
        // Depth 3, because this class sits at <root>/src/Support/PackagePaths.php
        // — one level deeper than the library's own Firewall.php, which is why
        // the depth is a parameter rather than a constant.
        $this->assertSame(
            \dirname((string) (new \ReflectionClass(PackagePaths::class))->getFileName(), 3),
            PackagePaths::locate(PackagePaths::class, 3)
        );
    }

    /**
     * A class with no file is refused rather than guessed at.
     *
     * An internal class is the reachable version of the real cases — an
     * opcache preload with `file_override`, a runtime-evaluated stub — and the
     * refusal matters because the alternative is a plausible-looking path that
     * resolves to nothing, which makes every preset silently fail to load.
     */
    #[Test]
    public function a_class_with_no_file_is_refused(): void
    {
        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/was not defined by a file/');

        PackagePaths::locate(\ArrayObject::class);
    }
}
