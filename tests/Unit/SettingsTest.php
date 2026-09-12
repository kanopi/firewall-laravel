<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Unit;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\Support\Settings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SettingsTest extends TestCase
{
    #[Test]
    public function it_reads_strings(): void
    {
        $settings = $this->settings(['a' => 'value', 'blank' => '']);

        $this->assertSame('value', $settings->text('a'));
        $this->assertSame('fallback', $settings->text('missing', 'fallback'));
        $this->assertSame('', $settings->text('missing'));
    }

    /**
     * An empty string takes the default rather than being returned.
     *
     * Every string this reads is a name or a path — a view, a channel, a
     * challenge path — and none of them means anything when empty. Returning
     * `''` would push a "did they mean empty or did they mean nothing?" check
     * out to each caller.
     */
    #[Test]
    public function an_empty_string_is_treated_as_absent(): void
    {
        $this->assertSame('fallback', $this->settings(['blank' => ''])->text('blank', 'fallback'));
    }

    /**
     * A value of the wrong type is treated as absent, never coerced.
     *
     * The failure this prevents is specific: `(string) []` is the literal
     * `"Array"`, so a `challenge.secret` mistyped as a list would have read as
     * a five-character secret and signed tokens with it.
     */
    #[Test]
    #[DataProvider('nonStrings')]
    public function a_non_string_is_treated_as_absent(mixed $value): void
    {
        $this->assertSame('fallback', $this->settings(['key' => $value])->text('key', 'fallback'));
    }

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function nonStrings(): array
    {
        return [
            'array' => [['not', 'a', 'string']],
            'int' => [42],
            'bool' => [true],
            'null' => [null],
            'object' => [new \stdClass()],
        ];
    }

    #[Test]
    public function it_reads_flags(): void
    {
        $settings = $this->settings(['on' => true, 'off' => false, 'zero' => 0, 'string' => 'yes']);

        $this->assertTrue($settings->flag('on'));
        $this->assertFalse($settings->flag('off'));
        $this->assertFalse($settings->flag('zero'));
        $this->assertTrue($settings->flag('string'));
        $this->assertTrue($settings->flag('missing', true));
        $this->assertFalse($settings->flag('missing'));
    }

    /**
     * An explicit FALSE must not be mistaken for "not configured".
     *
     * This is the whole reason `tristate()` exists next to `flag()`:
     * `global.behind_proxy` has three meanings, and the library treats an
     * explicit FALSE (asserted: no proxy) differently from an absent value
     * (posture unknown, keep warning).
     */
    #[Test]
    public function tristate_distinguishes_false_from_absent(): void
    {
        $settings = $this->settings(['off' => false, 'on' => true]);

        $this->assertFalse($settings->tristate('off'));
        $this->assertTrue($settings->tristate('on'));
        $this->assertNull($settings->tristate('missing'));
    }

    #[Test]
    public function it_reads_numbers(): void
    {
        $settings = $this->settings(['int' => 7, 'numeric' => '9', 'words' => 'nine']);

        $this->assertSame(7, $settings->number('int'));
        $this->assertSame(9, $settings->number('numeric'));
        $this->assertSame(3, $settings->number('words', 3));
        $this->assertSame(3, $settings->number('missing', 3));
        $this->assertSame(0, $settings->number('missing'));
    }

    #[Test]
    public function it_reads_sections_and_normalises_integer_keys(): void
    {
        $settings = $this->settings(['section' => [0 => 'a', 'named' => 'b'], 'scalar' => 'x']);

        $this->assertSame(['0' => 'a', 'named' => 'b'], $settings->section('section'));
        $this->assertSame([], $settings->section('scalar'));
        $this->assertSame([], $settings->section('missing'));
    }

    #[Test]
    public function it_reads_string_lists_and_drops_everything_else(): void
    {
        $settings = $this->settings(['list' => ['a', 5, '', null, 'b', ['c']], 'scalar' => 'x']);

        $this->assertSame(['a', 'b'], $settings->strings('list'));
        $this->assertSame([], $settings->strings('scalar'));
        $this->assertSame([], $settings->strings('missing'));
    }

    #[Test]
    public function it_reads_lists_of_sections(): void
    {
        $settings = $this->settings([
            'plugins' => [
                ['plugin' => 'A'],
                'not-an-array',
                [0 => 'positional'],
            ],
            'scalar' => 'x',
        ]);

        $this->assertSame(
            [['plugin' => 'A'], ['0' => 'positional']],
            $settings->listOfSections('plugins')
        );
        $this->assertSame([], $settings->listOfSections('scalar'));
    }

    #[Test]
    public function it_exposes_the_raw_value_and_the_repository(): void
    {
        $repository = new Repository(['obj' => $object = new \stdClass()]);
        $settings = new Settings($repository);

        $this->assertSame($object, $settings->raw('obj'));
        $this->assertSame($repository, $settings->repository());
    }

    #[Test]
    public function it_builds_from_a_container(): void
    {
        $container = new Container();
        $container->instance('config', new Repository(['a' => 'b']));

        $this->assertSame('b', Settings::for($container)->text('a'));
    }

    /**
     * A container with no config repository is refused, not tolerated.
     *
     * Returning empty settings would present a firewall configured with
     * nothing as a firewall configured to allow everything — the single worst
     * way for this package to fail.
     */
    #[Test]
    public function it_refuses_a_container_without_a_config_repository(): void
    {
        $container = new Container();
        $container->instance('config', new \stdClass());

        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/not a Illuminate\\\\Contracts\\\\Config\\\\Repository/');

        Settings::for($container);
    }

    /**
     * @param array<string, mixed> $values
     */
    private function settings(array $values): Settings
    {
        return new Settings(new Repository($values));
    }
}
