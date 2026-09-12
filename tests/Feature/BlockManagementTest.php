<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Kanopi\Firewall\Laravel\Console\FirewallCommand;
use Kanopi\Firewall\Laravel\Exceptions\IntegrationException;
use Kanopi\Firewall\Laravel\Support\BlockManager;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use Kanopi\Firewall\Laravel\Tests\Fixtures\NonQueryableStorage;
use Kanopi\Firewall\Storage\FileStorage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * `firewall:block`, `firewall:unblock` and `firewall:find-reference`.
 *
 * These three are the operations the library's own `bin/` scripts do not
 * provide, so unlike every other command in this package they are real code
 * rather than a forwarded subprocess — which is exactly why they need tests of
 * their own rather than a smoke test that the arguments were assembled.
 *
 * Run against `FileStorage` on a temporary path rather than the suite's usual
 * `InMemoryStorage`. In-memory storage is per-process, and these commands write
 * in one process and are asserted in another — through `artisan`, whose
 * container is the same but whose storage instance need not be. A file makes
 * the durability the commands are about actually observable.
 */
final class BlockManagementTest extends TestCase
{
    private string $storageFile;

    protected function setUp(): void
    {
        $this->storageFile = sys_get_temp_dir() . '/fw-blocks-' . bin2hex(random_bytes(6)) . '.data';

        parent::setUp();

        config(['firewall.storage' => [
            'type' => FileStorage::class,
            'config' => [
                'storage_file' => $this->storageFile,
                'offense_file' => $this->storageFile . '.offenses',
            ],
        ]]);
    }

    protected function tearDown(): void
    {
        foreach ([$this->storageFile, $this->storageFile . '.offenses'] as $file) {
            if (is_file($file)) {
                unlink($file);
            }

            if (is_file($file . '.lock')) {
                unlink($file . '.lock');
            }
        }

        parent::tearDown();
    }

    #[Test]
    public function it_blocks_an_address(): void
    {
        $this->artisan('firewall:block', ['ip' => '203.0.113.9'])
            ->expectsOutputToContain('Blocked 203.0.113.9')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertArrayHasKey('203.0.113.9', $this->manager()->all());
    }

    /**
     * The block takes effect on the next request, with no deploy.
     *
     * This is the assertion that makes the command worth having: a durable
     * block is enforced by the middleware's storage check, ahead of every rule.
     */
    #[Test]
    public function a_manually_blocked_client_is_refused_by_the_middleware(): void
    {
        \Illuminate\Support\Facades\Route::get('/probe', static fn (): string => 'through');

        $this->get('/probe')->assertOk();

        $this->artisan('firewall:block', ['ip' => '127.0.0.1'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->get('/probe')->assertStatus(400)->assertDontSee('through');
    }

    #[Test]
    public function it_records_a_reason_and_reports_a_reference(): void
    {
        $this->artisan('firewall:block', [
            'ip' => '203.0.113.9',
            '--reason' => 'Scraping /api',
        ])
            ->expectsOutputToContain('Reference')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $record = $this->manager()->all()['203.0.113.9'];

        $this->assertSame('Scraping /api', $this->manager()->payloadValue($record, 'reason'));
        $this->assertSame('firewall:block', $this->manager()->payloadValue($record, 'blocked_by'));
        $this->assertNotSame('', $this->manager()->referenceOf($record));
    }

    /**
     * `--duration=0` blocks until somebody lifts it.
     *
     * The backend treats the value as a duration and `0` as "no expiry", which
     * is the opposite of how a timestamp would read — so this asserts the
     * mapping rather than trusting it.
     */
    #[Test]
    public function a_zero_duration_blocks_indefinitely(): void
    {
        $this->artisan('firewall:block', ['ip' => '203.0.113.9', '--duration' => '0'])
            ->expectsOutputToContain('never')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertSame(0, $this->manager()->all()['203.0.113.9']['expire']);
    }

    #[Test]
    public function a_duration_sets_an_expiry_in_the_future(): void
    {
        $this->artisan('firewall:block', ['ip' => '203.0.113.9', '--duration' => '600'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $expire = $this->manager()->all()['203.0.113.9']['expire'];

        $this->assertIsInt($expire);
        $this->assertGreaterThan(time() + 500, $expire);
        $this->assertLessThanOrEqual(time() + 600, $expire);
    }

    /**
     * A non-numeric duration falls back to an hour, not to zero.
     *
     * `(int) 'an hour'` is 0, and 0 means permanent — so a typo would silently
     * create a block nothing ever lifts.
     */
    #[Test]
    public function a_non_numeric_duration_does_not_become_permanent(): void
    {
        $this->artisan('firewall:block', ['ip' => '203.0.113.9', '--duration' => 'an hour'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertGreaterThan(time(), $this->manager()->all()['203.0.113.9']['expire']);
    }

    /**
     * A range is refused, and the message says where ranges belong.
     *
     * Storage keys are the client IP verbatim and lookups are exact, so a range
     * stored as a block would sit in the list looking authoritative and match
     * nobody — the worst kind of wrong, because it looks like it worked.
     */
    #[Test]
    public function it_refuses_a_cidr_range_and_points_at_rules_instead(): void
    {
        [$exit, $output] = $this->runCommand('firewall:block', ['ip' => '203.0.113.0/24']);

        $this->assertSame(FirewallCommand::EXIT_ERROR, $exit);
        $this->assertStringContainsString('is a range', $output);
        $this->assertStringContainsString('IpAddress rule', $output);
        $this->assertSame([], $this->manager()->all());
    }

    #[Test]
    #[DataProvider('invalidAddresses')]
    public function it_refuses_an_address_that_is_not_one(string $ip): void
    {
        $this->artisan('firewall:block', ['ip' => $ip])
            ->assertExitCode(FirewallCommand::EXIT_ERROR);

        $this->assertSame([], $this->manager()->all());
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function invalidAddresses(): array
    {
        return [
            'words' => ['not-an-ip'],
            'truncated' => ['203.0.113'],
            'out of range' => ['299.0.113.9'],
            'empty' => [''],
            'hostname' => ['example.test'],
        ];
    }

    /**
     * Re-blocking is refused rather than silently keeping the old expiry.
     *
     * `set()` on an existing key replaces the payload and leaves the expiry
     * alone, so a longer `--duration` would appear to apply and would not.
     */
    #[Test]
    public function it_refuses_to_re_block_without_force(): void
    {
        $this->artisan('firewall:block', ['ip' => '203.0.113.9', '--duration' => '60'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:block', ['ip' => '203.0.113.9', '--duration' => '9000'])
            ->expectsOutputToContain('already blocked')
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function force_replaces_the_block_and_applies_the_new_duration(): void
    {
        $this->artisan('firewall:block', ['ip' => '203.0.113.9', '--duration' => '60'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:block', [
            'ip' => '203.0.113.9',
            '--duration' => '9000',
            '--force' => true,
        ])
            ->expectsOutputToContain('Replaced the block on')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertGreaterThan(
            time() + 8000,
            $this->manager()->all()['203.0.113.9']['expire'],
            'Without deleting first, the original 60 second expiry would have survived.'
        );
    }

    #[Test]
    public function it_lifts_a_block_by_address(): void
    {
        $this->manager()->add('203.0.113.9', 3600);

        $this->artisan('firewall:unblock', ['ip' => '203.0.113.9'])
            ->expectsOutputToContain('Lifted 1 block')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertSame([], $this->manager()->all());
    }

    /**
     * A range is accepted for lifting, unlike for blocking.
     *
     * Not an inconsistency: lifting matches against stored addresses, so a
     * range is the right shape for "everything in the list inside this range".
     */
    #[Test]
    public function it_lifts_a_whole_range(): void
    {
        $this->manager()->add('203.0.113.9', 3600);
        $this->manager()->add('203.0.113.10', 3600);
        $this->manager()->add('198.51.100.1', 3600);

        $this->artisan('firewall:unblock', ['ip' => '203.0.113.0/24'])
            ->expectsOutputToContain('Lifted 2 blocks')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertSame(['198.51.100.1'], array_keys($this->manager()->all()));
    }

    #[Test]
    public function a_dry_run_lift_changes_nothing(): void
    {
        $this->manager()->add('203.0.113.9', 3600);

        $this->artisan('firewall:unblock', ['ip' => '203.0.113.9', '--dry-run' => true])
            ->expectsOutputToContain('Would lift 1 block')
            ->expectsOutputToContain('Dry run')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertArrayHasKey('203.0.113.9', $this->manager()->all());
    }

    #[Test]
    public function it_empties_the_list(): void
    {
        $this->manager()->add('203.0.113.9', 3600);
        $this->manager()->add('198.51.100.1', 0);

        $this->artisan('firewall:unblock', ['--all' => true])
            ->expectsOutputToContain('Lifted 2 blocks')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertSame([], $this->manager()->all());
    }

    #[Test]
    public function a_dry_run_clear_changes_nothing(): void
    {
        $this->manager()->add('203.0.113.9', 3600);

        $this->artisan('firewall:unblock', ['--all' => true, '--dry-run' => true])
            ->expectsOutputToContain('Would lift 1 block')
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->assertCount(1, $this->manager()->all());
    }

    #[Test]
    public function clearing_an_empty_list_is_not_an_error(): void
    {
        $this->artisan('firewall:unblock', ['--all' => true])
            ->expectsOutputToContain('already empty')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * Nothing matched is an answer, not a failure.
     *
     * Exiting non-zero would make a deploy step that defensively lifts an
     * address fail as soon as the address is no longer listed.
     */
    #[Test]
    public function lifting_something_that_is_not_blocked_exits_zero(): void
    {
        $this->artisan('firewall:unblock', ['ip' => '203.0.113.9'])
            ->expectsOutputToContain('Nothing in the block list matches')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function it_refuses_an_address_and_all_together(): void
    {
        $this->artisan('firewall:unblock', ['ip' => '203.0.113.9', '--all' => true])
            ->expectsOutputToContain('not both')
            ->assertExitCode(FirewallCommand::EXIT_CONFIG_UNREADABLE);
    }

    #[Test]
    public function it_refuses_to_lift_nothing_in_particular(): void
    {
        $this->artisan('firewall:unblock')
            ->expectsOutputToContain('Name an address or range')
            ->assertExitCode(FirewallCommand::EXIT_CONFIG_UNREADABLE);
    }

    /**
     * The reference lookup — the reason this command exists.
     *
     * A support caller can read out the hex string on the block page and
     * nothing else. Before this there was no way to turn it back into an
     * address without grepping logs.
     */
    #[Test]
    public function it_finds_the_client_a_reference_belongs_to(): void
    {
        $result = $this->manager()->add('203.0.113.9', 3600, 'Scraping /api');

        [$exit, $output] = $this->runCommand('firewall:find-reference', [
            'reference' => $result['reference'],
        ]);

        $this->assertSame(FirewallCommand::EXIT_OK, $exit);
        $this->assertStringContainsString('203.0.113.9', $output);
        $this->assertStringContainsString('Scraping /api', $output);
        // The remediation line: a reference is only useful if it leads
        // somewhere, and this is where it leads.
        $this->assertStringContainsString('firewall:unblock 203.0.113.9', $output);
    }

    /**
     * References are matched case-insensitively.
     *
     * The firewall renders them uppercase; people retype them however they like.
     */
    #[Test]
    public function a_reference_is_matched_regardless_of_case(): void
    {
        $result = $this->manager()->add('203.0.113.9', 3600);

        $this->artisan('firewall:find-reference', [
            'reference' => strtolower($result['reference']),
        ])->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:find-reference', [
            'reference' => '  ' . $result['reference'] . '  ',
        ])->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function an_unknown_reference_explains_that_blocks_lapse(): void
    {
        $this->artisan('firewall:find-reference', ['reference' => 'DEADBEEFDEADBEEFDEADBEEFDEADBEEF'])
            ->expectsOutputToContain('No block in force carries reference')
            ->expectsOutputToContain('lapsed')
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function an_empty_reference_finds_nothing(): void
    {
        $this->manager()->add('203.0.113.9', 3600);

        $this->artisan('firewall:find-reference', ['reference' => '   '])
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function it_reports_a_found_reference_as_json(): void
    {
        $result = $this->manager()->add('203.0.113.9', 3600, 'Scraping /api');

        [, $output] = $this->runCommand('firewall:find-reference', [
            'reference' => $result['reference'],
            '--json' => true,
        ]);

        $payload = json_decode($output, true);

        $this->assertIsArray($payload);
        $this->assertSame('203.0.113.9', $payload['address']);
        $this->assertSame($result['reference'], $payload['reference']);
        $this->assertSame('Scraping /api', $payload['reason']);
    }

    #[Test]
    public function it_reports_a_missing_reference_as_json(): void
    {
        [$exit, $output] = $this->runCommand('firewall:find-reference', [
            'reference' => 'ABC123',
            '--json' => true,
        ]);

        $payload = json_decode($output, true);

        $this->assertSame(FirewallCommand::EXIT_ERROR, $exit);
        $this->assertIsArray($payload);
        $this->assertFalse($payload['found']);
        $this->assertSame('ABC123', $payload['reference']);
    }

    /**
     * A rule-written block is findable by reference too.
     *
     * The whole point is answering a caller holding a reference from a page the
     * firewall served, not one this command wrote — so the lookup has to work
     * against a record the middleware created.
     */
    #[Test]
    public function a_reference_from_a_real_block_is_findable(): void
    {
        \Illuminate\Support\Facades\Route::get('/probe', static fn (): string => 'through');
        $this->blockIp('127.0.0.1');

        $body = (string) $this->get('/probe')->getContent();

        $matched = preg_match('/\b([0-9A-F]{32})\b/', $body, $matches);
        $this->assertSame(1, $matched, 'The block page must show a reference.');

        $this->artisan('firewall:find-reference', ['reference' => $matches[1]])
            ->expectsOutputToContain('127.0.0.1')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * A backend that cannot answer questions says so rather than saying "none".
     *
     * A non-queryable backend returns an empty list from every read, so a lift
     * would report "0 removed" and a lookup "no such reference" — both of which
     * read as an answer rather than as an inability to answer.
     */
    #[Test]
    public function a_non_queryable_backend_is_reported_rather_than_answered(): void
    {
        $manager = new BlockManager(new \Kanopi\Firewall\Utility\BlockList([[
            'storage' => ['type' => NonQueryableStorage::class],
        ]]));

        $this->expectException(IntegrationException::class);
        $this->expectExceptionMessageMatches('/cannot be queried/');

        $manager->all();
    }

    /**
     * Each command reports a backend that cannot answer, rather than a verdict.
     *
     * Reached through a backend that implements only `StorageInterface`. The
     * distinction matters because the wrong answer here is silence that looks
     * like success: "0 blocks lifted" and "no such reference" are both things
     * an operator would believe.
     */
    #[Test]
    public function unblock_reports_a_backend_that_cannot_be_queried(): void
    {
        $this->useNonQueryableStorage();

        $this->artisan('firewall:unblock', ['ip' => '203.0.113.9'])
            ->expectsOutputToContain('cannot be queried')
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function clearing_reports_a_backend_that_cannot_be_queried(): void
    {
        $this->useNonQueryableStorage();

        $this->artisan('firewall:unblock', ['--all' => true])
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function find_reference_reports_a_backend_that_cannot_be_queried(): void
    {
        $this->useNonQueryableStorage();

        $this->artisan('firewall:find-reference', ['reference' => 'ABC123'])
            ->expectsOutputToContain('cannot be queried')
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    /**
     * A backend that accepts the write but returns false is reported.
     *
     * `set()` returning FALSE is the storage layer declining, and continuing
     * would print "Blocked 203.0.113.9" about a block that does not exist —
     * the one outcome worse than failing.
     */
    #[Test]
    public function it_reports_a_backend_that_refuses_to_store_the_block(): void
    {
        $this->useNonQueryableStorage();

        $this->artisan('firewall:block', ['ip' => '203.0.113.9'])
            ->expectsOutputToContain('refused to record a block')
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function the_backend_is_named_in_output(): void
    {
        $this->artisan('firewall:block', ['ip' => '203.0.113.9'])
            ->expectsOutputToContain('FileStorage')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    /**
     * Malformed records do not break a lookup.
     *
     * The accessors walk into a nested payload, and a record written by an
     * older release — or by something else sharing the store — may not have
     * one. Returning an empty string beats a TypeError during an incident.
     */
    #[Test]
    public function record_accessors_tolerate_a_shape_they_do_not_recognise(): void
    {
        $manager = $this->manager();

        $this->assertSame('', $manager->referenceOf('not-a-record'));
        $this->assertSame('', $manager->referenceOf(['value' => 'not-an-array']));
        $this->assertSame('', $manager->referenceOf(['value' => ['event_id' => ['nested']]]));
        $this->assertSame('', $manager->payloadValue('not-a-record', 'reason'));
        $this->assertSame('', $manager->payloadValue(['value' => 'flat'], 'reason'));
        $this->assertSame('', $manager->payloadValue(['value' => ['reason' => ['a']]], 'reason'));
    }

    /**
     * Run a command and hand back its exit code and full output.
     *
     * Not named `run()`: `PHPUnit\Framework\TestCase::run()` is final, and
     * overriding it is a fatal error at file-load time that PHPUnit reports as
     * "premature end of PHP process" rather than as a name collision.
     *
     * Used instead of chained `expectsOutputToContain()` wherever more than one
     * substring is asserted, because those cannot both match the same line:
     * each becomes its own Mockery expectation on `doWrite`, and Mockery
     * dispatches a call to the first expectation that matches it, leaving the
     * others unsatisfied. The failure reads as "output does not contain X"
     * about a string that is plainly there.
     *
     * @param array<string, mixed> $arguments
     *
     * @return array{0: int, 1: string}
     */
    private function runCommand(string $command, array $arguments = []): array
    {
        $exit = Artisan::call($command, $arguments);

        return [$exit, Artisan::output()];
    }

    /**
     * Swap in a backend that implements only `StorageInterface`.
     *
     * Every backend the library ships is queryable, so the refusal branches
     * are unreachable without one of these.
     */
    private function useNonQueryableStorage(): void
    {
        config(['firewall.storage' => ['type' => NonQueryableStorage::class]]);
    }

    private function manager(): BlockManager
    {
        return $this->app->make(BlockManager::class);
    }
}

