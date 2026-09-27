<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Tests\Feature;

use Illuminate\Http\Request;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Laravel\Console\FirewallCommand;
use Kanopi\Firewall\Laravel\Tests\TestCase;
use Kanopi\Firewall\Storage\FileStorage;
use PHPUnit\Framework\Attributes\Test;

/**
 * `firewall:challenge`, over `bin/firewall-challenge` (#16).
 *
 * Real tokens signed with the configured secret, and a real file store for
 * revocations: a revocation written to the suite's in-memory default would be
 * recorded and forgotten when the script's process ended, which proves
 * nothing.
 */
final class ChallengeCommandTest extends TestCase
{
    private const SECRET = 'test-secret-that-is-long-enough-to-be-a-real-hmac-key';

    private string $directory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->directory = sys_get_temp_dir() . '/fw-challenge-' . bin2hex(random_bytes(6));
        mkdir($this->directory);

        config([
            'firewall.challenge.secret' => self::SECRET,
            'firewall.challenge.revocable' => true,
            'firewall.storage' => ['type' => FileStorage::class, 'config' => [
                'storage_file' => $this->directory . '/blocked.data',
                'offense_file' => $this->directory . '/offenses.data',
            ]],
        ]);
    }

    protected function tearDown(): void
    {
        foreach (array_filter((array) glob($this->directory . '/*'), 'is_string') as $file) {
            @unlink($file);
        }

        @rmdir($this->directory);

        parent::tearDown();
    }

    #[Test]
    public function it_inspects_a_pass_signed_with_the_configured_secret(): void
    {
        $this->artisan('firewall:challenge', ['--inspect' => $this->pass('203.0.113.9')])
            ->expectsOutputToContain('203.0.113.9')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function it_refuses_a_token_this_configuration_did_not_sign(): void
    {
        $forged = (new TokenManager('a-different-secret-entirely-and-long-enough', 'math', 'math'))
            ->mint(Request::create('/', server: ['REMOTE_ADDR' => '203.0.113.9']), 600, 'math');

        $this->artisan('firewall:challenge', ['--inspect' => $forged])
            ->assertExitCode(FirewallCommand::EXIT_ERROR);
    }

    #[Test]
    public function it_revokes_a_pass_and_reports_it_revoked(): void
    {
        $token = $this->pass('203.0.113.9');

        $this->artisan('firewall:challenge', ['--revoke' => $token, '--reason' => 'shared on a forum'])
            ->assertExitCode(FirewallCommand::EXIT_OK);

        $this->artisan('firewall:challenge', ['--inspect' => $token, '--json' => true])
            ->expectsOutputToContain('shared on a forum')
            ->assertExitCode(FirewallCommand::EXIT_OK);
    }

    #[Test]
    public function it_needs_exactly_one_action(): void
    {
        $this->artisan('firewall:challenge')
            ->assertExitCode(FirewallCommand::EXIT_CONFIG_UNREADABLE);
    }

    private function pass(string $address): string
    {
        return (new TokenManager(self::SECRET, 'math', 'math'))
            ->mint(Request::create('/', server: ['REMOTE_ADDR' => $address]), 600, 'math');
    }
}
