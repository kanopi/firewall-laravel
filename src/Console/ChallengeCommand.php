<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Console;

/**
 * Read a challenge pass, and withdraw one without re-challenging everybody.
 *
 * Wraps `bin/firewall-challenge` (2.30). A pass token is stateless and signed,
 * so until then the only way to withdraw one was rotating `challenge.secret`,
 * which re-challenges every legitimate visitor holding a pass to remove one.
 *
 *     php artisan firewall:challenge --inspect=eyJpcCI6…
 *     php artisan firewall:challenge --revoke=eyJpcCI6… --reason="shared on a forum"
 *
 * Revocation needs `challenge.revocable: true`, and a durable storage backend
 * to hold the list. The script says so when either is missing, rather than
 * recording a revocation nothing will read.
 */
final class ChallengeCommand extends FirewallCommand
{
    /**
     * @var string
     */
    protected $signature = 'firewall:challenge
        {--inspect= : Decode a pass: address, provider, issued, expires, nonce}
        {--revoke= : Withdraw that pass, until its own expiry}
        {--revoke-nonce= : Withdraw by nonce, for when the log is what you have}
        {--restore= : Put a revoked pass back, by nonce}
        {--status= : Whether a nonce is currently revoked, and why}
        {--expires= : With --revoke-nonce: when the token expires, as a Unix timestamp}
        {--reason= : Recorded alongside a revocation}
        {--json : Machine-readable output}
        {--keep-config : Leave the dumped effective configuration on disk and print its path}';

    /**
     * @var string
     */
    protected $description = 'Inspect, revoke and restore challenge passes';

    public function handle(): int
    {
        return $this->runFirewallBinary('firewall-challenge', $this->forwardOptions(
            flags: ['json'],
            values: ['inspect', 'revoke', 'revoke-nonce', 'restore', 'status', 'expires', 'reason']
        ));
    }
}
