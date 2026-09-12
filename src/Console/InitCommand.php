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
 * Write a starting YAML configuration from four questions.
 *
 * The odd one out, because a Laravel application already has a starting
 * configuration: `vendor:publish --tag=firewall-config` gives it, with `env()`
 * calls and Laravel paths that YAML cannot express. So this is not the
 * recommended way in, and the command says so.
 *
 * It is wrapped anyway for the case it is genuinely better at: the shipped
 * presets it selects between are curated rule sets that this package's config
 * file leaves empty on purpose, and the platform and CDN questions produce a
 * ruleset it would take some reading to assemble by hand. Point it at a file,
 * then list that file in `firewall.configs`.
 *
 * Runs with no configuration of its own — it writes one rather than reading
 * one — so nothing is dumped and no secret is passed.
 */
final class InitCommand extends FirewallCommand
{
    /**
     * @var string
     */
    protected $signature = 'firewall:init
        {--platform= : wordpress, drupal or other}
        {--cdn= : none, cloudflare, pantheon, wpengine or fastly}
        {--storage= : file, database or redis}
        {--mode= : log (observe, recommended) or block (enforce)}
        {--output= : Where to write. Defaults to config/firewall.yml}
        {--print : Write to stdout and create nothing}
        {--force : Overwrite an existing file}';

    /**
     * @var string
     */
    protected $description = 'Generate a starter firewall YAML config from the shipped presets';

    public function handle(): int
    {
        $this->components->warn(
            'A Laravel application normally wants `php artisan vendor:publish '
            . '--tag=firewall-config` instead: that config file can use env() and '
            . 'storage_path(), which YAML cannot. Use this to pick a starting rule set '
            . 'from the shipped presets, then add the file it writes to firewall.configs.'
        );

        $options = $this->forwardOptions(
            flags: ['print', 'force'],
            values: ['platform', 'cdn', 'storage', 'mode', 'output']
        );

        // The `mode` this writes into a YAML file is the library's, and `block`
        // in a file that this package then loads is harmless: the mode override
        // wins over anything a config input carries. So it is forwarded as
        // given rather than translated, and the file stays valid for
        // `bin/firewall-*` used directly.
        return $this->runFirewallBinary('firewall-init', $options, withConfig: false);
    }
}
