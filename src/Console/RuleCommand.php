<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Kanopi\Firewall\Laravel\Console;

use Kanopi\Firewall\Laravel\Support\Settings;

/**
 * Add and remove rules without editing config by hand.
 *
 * It writes to a file it owns exclusively — `firewall.artisan.managed_rules` —
 * and will refuse to change a rule it did not write. Rules declared in
 * `config/firewall.php` can be listed but not edited, which is the right way
 * round: a command that rewrote a PHP config file would have to preserve
 * comments, `env()` calls and formatting, and would eventually fail to.
 *
 * That managed file is added to the firewall's config inputs automatically as
 * soon as it exists, so a rule added here is live on the next request with no
 * further wiring.
 */
final class RuleCommand extends FirewallCommand
{
    /**
     * @var string
     */
    protected $signature = 'firewall:rule
        {action : init, list, add, remove, disable or enable}
        {name? : The rule name, for remove, disable and enable}
        {--plugin= : ip, url, agent, asn, geo, or a class name. Default ip}
        {--response= : block, allow or challenge. Default block}
        {--rule=* : A config entry for the rule. Required for add}
        {--ip=* : Shorthand for --plugin=ip --rule=VALUE}
        {--path=* : Shorthand for --plugin=url --rule=path:VALUE}
        {--name= : What the log will call it. Default is generated}
        {--weight= : Evaluation order, lower first. Default 0}
        {--managed= : Override firewall.artisan.managed_rules for this run}
        {--dry-run : Report what would change and write nothing}
        {--json : Machine-readable output}
        {--keep-config : Leave the dumped effective configuration on disk and print its path}';

    /**
     * @var string
     */
    protected $description = 'Add, remove, enable and disable managed firewall rules';

    public function handle(): int
    {
        $action = $this->argument('action');
        $action = is_string($action) ? $action : '';
        $managed = $this->managedPath();

        if ($action !== 'init' && !is_file($managed)) {
            // The script refuses to add a rule to a file that nothing includes
            // — correctly, because a rule written somewhere the firewall never
            // reads is worse than no rule. But the include can only be written
            // once the file exists: naming a missing include is a load failure
            // that empties the whole document, not a skipped line. So the file
            // is created first, which makes the include valid, and the action
            // then runs against a configuration that already carries it.
            //
            // Done here rather than left to the operator because the two steps
            // are not independent: `firewall:rule add` on a fresh install would
            // otherwise write the rule, warn that nothing includes it, and exit
            // non-zero — having changed the file but not the firewall.
            $initExit = $this->runFirewallBinaryWithLeadingArguments(
                'firewall-rule',
                leading: ['init'],
                arguments: ['--managed=' . $managed]
            );

            if ($initExit !== self::EXIT_OK) {
                return $initExit;
            }
        }

        // The action, then the rule name, then the config paths. That order is
        // the script's: for `remove`, `disable` and `enable` the first bare word
        // is taken as the rule name and everything after it as a config file, so
        // a name placed after the config would be read as another config file
        // and rejected as "Configuration file not found".
        $leading = [$action];
        $name = $this->argument('name');

        if (is_string($name) && $name !== '') {
            $leading[] = $name;
        }

        $options = $this->forwardOptions(
            flags: ['dry-run', 'json'],
            values: ['plugin', 'response', 'name', 'weight'],
            repeatable: ['rule', 'ip', 'path']
        );

        $options[] = '--managed=' . $managed;

        return $this->runFirewallBinaryWithLeadingArguments(
            'firewall-rule',
            leading: $leading,
            arguments: $options
        );
    }

    /**
     * Where the managed rules file lives.
     *
     * Always passed explicitly, never left to the script's own default. That
     * default is "beside the first config given", and the first config given
     * here is a temporary dump in the system temp directory — so the rules
     * would be written next to a file that is deleted when the command exits,
     * and `firewall:rule add` would report success having changed nothing that
     * survives.
     */
    private function managedPath(): string
    {
        $override = $this->option('managed');

        if (is_string($override) && $override !== '') {
            return $override;
        }

        $configured = Settings::for($this->laravel)->text('firewall.artisan.managed_rules');

        return $configured !== ''
            ? $configured
            : $this->laravel->basePath('config/firewall-managed.yml');
    }
}
