<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*
 * Insert one rule into a published `config/firewall.php`.
 *
 * A separate file rather than a `php -r` inside install.sh. The rule is PHP
 * source containing single quotes, backslashes and a heredoc, and threading
 * that through bash's quoting produced a config that parsed as
 * `Undefined constant "plugins"` — a failure in the test harness that looked
 * exactly like a failure in the package.
 *
 * Usage: php add-rule.php path/to/config/firewall.php
 */

$path = $argv[1] ?? '';

if (!is_file($path)) {
    fwrite(STDERR, sprintf("No config file at %s\n", $path));
    exit(1);
}

$config = (string) file_get_contents($path);

$rule = <<<'PHP_SNIPPET'
    'plugins' => [
        [
            'plugin' => \Kanopi\Firewall\Plugins\Url::class,
            'response' => 'block',
            'name' => 'block-wp-probes',
            'config' => ['path@starts_with:/wp-'],
        ],
PHP_SNIPPET;

$updated = str_replace("    'plugins' => [", $rule, $config, $count);

if ($count !== 1) {
    fwrite(STDERR, sprintf(
        "Expected exactly one `plugins` key in %s, found %d.\n",
        $path,
        $count
    ));
    exit(1);
}

if (file_put_contents($path, $updated) === false) {
    fwrite(STDERR, sprintf("Could not write %s\n", $path));
    exit(1);
}

// Parsed rather than assumed: a config this script corrupted would otherwise
// surface as "the development server never came up", which reads as a problem
// with the package.
$check = shell_exec(sprintf('%s -l %s 2>&1', escapeshellarg(PHP_BINARY), escapeshellarg($path)));

if (!is_string($check) || !str_contains($check, 'No syntax errors')) {
    fwrite(STDERR, sprintf("The patched config does not parse:\n%s\n", (string) $check));
    exit(1);
}

echo "one Url rule blocking /wp-*\n";
