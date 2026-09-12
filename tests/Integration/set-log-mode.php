<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*
 * Switch a published `config/firewall.php` to `log` mode.
 *
 * A separate file rather than a `php -r` inside install.sh, for the same reason
 * as add-rule.php: the string being matched is PHP source full of single quotes,
 * and threading it through bash's quoting produced a config that silently did
 * not change — which reads as "log mode is broken" rather than "the test
 * harness did nothing".
 *
 * The replacement is verified and the file is re-parsed, so a skeleton that
 * changes the shape of this line fails here, naming itself, rather than three
 * assertions later.
 *
 * Usage: php set-log-mode.php path/to/config/firewall.php
 */

$path = $argv[1] ?? '';

if (!is_file($path)) {
    fwrite(STDERR, sprintf("No config file at %s\n", $path));
    exit(1);
}

$config = (string) file_get_contents($path);
$search = "'mode' => env('FIREWALL_MODE', 'block')";
$replace = "'mode' => 'log'";

if (!str_contains($config, $search)) {
    fwrite(STDERR, sprintf("Could not find the mode line in %s.\n", $path));
    exit(1);
}

if (file_put_contents($path, str_replace($search, $replace, $config)) === false) {
    fwrite(STDERR, sprintf("Could not write %s\n", $path));
    exit(1);
}

$check = shell_exec(sprintf('%s -l %s 2>&1', escapeshellarg(PHP_BINARY), escapeshellarg($path)));

if (!is_string($check) || !str_contains($check, 'No syntax errors')) {
    fwrite(STDERR, sprintf("The patched config does not parse:\n%s\n", (string) $check));
    exit(1);
}

echo "mode switched to log\n";
