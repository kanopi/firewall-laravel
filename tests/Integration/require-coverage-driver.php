<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*
 * Refuse a coverage run when no coverage driver is loaded.
 *
 * Without this the failure is actively misleading. `phpunit.xml` declares
 * `<coverage>` and `failOnWarning="true"`, so PHPUnit raises "No code coverage
 * driver available" and then executes **zero tests**, reporting "No tests
 * executed!". That reads as a broken test suite, and it is a missing PHP
 * extension. The first CI run on this repository failed exactly that way in all
 * seven phpunit jobs — having tested nothing at all — and diagnosing it took a
 * container reproduction rather than a glance at the log.
 *
 * A separate file rather than a `php -r` one-liner in composer.json, and that is
 * not a style preference. The one-liner it replaced had to survive JSON
 * escaping, Composer's argument handling and a shell, and its message contained
 * the words `composer test` in backticks — which the shell duly executed as a
 * command substitution, running the entire test suite as a side effect of
 * printing an error about not being able to run the test suite. Four levels of
 * quoting is a place bugs live.
 */

if (extension_loaded('xdebug') || extension_loaded('pcov')) {
    exit(0);
}

fwrite(STDERR, <<<'MESSAGE'

  No code coverage driver is loaded, so a coverage run would execute no tests.

  PHPUnit needs Xdebug or PCOV to measure coverage. Without one it raises a
  runner warning, and because phpunit.xml sets failOnWarning it then runs
  nothing at all and reports "No tests executed!" — which names the symptom
  rather than the cause.

  Fix it one of these ways:

    pecl install xdebug      install a driver (what CI does)
    pecl install pcov        a faster alternative, line coverage only
    composer test            run both suites without coverage instead

MESSAGE);

exit(1);
