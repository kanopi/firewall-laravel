#!/usr/bin/env bash
#
# Install this package into a real Laravel application and drive it over HTTP.
#
# The PHPUnit suites run inside Testbench, which is a Laravel application in
# every way that matters for unit and feature testing — and in three ways that
# matter here, is not:
#
#   1. **Composer never runs.** Package auto-discovery, the `laravel.providers`
#      extra and `vendor:publish` are all unexercised by a suite that loads the
#      provider by class name.
#   2. **Storage is InMemoryStorage.** The shipped default is FileStorage under
#      `storage/`, and the directory it needs did not exist. That defect — a 500
#      on every request of a clean install — was invisible to 246 passing tests
#      and obvious within a minute of a real install.
#   3. **The SAPI is `cli`.** Requests here go through `artisan serve`, which is
#      `cli-server`, and the library's CLI short-circuit keys off exactly that
#      distinction. This script is what established that `artisan serve` is
#      *not* short-circuited — which had been assumed the other way round.
#
# Usage:
#   tests/Integration/install.sh [laravel-constraint]
#
#   tests/Integration/install.sh            # whatever Laravel resolves to
#   tests/Integration/install.sh '^12.0'    # pin the framework
#
# Environment:
#   FIREWALL_INSTALL_KEEP=1   Leave the application on disk and print its path.
#
# Exit codes:
#   0  the package installed and enforced over HTTP
#   1  a step failed — the failing assertion names itself

set -euo pipefail

LARAVEL_CONSTRAINT="${1:-}"
PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/firewall-install-XXXXXX")"
# No `.log` suffix on the template: BSD mktemp only substitutes an `XXXXXX`
# that ends the template, so the GNU-style `...-XXXXXX.log` is taken literally
# and the second run on macOS fails with "File exists".
SERVE_LOG="$(mktemp "${TMPDIR:-/tmp}/firewall-serve-XXXXXX")"
# 0 asks the kernel for a free port, which matters more than it looks: CI runs
# these jobs in parallel, and a hardcoded port makes two of them fight over it
# and fail in whichever order they happened to start.
PORT="$(php -r '$s = stream_socket_server("tcp://127.0.0.1:0"); echo (int) explode(":", stream_socket_get_name($s, false))[1];')"
SERVER_PID=""

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
pass() { printf '    \033[32mok\033[0m   %s\n' "$1"; }

stop_server() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi

    SERVER_PID=""
}

cleanup() {
    stop_server

    if [[ -n "${FIREWALL_INSTALL_KEEP:-}" ]]; then
        printf '\nApplication kept at %s\n' "${APP_DIR}"
        return
    fi

    rm -rf "${APP_DIR}" "${SERVE_LOG}"
}
trap cleanup EXIT

# Everything a failure needs to be explicable: the server's log and the
# framework's own. Printed here rather than left for someone to go looking for,
# because in CI the directory is gone by the time anybody reads the output.
fail() {
    printf '    \033[31mFAIL\033[0m %s\n' "$1"

    if [[ -s "${SERVE_LOG}" ]]; then
        printf '\n--- artisan serve ---\n'
        tail -20 "${SERVE_LOG}"
    fi

    if [[ -s "${APP_DIR}/storage/logs/laravel.log" ]]; then
        printf '\n--- laravel.log ---\n'
        tail -c 2000 "${APP_DIR}/storage/logs/laravel.log"
    fi

    exit 1
}

assert_eq() {
    if [[ "$1" == "$2" ]]; then pass "$3 ($2)"; else fail "$3: expected $1, got $2"; fi
}

assert_contains() {
    if [[ "$1" == *"$2"* ]]; then pass "$3"; else fail "$3: output did not contain '$2'"; fi
}

# Status of a GET, without following redirects — a block is the response under
# test, not wherever it might point.
status_of() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:${PORT}$1"
}

start_server() {
    php artisan serve --port="${PORT}" --no-interaction >> "${SERVE_LOG}" 2>&1 &
    SERVER_PID=$!

    for _ in $(seq 1 40); do
        if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${PORT}/"; then
            return 0
        fi
        sleep 0.25
    done

    fail "the development server never came up"
}

step "Creating a Laravel application"
composer create-project laravel/laravel "${APP_DIR}" \
    --no-interaction --quiet --no-scripts ${LARAVEL_CONSTRAINT:+"${LARAVEL_CONSTRAINT}"}
cd "${APP_DIR}"
php -r 'file_exists(".env") || copy(".env.example", ".env");'
php artisan key:generate --quiet

# `--no-scripts` skips the post-create hooks that create `database/database.sqlite`
# and migrate it, and a current skeleton defaults SESSION_DRIVER and CACHE_STORE
# to `database` — so the welcome page 500s on a database that does not exist.
# Switched to the array drivers rather than provisioning sqlite: this script is
# about whether the firewall installs, and a database would add setup that can
# fail for reasons having nothing to do with it. The baseline assertion below is
# what keeps that honest.
php -r '
$env = (string) file_get_contents(".env");
foreach (["SESSION_DRIVER" => "array", "CACHE_STORE" => "array"] as $key => $value) {
    $env = preg_replace("/^{$key}=.*$/m", "{$key}={$value}", $env, 1, $count);
    if ($count === 0) {
        $env .= PHP_EOL . "{$key}={$value}";
    }
}
file_put_contents(".env", $env);
'
pass "laravel/framework $(php -r '
    $lock = json_decode((string) file_get_contents("composer.lock"), true);
    foreach ($lock["packages"] as $package) {
        if ($package["name"] === "laravel/framework") { echo $package["version"]; }
    }')"

step "Establishing a baseline before installing anything"
# The application is proved healthy *before* the package exists, so that every
# later failure is attributable. Without this a broken skeleton looks exactly
# like a broken firewall — which is precisely the confusion that cost time while
# writing this script.
start_server
assert_eq "200" "$(status_of /)" "the untouched application serves its welcome page"
stop_server

step "Installing kanopi/firewall-laravel from the working tree"
# A path repository with `symlink: false`, so the package is copied in and the
# install is tested rather than the checkout being mutated. The dev stability is
# an artefact of installing an untagged working tree; a released version needs
# neither line.
composer config repositories.firewall-laravel \
    "{\"type\": \"path\", \"url\": \"${PACKAGE_DIR}\", \"options\": {\"symlink\": false}}" --json
composer config minimum-stability dev
composer config prefer-stable true
INSTALL_OUTPUT="$(composer require "kanopi/firewall-laravel:*@dev" --no-interaction 2>&1)" \
    || { printf '%s\n' "${INSTALL_OUTPUT}"; fail "composer require failed"; }

# Asserted against the manifest discovery actually writes, not against the
# console output. The output is cosmetic and pads the package name with a
# version-dependent number of dots, so matching it passed on Laravel 13 and
# failed on 12 while discovery was working perfectly in both.
#
# The needle is the bare class name: the manifest is `var_export`ed, so every
# namespace separator in it is a doubled backslash, and matching the FQCN means
# writing a needle that is itself an escaping puzzle. No other package in this
# application declares a class by that name.
assert_contains "$(cat bootstrap/cache/packages.php 2>/dev/null || true)" \
    'FirewallServiceProvider' \
    "Laravel auto-discovered the service provider"

step "Publishing the configuration"
php artisan vendor:publish --tag=firewall-config --quiet
if [[ -f config/firewall.php ]]; then
    pass "config/firewall.php published"
else
    fail "config/firewall.php was not published"
fi

step "Diagnosing a clean install"
# Exit 0 is the assertion. This is the step that would have caught the missing
# storage directory: the library half of the doctor opens the real storage file
# rather than reading the config in the abstract.
php artisan firewall:doctor > "${APP_DIR}/doctor.txt" 2>&1 \
    || { cat "${APP_DIR}/doctor.txt"; fail "firewall:doctor reported an error on a clean install"; }
pass "firewall:doctor exits 0 on a freshly published config"
if [[ -d storage/firewall ]]; then
    pass "storage/firewall was created"
else
    fail "storage/firewall was not created"
fi

step "Adding a rule"
php "${PACKAGE_DIR}/tests/Integration/add-rule.php" config/firewall.php > /dev/null \
    && pass "one Url rule blocking /wp-*" \
    || fail "could not add a rule to the published config"

step "Enforcing over HTTP"
start_server
# These requests go over HTTP rather than through the kernel in-process because
# `artisan serve` runs under the `cli-server` SAPI. The library short-circuits on
# `cli` and not on `cli-server`, so this is the only way to assert which side of
# that line `artisan serve` falls on — and it is the wrong thing to guess at,
# because guessing "it short-circuits" means telling operators their development
# environment is unprotected when it is not.
assert_eq "200" "$(status_of /)" "a normal request is still served with the firewall installed"
assert_eq "400" "$(status_of /wp-login.php)" "a probe for /wp-login.php is blocked"
# Captured rather than inlined into the assertion: the reference number in this
# body is looked up further down, and it has to be a reference the firewall
# actually served rather than one this script generated.
BLOCKED_BODY="$(curl -s --max-time 10 "http://127.0.0.1:${PORT}/wp-admin/setup-config.php")"
assert_contains "${BLOCKED_BODY}" "Request blocked" "the block renders the package's Blade view"

step "Lifting the block the probes earned"
# Two probes put this client on the durable block list, which is the
# repeat-offender defence working — and it means `/` is blocked now too. Lifting
# it is both the cleanup and the test of the operational command.
assert_eq "400" "$(status_of /)" "the repeat-offender list now blocks everything from this client"
assert_contains "$(php artisan firewall:blocks 2>&1)" "127.0.0.1" "firewall:blocks names the client"

# The reference on the page is the only thing a support caller can read out, so
# the round trip from page to client is asserted rather than assumed.
REFERENCE="$(printf '%s' "${BLOCKED_BODY}" | grep -oE '[0-9A-F]{32}' | head -1)"
[[ -n "${REFERENCE}" ]] && pass "the block page carries a reference (${REFERENCE})" \
    || fail "the block page carried no reference to look up"
assert_contains "$(php artisan firewall:find-reference "${REFERENCE}" 2>&1)" "127.0.0.1" \
    "firewall:find-reference resolves it to the client"

php artisan firewall:unblock 127.0.0.1 > /dev/null 2>&1 || true
assert_eq "200" "$(status_of /)" "the client is served again once the block is lifted"

# Blocking by hand takes effect on the next request, with no deploy — the
# reason the command exists.
php artisan firewall:block 127.0.0.1 --reason="Install test" > /dev/null 2>&1 \
    || fail "firewall:block refused to block the client"
assert_eq "400" "$(status_of /)" "a hand-written block is enforced on the next request"
php artisan firewall:unblock --all > /dev/null 2>&1 || true
assert_eq "200" "$(status_of /)" "firewall:unblock --all empties the list"

step "Probing health the way a monitor would"
# Exit code and JSON shape together, because that pair is the whole interface a
# monitoring check is written against — and a check keyed off a renamed field
# reports "healthy" forever rather than failing.
php artisan firewall:health > /dev/null 2>&1 || fail "firewall:health reported an unhealthy firewall"
pass "firewall:health exits 0"
HEALTH_JSON="$(php artisan firewall:health --json 2>/dev/null)"
assert_eq "true" "$(printf '%s' "${HEALTH_JSON}" | php -r 'echo json_decode(stream_get_contents(STDIN), true)["healthy"] ? "true" : "false";')" \
    "firewall:health --json reports healthy"
assert_eq "exception" "$(printf '%s' "${HEALTH_JSON}" | php -r 'echo json_decode(stream_get_contents(STDIN), true)["mode"];')" \
    "firewall:health --json reports the effective mode"

step "Checking the CLI agrees with the running application"
# `firewall:check` exits 1 when a request would be blocked. If the config the
# command translates ever drifted from the one the middleware builds, this is
# where it would show: the two would answer differently for the same URL.
if php artisan firewall:check --url=/wp-login.php --ip=203.0.113.9 > /dev/null 2>&1; then
    fail "firewall:check said /wp-login.php is allowed, but HTTP returned 400"
fi
pass "firewall:check agrees that /wp-login.php would be blocked"

step "Observing without enforcing"
# `log` mode is the assertion that matters most here, and it can only be made
# over HTTP. Under the `cli` SAPI the library returns before evaluating anything,
# so a test running in PHPUnit cannot tell a working `log` mode from a
# short-circuited one. Under `cli-server` it genuinely evaluates: the probe is
# served rather than blocked, and the decision is written to the log.
php "${PACKAGE_DIR}/tests/Integration/set-log-mode.php" config/firewall.php > /dev/null \
    || fail "could not switch the config to log mode"
stop_server
rm -f storage/logs/laravel.log
start_server

# 404, not 200: the probe is no longer blocked, so it falls through to Laravel's
# router and `/wp-login.php` has no route. That is the point — a 404 can only
# come from downstream of the firewall, so it proves the request was passed on
# rather than merely that it was not refused.
assert_eq "404" "$(status_of /wp-login.php)" "log mode passes the probe through to the router"

# And this is the assertion that pins down the SAPI question, because the status
# above cannot: a short-circuited firewall would also let the request through to
# a 404. Only a firewall that actually evaluated writes this line. Its presence
# under `artisan serve` is the evidence that `cli-server` is not `cli` and the
# library's CLI short-circuit does not apply here — which had been assumed the
# other way round until this script was written.
assert_contains "$(cat storage/logs/laravel.log 2>/dev/null || true)" \
    "would be blocked" "log mode evaluated and recorded the decision it declined to enforce"

printf '\n\033[32mInstall verified.\033[0m\n'
