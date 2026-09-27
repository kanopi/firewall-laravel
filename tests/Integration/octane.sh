#!/usr/bin/env bash
#
# Run the firewall under a real Laravel Octane worker (RoadRunner) and check
# the three things the README's Octane section claims (#17):
#
#   1. Enforcement works in a long-lived worker, although RoadRunner reports
#      PHP_SAPI as `cli`, the side of the library's CLI short-circuit that
#      skips evaluation. `exception` mode opts out of it, and this package
#      always runs the library in `exception` mode.
#   2. The binding is scoped, so the firewall is rebuilt for every request:
#      a panic file written while the workers are running takes effect on the
#      next request, with no reload.
#   3. A block lifted from the CLI stops applying on the next request, with no
#      reload: nothing about the block list is kept in the worker.
#
# And a control: with `octane.persist_instance` on, the same panic file is
# ignored until the workers restart, as documented. Without it, the second
# claim could pass for some reason other than the scoped binding.
#
#   composer test:octane
#   bash tests/Integration/octane.sh ^13.0
#
# Slow: it creates a Laravel application, installs Octane and downloads the
# RoadRunner binary. Set FIREWALL_INSTALL_KEEP=1 to keep the application.

set -euo pipefail

LARAVEL_CONSTRAINT="${1:-}"
PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/firewall-octane-XXXXXX")"
SERVE_LOG="$(mktemp "${TMPDIR:-/tmp}/firewall-octane-log-XXXXXX")"
PORT="$(php -r '$s = stream_socket_server("tcp://127.0.0.1:0"); echo (int) explode(":", stream_socket_get_name($s, false))[1];')"
SERVER_PID=""

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
pass() { printf '    \033[32mok\033[0m   %s\n' "$1"; }

stop_server() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        # octane:start handles SIGTERM by stopping RoadRunner and its workers.
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

fail() {
    printf '    \033[31mFAIL\033[0m %s\n' "$1"
    if [[ -s "${SERVE_LOG}" ]]; then
        printf '\n--- octane:start ---\n'
        tail -30 "${SERVE_LOG}"
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

status_of() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:${PORT}$1"
}

start_server() {
    php artisan octane:start --server=roadrunner --host=127.0.0.1 --port="${PORT}" \
        --workers=2 --no-interaction >> "${SERVE_LOG}" 2>&1 &
    SERVER_PID=$!

    for _ in $(seq 1 80); do
        if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${PORT}/"; then
            return 0
        fi
        sleep 0.25
    done

    fail "the Octane server never came up"
}

step "Creating a Laravel application"
composer create-project laravel/laravel "${APP_DIR}" \
    --no-interaction --quiet --no-scripts ${LARAVEL_CONSTRAINT:+"${LARAVEL_CONSTRAINT}"}
cd "${APP_DIR}"
php -r 'file_exists(".env") || copy(".env.example", ".env");'
php artisan key:generate --quiet

# Array drivers for the same reason as install.sh: no database to provision.
# The panic file is named up front, because the panic switch is configuration
# read at boot; only the file's contents are meant to change at runtime.
php -r '
$env = (string) file_get_contents(".env");
foreach (["SESSION_DRIVER" => "array", "CACHE_STORE" => "array", "FIREWALL_PANIC_FILE" => getcwd() . "/storage/firewall/panic"] as $key => $value) {
    $env = preg_replace("/^{$key}=.*$/m", "{$key}={$value}", $env, 1, $count);
    if ($count === 0) {
        $env .= PHP_EOL . "{$key}={$value}";
    }
}
file_put_contents(".env", $env);
'

step "Installing kanopi/firewall-laravel and Octane"
composer config repositories.firewall-laravel \
    "{\"type\": \"path\", \"url\": \"${PACKAGE_DIR}\", \"options\": {\"symlink\": false}}" --json
composer config minimum-stability dev
composer config prefer-stable true
composer require "kanopi/firewall-laravel:*@dev" laravel/octane spiral/roadrunner-cli spiral/roadrunner-http \
    --no-interaction --quiet || fail "composer require failed"
php artisan vendor:publish --tag=firewall-config --quiet
php "${PACKAGE_DIR}/tests/Integration/add-rule.php" config/firewall.php > /dev/null \
    || fail "could not add a rule to the published config"
# Downloads the RoadRunner binary for this platform into the application.
php artisan octane:install --server=roadrunner --no-interaction > /dev/null 2>&1 \
    || fail "octane:install --server=roadrunner failed"
[[ -x ./rr ]] || fail "the RoadRunner binary was not downloaded"
pass "Octane $(composer show laravel/octane | grep -E '^versions' | awk '{print $NF}') with RoadRunner $(./rr --version 2>/dev/null | awk '{print $3}')"

step "Enforcing in a long-lived worker"
start_server
assert_eq "200" "$(status_of /)" "a normal request is served by the Octane worker"
assert_eq "400" "$(status_of /wp-login.php)" "a probe is blocked, although the worker's SAPI is cli"

step "Lifting a block without a reload"
# The probe earned a durable block; everything from this client is refused.
assert_eq "400" "$(status_of /)" "the repeat-offender list blocks the client"
php artisan firewall:unblock --all > /dev/null 2>&1 || fail "firewall:unblock --all failed"
assert_eq "200" "$(status_of /)" "the next request, in the same workers, is served"

step "Throwing the panic switch without a reload"
mkdir -p storage/firewall
printf 'disabled\n' > storage/firewall/panic
# 404 rather than 400: the probe reached Laravel's router, so the firewall
# evaluated nothing. Several requests, because which worker answers is
# RoadRunner's choice: every one of them has to have noticed.
CODES=""
for path in /wp-login.php /wp-config.php /wp-admin /wp-login.php /wp-cron.php /wp-json; do
    CODES="${CODES}$(status_of "${path}") "
done
assert_eq "404 404 404 404 404 404 " "${CODES}" "the panic file disables the firewall in every worker, on the next request"
rm -f storage/firewall/panic
assert_eq "400" "$(status_of /wp-login.php)" "removing it restores enforcement on the next request"
php artisan firewall:unblock --all > /dev/null 2>&1 || true
stop_server

step "The control: a persistent instance does not see the panic file"
# The same steps with `octane.persist_instance` on, which binds a true
# singleton. The panic file must now be ignored until the workers restart —
# the caveat the README documents, and the proof that the step above passed
# because of the scoped binding rather than despite it.
php -r '
$env = (string) file_get_contents(".env");
file_put_contents(".env", rtrim($env) . PHP_EOL . "FIREWALL_OCTANE_PERSIST=true" . PHP_EOL);
'
start_server
assert_eq "200" "$(status_of /)" "the persistent worker serves a normal request"
printf 'disabled\n' > storage/firewall/panic
CODES=""
for path in /wp-login.php /wp-config.php /wp-admin /wp-login.php; do
    CODES="${CODES}$(status_of "${path}") "
    php artisan firewall:unblock --all > /dev/null 2>&1 || true
done
assert_eq "400 400 400 400 " "${CODES}" "a persistent instance ignores a panic file written after boot"
rm -f storage/firewall/panic
stop_server

printf '\n\033[32mOctane verified.\033[0m\n'
