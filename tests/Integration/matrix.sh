#!/usr/bin/env bash
#
# Run the test suite across PHP and Laravel versions, in Docker.
#
# The versions this package claims to support are wider than any one machine
# has installed, and "it passes here" is a claim about one PHP build with one
# set of extensions. This runs the same suite against each combination in a
# container, so the support table in the README is something that was measured
# rather than assumed — and so anyone can re-measure it without installing five
# PHP versions.
#
# Each cell is independent: its own container, its own `composer update`, its
# own lock resolution. That is deliberate. A shared `vendor/` would let one
# cell's resolution mask another's conflict, which is the exact failure a
# version matrix exists to catch.
#
# Usage:
#   tests/Integration/matrix.sh                     # every supported cell
#   tests/Integration/matrix.sh 8.3                 # one PHP version, both Laravels
#   tests/Integration/matrix.sh 8.3 '^13.0'         # one cell
#   FIREWALL_MATRIX_LOWEST=1 tests/Integration/matrix.sh    # --prefer-lowest
#
# Exit codes:
#   0  every installable cell passed
#   1  a cell failed, or a cell that should have been installable was not
#
# A cell below a Laravel version's PHP floor is expected not to install and is
# reported as SKIP. Every other resolution failure is a FAIL. The floors are
# declared below as data rather than inferred from Composer's message, because
# that message does not say what it means: on PHP 8.1 the real cause is that no
# compatible `orchestra/testbench` exists, and Composer reports it as a conflict
# with the Laravel constraint. Classifying on the message would mean reading
# tea leaves; classifying on a declared floor means a cell that quietly stops
# installing still fails the run.

set -uo pipefail

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_PREFIX="kanopi-firewall-laravel-test"

# The cells. PHP 8.1 is present and expected to skip: the package declares
# `php: >=8.1` because its own code is 8.1-compatible, and no Laravel this
# package supports can be installed there — 12 needs 8.2, 13 needs 8.3, and
# 10 and 11 are blocked by unresolved security advisories. Listing it makes
# that a measured fact in the output rather than a footnote.
PHP_VERSIONS=(8.1 8.2 8.3 8.4 8.5)
LARAVEL_CONSTRAINTS=('^12.0' '^13.0')

# The PHP floor each Laravel version imposes, as a fact rather than a guess.
# Laravel 12 requires PHP ^8.2 and Laravel 13 requires ^8.3; `orchestra/testbench`
# matches those. A cell below its floor is expected not to install.
minimum_php_for() {
    case "$1" in
        '^12.0') echo "8.2" ;;
        '^13.0') echo "8.3" ;;
        # An unrecognised constraint has no declared floor, so nothing is
        # excused: it has to install and pass like any other cell.
        *) echo "0.0" ;;
    esac
}

# TRUE when $1 is an older version than $2. `sort -V` rather than a numeric
# comparison, because "8.10" must sort after "8.9" and as a float it does not.
version_lt() {
    [[ "$1" != "$2" ]] && [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]
}

if [[ $# -ge 1 ]]; then PHP_VERSIONS=("$1"); fi
if [[ $# -ge 2 ]]; then LARAVEL_CONSTRAINTS=("$2"); fi

PREFER_LOWEST=""
if [[ -n "${FIREWALL_MATRIX_LOWEST:-}" ]]; then
    PREFER_LOWEST="--prefer-lowest --prefer-stable"
fi

FAILED=0
RESULTS=()

printf '\n\033[1mTest matrix\033[0m  (package: %s)\n' "${PACKAGE_DIR}"

for php in "${PHP_VERSIONS[@]}"; do
    image="${IMAGE_PREFIX}:${php}"

    printf '\n\033[1m==> Building the PHP %s image\033[0m\n' "${php}"
    if ! docker build \
        --quiet \
        --build-arg "PHP_VERSION=${php}" \
        -t "${image}" \
        -f "${PACKAGE_DIR}/tests/Integration/Dockerfile" \
        "${PACKAGE_DIR}/tests/Integration" > /dev/null; then
        printf '    \033[31mFAIL\033[0m could not build the PHP %s image\n' "${php}"
        RESULTS+=("PHP ${php} — image build FAILED")
        FAILED=1
        continue
    fi

    for constraint in "${LARAVEL_CONSTRAINTS[@]}"; do
        floor="$(minimum_php_for "${constraint}")"

        if version_lt "${php}" "${floor}"; then
            printf '\033[1m--> PHP %s, laravel/framework %s\033[0m\n' "${php}" "${constraint}"
            printf '    \033[33mskip\033[0m needs PHP %s or newer\n' "${floor}"
            RESULTS+=("PHP ${php} + Laravel ${constraint} — skipped, needs PHP ${floor}+")
            continue
        fi

        printf '\033[1m--> PHP %s, laravel/framework %s\033[0m\n' "${php}" "${constraint}"

        # The package is mounted read-only and copied inside. Composer writes a
        # lock file and a vendor tree, and neither belongs in the working tree
        # the developer is editing — a matrix run that left `vendor/` resolved
        # for PHP 8.1 behind would break the next local test run in a way that
        # looks like a code problem.
        output="$(docker run --rm \
            -v "${PACKAGE_DIR}:/package:ro" \
            "${image}" \
            bash -c "
                set -e
                cp -r /package /work
                cd /work
                rm -rf vendor composer.lock reports .phpunit.cache
                composer update --no-interaction --no-progress ${PREFER_LOWEST} \
                    --with 'laravel/framework:${constraint}' 2>&1 | tail -20
                echo '---RESOLVED---'
                composer show laravel/framework 2>/dev/null | grep '^versions' || true
                echo '---TESTS---'
                vendor/bin/phpunit --no-coverage 2>&1 | tail -6
            " 2>&1)"

        laravel="$(printf '%s' "${output}" | sed -n 's/^versions *: *\* *//p' | head -1)"
        verdict="$(printf '%s' "${output}" | grep -oE 'OK \([0-9]+ tests, [0-9]+ assertions\)|FAILURES!|ERRORS!' | head -1)"

        if [[ -n "${verdict}" && "${verdict}" == OK* ]]; then
            printf '    \033[32mok\033[0m   Laravel %s — %s\n' "${laravel}" "${verdict}"
            RESULTS+=("PHP ${php} + Laravel ${laravel} — ${verdict}")
            continue
        fi

        # Anything that gets here was above its declared floor, so it was
        # expected to install and pass. The output is printed in full rather
        # than summarised: a matrix that says "FAIL" without saying why costs
        # more time than it saves.
        printf '    \033[31mFAIL\033[0m Laravel %s\n' "${constraint}"
        printf '%s\n' "${output}" | sed 's/^/        /'
        RESULTS+=("PHP ${php} + Laravel ${constraint} — FAILED")
        FAILED=1
    done
done

printf '\n\033[1mSummary\033[0m\n'
for line in "${RESULTS[@]}"; do
    printf '  %s\n' "${line}"
done

if [[ "${FAILED}" -ne 0 ]]; then
    printf '\n\033[31mAt least one cell failed.\033[0m\n'
    exit 1
fi

printf '\n\033[32mEvery installable cell passed.\033[0m\n'
