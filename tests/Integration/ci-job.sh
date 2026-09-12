#!/usr/bin/env bash
#
# Run a CircleCI job's commands locally, in the image CI uses.
#
# This exists because of how the first two pipelines on this repository failed:
# one bug per run, each found only after a push, and the second one
# (`composer show` with three arguments) reproducible locally in under a second.
# Fixing CI by pushing and reading the result is a slow loop with a bad failure
# mode — the log shows the *first* command that exited non-zero, so a job with
# two faults hides the second until the first is fixed.
#
# So: run the whole job, in `cimg/php`, before pushing.
#
# Usage:
#   tests/Integration/ci-job.sh phpunit [php] [laravel-constraint]
#   tests/Integration/ci-job.sh static-analysis [php]
#
#   tests/Integration/ci-job.sh phpunit 8.3 '^13.0'
#
# Note this is slow on Apple silicon: `cimg/php` publishes amd64 only, so it
# runs under emulation. That is the cost of testing the actual CI image rather
# than an approximation of it, and it is the right trade for a pre-push check.
# `tests/Integration/matrix.sh` is the fast, native, multi-version counterpart —
# it runs the suite, not the job, and cannot catch a fault in the CI config.

set -uo pipefail

JOB="${1:-phpunit}"
PHP_VERSION="${2:-8.3}"
LARAVEL_VERSION="${3:-^13.0}"
PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="cimg/php:${PHP_VERSION}"

printf '\n\033[1mRunning the %s job\033[0m  PHP %s, Laravel %s, image %s\n\n' \
    "${JOB}" "${PHP_VERSION}" "${LARAVEL_VERSION}" "${IMAGE}"

# The commands below mirror .circleci/config.yml. They are duplicated rather
# than parsed out of the YAML, which is a real cost: the two can drift. Parsing
# them would need a YAML processor inside the container and would still not run
# CircleCI's own interpolation, so it would be a different approximation with
# more moving parts. The mitigation is that both are short and sit next to each
# other in review.
case "${JOB}" in
    phpunit)
        SCRIPT='
            set -e
            sudo pecl update-channels
            sudo pecl install xdebug
            php -m | grep -qi xdebug \
              || { echo "Xdebug did not enable; coverage would silently run no tests."; exit 1; }

            composer update --no-interaction --prefer-dist \
              --with "laravel/framework:${LARAVEL_VERSION}"

            for package in laravel/framework orchestra/testbench kanopi/firewall; do
              composer show "${package}" | grep -E "^(name|versions)"
            done

            composer test:gate

            PASSING=100
            php -d display_errors=stderr -r '"'"'
              $min = (float) $argv[1];
              $xml = simplexml_load_file("reports/xml/index.xml");
              if ($xml === false) {
                fwrite(STDERR, "Could not read reports/xml/index.xml\n");
                exit(1);
              }
              $totals = $xml->project->directory->totals;
              $metrics = ["lines" => "executable", "methods" => "count"];
              $failed = false;
              $measured = 0;
              foreach ($metrics as $metric => $denominator) {
                $node = $totals->{$metric};
                if ($node === null || (int) $node[$denominator] === 0) { continue; }
                ++$measured;
                $pct = (float) $node["percent"];
                printf("%s coverage %.2f%% against a %.2f%% floor.\n", ucfirst($metric), $pct, $min);
                if ($pct < $min) { $failed = true; }
              }
              if ($measured === 0) {
                fwrite(STDERR, "The coverage report contained neither lines nor methods.\n");
                exit(1);
              }
              exit($failed ? 1 : 0);
            '"'"' "${PASSING}"
        '
        ;;
    static-analysis)
        SCRIPT='
            set -e
            composer install --no-interaction --prefer-dist
            composer check:code
            composer check:security
        '
        ;;
    *)
        printf '\033[31mUnknown job "%s". Try phpunit or static-analysis.\033[0m\n' "${JOB}"
        exit 1
        ;;
esac

# `cimg` images run as the `circleci` user with a writable home, so the checkout
# is copied there rather than worked on in place — the mount is read-only for
# the same reason the matrix script uses one: a container must not leave a
# `vendor/` behind in the tree being edited.
docker run --rm \
    --platform linux/amd64 \
    -v "${PACKAGE_DIR}:/package:ro" \
    -e "LARAVEL_VERSION=${LARAVEL_VERSION}" \
    "${IMAGE}" \
    bash -lc "
        set -e
        cp -r /package \"\${HOME}/work\"
        cd \"\${HOME}/work\"
        rm -rf vendor composer.lock reports .phpunit.cache
        ${SCRIPT}
    "

STATUS=$?

if [[ "${STATUS}" -eq 0 ]]; then
    printf '\n\033[32mThe %s job passed.\033[0m\n' "${JOB}"
else
    printf '\n\033[31mThe %s job failed (exit %d).\033[0m\n' "${JOB}" "${STATUS}"
fi

exit "${STATUS}"
