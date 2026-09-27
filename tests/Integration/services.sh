#!/usr/bin/env bash
#
# Run the services suite against real Redis and Memcached, in Docker.
#
#   composer test:services            # PHP 8.3
#   bash tests/Integration/services.sh 8.4
#
# The same arrangement as the CircleCI `services` job: the two servers as
# their own containers, the suite in a third with ext-redis and ext-memcached,
# all on one network so the tests reach them by name. The suite is told the
# servers are required, so a missing extension or an unreachable server fails
# the run instead of skipping its way to a green result that tested nothing.

set -uo pipefail

PHP_VERSION="${1:-8.3}"
PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="kanopi-firewall-laravel-services:${PHP_VERSION}"
NETWORK="kanopi-firewall-laravel-services-$$"
REDIS="${NETWORK}-redis"
MEMCACHED="${NETWORK}-memcached"

cleanup() {
    docker rm -f "${REDIS}" "${MEMCACHED}" > /dev/null 2>&1 || true
    docker network rm "${NETWORK}" > /dev/null 2>&1 || true
}
trap cleanup EXIT

printf '\n\033[1m==> Building %s\033[0m\n' "${IMAGE}"
docker build --quiet --build-arg "PHP_VERSION=${PHP_VERSION}" \
    -f "${PACKAGE_DIR}/tests/Integration/Dockerfile.services" \
    -t "${IMAGE}" "${PACKAGE_DIR}/tests/Integration" > /dev/null \
    || { echo "image build failed"; exit 1; }

printf '\033[1m==> Starting Redis and Memcached\033[0m\n'
docker pull --quiet redis:7.4 > /dev/null && docker pull --quiet memcached:1.6.41 > /dev/null \
    || { echo "could not pull the server images"; exit 1; }
docker network create "${NETWORK}" > /dev/null
# Pinned to the versions the CI job uses.
docker run -d --rm --name "${REDIS}" --network "${NETWORK}" redis:7.4 > /dev/null
docker run -d --rm --name "${MEMCACHED}" --network "${NETWORK}" memcached:1.6.41 > /dev/null

printf '\033[1m==> Running the services suite\033[0m\n'
# The checkout is mounted read-only and copied in, so the container's
# `composer update` writes neither the host's vendor/ (resolved for the host's
# PHP) nor its composer.lock.
docker run --rm --network "${NETWORK}" \
    -v "${PACKAGE_DIR}:/src:ro" \
    -e REDIS_HOST="${REDIS}" -e REDIS_PORT=6379 \
    -e MEMCACHED_HOST="${MEMCACHED}" -e MEMCACHED_PORT=11211 \
    -e FIREWALL_SERVICES_REQUIRED=1 \
    "${IMAGE}" bash -c '
        set -e
        mkdir -p /work
        tar -C /src --exclude=./vendor --exclude=./composer.lock --exclude=./reports -cf - . | tar -C /work -xf -
        cd /work
        composer update --no-interaction --prefer-dist --quiet
        php -m | grep -E "^(redis|memcached)$"
        composer phpunit:services
    '
