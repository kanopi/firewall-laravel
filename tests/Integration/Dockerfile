# Test image for one PHP version.
#
# Built on the official `php:<version>-cli` images rather than CircleCI's
# `cimg/php`, for one practical reason: `cimg/php` publishes amd64 only, so on
# an arm64 developer machine every command runs under emulation — slowly, and
# with enough rough edges that Composer produced no output at all when this was
# first tried. The official images are multi-arch, so the matrix runs natively
# wherever it is invoked.
#
# The trade is that this is not byte-for-byte the image CI uses. That is
# acceptable because what the matrix tests is *the PHP version*, not the
# distribution: same minor, same extensions, same Composer. CI runs the same
# script on its own images, so a difference that mattered would surface there.
ARG PHP_VERSION=8.3
FROM php:${PHP_VERSION}-cli

# git and unzip are Composer's, not ours: without them it falls back to cloning
# from source, which is slower and needs git anyway. `libzip` + `ext-zip` let it
# use dist archives, which is the fast path.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git unzip libzip-dev \
    && docker-php-ext-install zip \
    && rm -rf /var/lib/apt/lists/*

# Copied from the official Composer image rather than curl'd through the
# installer script: a pinned digest-addressable binary beats fetching and
# verifying a PHAR on every build, and the parent project learned the same
# lesson about mid-build downloads failing for reasons unrelated to the code.
COPY --from=composer/composer:2-bin /composer /usr/bin/composer

ENV COMPOSER_ALLOW_SUPERUSER=1 \
    COMPOSER_NO_INTERACTION=1 \
    COMPOSER_ROOT_VERSION=1.0.0

WORKDIR /package
