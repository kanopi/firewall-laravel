# Changelog

All notable changes to `kanopi/firewall-laravel` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0](https://github.com/kanopi/firewall-laravel/releases/tag/v1.3.0) — 2026-09-29

Support for kanopi/firewall 2.34: `firewall:check --script-name`, and guidance
on the library's new `global.path_source`, including a `firewall:doctor` check
for the one setting that silently breaks path rules in a Laravel app.

### Upgrading

Nothing to change in your configuration. The new library minimum brings three
library releases with it; these are the changes worth knowing about:

- **`firewall:check` exits `3` for a redirect** (2.33.1). It used to exit `70`.
  A script that treats every non-zero exit as "blocked" now also treats a
  redirect as blocked.
- **A `start-end` range in `global.lockdown_allow` now matches** (2.33.1). It
  used to match nobody, so an allowlist that was locking out its own office
  starts serving it. `firewall:doctor` can now report an error on a lockdown
  allowlist entry that can never match, which turns a deploy gate red.
- **A rate-limit `key:` naming a capitalised `post`, `cookie` or `query` field
  now counts per value** (2.33.2). It used to be one counter for everybody.
  That old shared counter is dropped once, at upgrade.
- **Block records store a direct file's URL without a trailing slash** (2.34).
- **A `bot:true` rule now matches Nikto** (2.34). The library requires
  `matomo/device-detector` ^6.5.2, which adds it.

### Changed

- **Requires `kanopi/firewall` ^2.34** (was ^2.33). No library API this package
  calls was removed or changed.

### Added

- **`firewall:check --script-name` (#41)** checks a request for a PHP file the
  web server runs directly, as WordPress serves `/wp-login.php`, the way the
  site receives it. A Laravel app serves everything through
  `public/index.php`, so it rarely needs this. The script's note about
  direct-file URLs goes to stderr, so `--json` output still parses.
- **`firewall:doctor` checks `global.path_source` (#42).** The library's
  `script_name` source (2.34) is for sites whose server runs PHP files other
  than the front controller. A Laravel app does not need it, so it is a
  warning. It is an **error** when `APP_URL` shows a subdirectory that
  `global.base_path` does not name: every request then resolves to
  `/<subdirectory>/index.php`, no path rule matches, and nothing reports it at
  runtime.

### Documentation

- The README and `config/firewall.php` say to leave `path_source` at its
  default, and why.
- `firewall:check`'s exit codes list the redirect verdict (`3`) alongside
  allowed (`0`), blocked (`1`) and challenged (`2`).

## [1.2.0](https://github.com/kanopi/firewall-laravel/releases/tag/v1.2.0) — 2026-09-27

The last test gaps from the 1.1.0 review are closed. The firewall now runs in
CI against real Redis and Memcached servers and under a real Octane worker.
The Octane test found a bug, and this release fixes it.

### Upgrading

Nothing to change. One behaviour change, and only if you set
`firewall.octane.persist_instance = true` under Octane:

- **The firewall is now built once per worker, as documented.** Until now it
  was rebuilt on every request, so a panic file took effect immediately even
  with this option on. It no longer does: a persistent instance keeps the mode
  it booted with until the workers restart, which is the caveat the README has
  always described and `firewall:doctor` already reports. Leave
  `persist_instance` off (the default) if you rely on the panic switch.

### Fixed

- **`octane.persist_instance` did not persist the firewall under Octane
  (#38).** Octane serves each request from a clone of the worker's
  application, so a singleton first resolved during a request was discarded
  with the clone. The option did nothing, and the firewall was rebuilt per
  request like the default. It is now built when the worker starts (Octane's
  `WorkerStarting` event), on the worker's own application. If it cannot be
  built then, that is logged and it is built per request under the usual
  `on_boot_failure` policy, rather than stopping the worker from booting.

### Tests

- **Real Octane worker (#17).** `composer test:octane` and a new CircleCI
  `octane` job run the firewall under RoadRunner with two workers. They check:
  - enforcement, although RoadRunner's `PHP_SAPI` is `cli`
  - a block lifted from the CLI applying on the next request
  - a panic file honoured by every worker on the next request, with no reload
  - as a control, a `persist_instance` worker ignoring that same panic file
- **Real Redis and Memcached (#17).** A new `services` suite
  (`composer test:services` in Docker, and a CircleCI `services` job with the
  servers as service containers) covers:
  - a block earned in one process and enforced by the next
  - a Redis rate limit counted across requests
  - range lifts through the real Memcached index
  - a 90-day Memcached ban
  - `SharedStorage` mirroring locally and falling back when Redis is down

  It is not part of `composer test`. `FIREWALL_SERVICES_REQUIRED=1` turns a
  missing server into a failure instead of a skip.

## [1.1.0](https://github.com/kanopi/firewall-laravel/releases/tag/v1.1.0) — 2026-09-27

Support for kanopi/firewall 2.33, and the fixes from a pre-release review.
One of those fixes is urgent for anyone on 1.0.0: a common Laravel logging
setup made every request return a 500.

### Upgrading

Nothing to change in your configuration. Three behaviours change with this
release. Check them against your deploy and monitoring:

- **`global.require_config: true` now fails the boot on a missing `configs`
  file.** Before, the file was dropped silently and the firewall ran without
  those rules. If a path listed under `configs` doesn't exist, the firewall now
  refuses to start (handled by `on_boot_failure`).
- **`firewall:health --json`: `healthy` is false whenever `errors` is not
  empty**, including a panic file that failed to apply.
- **`firewall:check` exits 70 when the wrapper itself fails** (the script is
  missing, or the configuration cannot be written out), not 1 or 2, which are
  its "blocked" and "challenged" verdicts. The other wrapped commands exit 2 in
  that case, and report an unwritable `temp_path` as an error instead of
  throwing.

Upgrading the library also brings its own behaviour changes, worth reading
before deploying:
- block records no longer keep cookies, most headers or the request body (2.31)
- a challenge pass lasts at most `challenge.ttl`, an hour by default (2.30)
- a rule source larger than 32 MiB fails instead of loading (2.30)
- a request with no client address is no longer added to the block list (2.33)

### Changed

- **Requires `kanopi/firewall` ^2.33** (was ^2.26). No library API this package
  calls was removed or changed.

### Fixed

- **Borrowed log handlers took down every request (#4).** The handlers this
  package borrows from your Laravel log channel went into the library's config
  input, which the library serializes to key its cache. A handler holding a
  closure (for example a processor pushed from a channel `tap`) threw on every
  request, even with `on_boot_failure=allow`, and serializing the rest closed
  the application's own handlers, discarding a `FingersCrossedHandler`'s
  buffer. They are now delivered as overrides, which are never serialized.
- **`require_config` could not catch a missing `configs` file (#19).** See
  Upgrading.
- **Solved challenges looped with the middleware in the `web` group (#5).**
  `EncryptCookies` discarded the raw pass cookie. The cookie is now excluded
  from encryption.
- **A missing challenge view served a blank page (#6).** Visitors had nothing
  to solve. The interstitial is now served on its own.
- **`response: redirect` raised from your own code was a 500 (#7).** It now
  renders as a redirect.
- **`--json` output could not be parsed (#8).** `firewall:doctor --json`
  printed two documents, and wrapped scripts' warnings went to stdout. It is now
  one document (`integration` and `library`), and stderr goes to stderr.
- **Wrapper failures looked like `firewall:check` verdicts (#11).** See
  Upgrading.
- **`firewall:block --duration=-60` created a permanent block (#9).** Negative
  durations are refused.
- **`firewall:health` reported `healthy: true` beside errors (#10).** See
  Upgrading.
- **Block commands drew conclusions from an incomplete Memcached index (#20).**
  `unblock --all`, range lifts and a `find-reference` miss are refused while
  the index reports a gap. A single exact address is lifted by key on any
  backend, including `SharedStorage`, which used to be refused.
- **`SharedStorage` (#21):** the local fallback store's directory is now
  created, and `firewall:block` warns when only the local copy was written.
- **`firewall:rule list` and `--dry-run` created the managed rules file
  (#12).**
- **The banning message was HTML-escaped twice (#14).** JSON clients were also
  given the wrong challenge URL on sites served from a subdirectory.
- **The pass cookie's lifetime came from the visitor.** It is now read from the
  solved token's signed expiry.
- **`tarpit`, `events`, `metrics` and `connections` in `config/firewall.php`
  were dropped silently.** They are now passed through.

### Added

- **`firewall:challenge` (#16)** inspects a challenge pass, or revokes one
  without rotating the secret for everybody (wraps `bin/firewall-challenge`).
- **`firewall:health` reports `sleeping_rules` and `locked_down` (#13).**
  Lockdown is a warning. A rule outside its schedule is listed but is not a
  warning.
- **`firewall:doctor` understands `global.trusted_proxies`** (2.33), and warns
  when both Laravel and the firewall declare proxies.

### Tests

- A real-shaped Laravel log channel, `DatabaseStorage` on SQLite,
  `SharedStorage`, a Memcached-style index gap, per-route registration in the
  `web` group, and parsed `--json` output.
- The install test now runs `php artisan optimize` and repeats its HTTP checks
  against cached config and routes.
- CI gains a lowest-dependencies job.

## [1.0.0](https://github.com/kanopi/firewall-laravel/releases/tag/v1.0.0) — 2026-09-12

### Added

Initial release. Laravel integration for `kanopi/firewall` ^2.26.

- **`EvaluateFirewall` middleware**, registered into the global stack after
  `TrustProxies`. `Illuminate\Http\Request` is passed to `evaluate()` unchanged —
  it already extends the Symfony request the library expects, and converting it
  would discard the trusted-proxy state every IP rule depends on.
- **`block` mode is delivered as `exception` mode**, so the library never calls
  `exit()` mid-request. Delivered as a PropertyAccess override so no preset can
  reintroduce it, and the outcome is asserted after `create()` because
  `Config::load()` swallows an override it cannot apply.
- **Publishable `config/firewall.php`**, using the library's own section names so
  its documentation remains the reference for rule syntax. Adds `presets`,
  `env()`-driven values, Laravel paths, and the framework-only `middleware`,
  `octane`, `views` and `artisan` sections.
- **Trusted-proxy bridge** reading all three of Laravel's mechanisms —
  `TrustProxies::at()`, `config('trustedproxy.proxies')`, and the `$proxies`
  property on an application's own subclass — so proxies are not configured
  twice. Middleware ordering is verified per request and reported, or refused,
  when the firewall would be reading a spoofable client address.
- **Challenge round-trip**, including a dedicated CSRF-free `POST` route on
  `challenge.path` so a challenged visitor can always solve even when the
  middleware is not global.
- **Publishable Blade views** for the block page and the challenge wrapper, plus
  `renderable()` handlers so a block raised outside the middleware still renders
  as a block rather than a 500.
- **PSR-14 bridge** wiring Laravel's dispatcher into `Firewall::create()`, so
  listeners register against the library's event classes directly.
- **`HealthReport`** surfacing failed rules, degraded backends, the effective and
  configured modes, and the panic switch.
- **Eight Artisan commands** wrapping the library's `bin/` scripts as
  subprocesses, with the effective configuration translated to YAML and the
  challenge secret passed by environment rather than written to disk.
- **`firewall:doctor`** running Laravel-specific integration checks alongside the
  library's own, and failing if either half does.
- **`firewall:block`, `firewall:unblock` and `firewall:find-reference`** — the
  three operations the library's `bin/` scripts do not provide, written against
  its public API rather than forwarded to a subprocess. `bin/firewall-block`
  can list, find, show and lift but cannot *add*, and nothing upstream can turn
  a reference number from a block page back into a client. The listing wrapper
  is now `firewall:blocks`, plural, so adding and reading are separate verbs and
  the destructive one is not a typo away from the harmless one.
- **`firewall:health`**, a monitoring probe: exit 0 when healthy, 1 when a rule
  is not running or a panic file did not take, and `--json` in a fixed flat
  shape a check can key off. Distinct from `firewall:doctor`, which asks whether
  the firewall is *configured* correctly and answers in prose for a person;
  health asks whether it is *working*, repeatedly, for a script. It is also the
  only surface that reports `degraded_backends` — a store a successfully-built
  rule cannot reach, which no static check can see.
- **Storage directories are created** for file-based paths under
  `storage_path()`, because `FileStorage` creates its data file but not the
  directory holding it. Without this a freshly published config failed on its
  first request — and, with the default fail-closed policy, on every request
  after it. Paths outside `storage_path()` are left alone and reported by
  `firewall:doctor` instead.

### Requires kanopi/firewall ^2.26

2.26 added three response types and a lockdown mode. Two needed work here.

- **`response: redirect`** raises `FirewallRedirectException`. The middleware
  now dispatches on the base `FirewallException` and routes by type, rather than
  enumerating catch clauses — so a decision this package has not been taught yet
  fails closed under the documented policy instead of falling through whichever
  clause happens to be last. Unhandled, a redirect rule would have produced a
  500, or an unfiltered pass-through when configured to fail open.
- **`mode: lockdown`** is shorthand: the library sets its lockdown flag and
  rewrites its own mode to `block`, which calls `exit()`. It is translated to
  `global.lockdown: true` delivered as `exception`. Without that the boot guard
  refused to start, reporting a failed mode override to an operator who had
  asked for lockdown and done nothing wrong. `global.lockdown` set directly is
  passed through untouched, including an explicit `false`.
- **`FirewallLockdownException`** extends `FirewallBlockedException`, so the
  block view already rendered it. Refusals now carry `Retry-After`, and the view
  receives `$retry_after` — a lockdown is temporary and a ban is not.
- **`response: record` and `response: mark`** are non-terminal and needed no
  middleware change. Marks reach the application as request attributes because
  Laravel's own request object is handed to `evaluate()` rather than converted.
  The three new events reach Laravel listeners through the existing PSR-14
  bridge.

### Removed

- **The per-plugin challenge provider limitation is gone.** 2.26's
  `ChallengeRequiredException` carries the provider and render context, so
  `renderInterstitial()` replaces the provider this package used to rebuild from
  `challenge.provider` — which rendered the wrong challenge for any rule using
  `metadata.challenge_provider`, and could not be fixed here because signing the
  provider token needed a private prefix. The `firewall:doctor` check that
  reported it as unsupported is removed, as is a redirect sanitiser that
  duplicated a rule the library now supplies.

### Fixed during pre-release verification

Both found by installing the package into a real Laravel application. Both were
invisible to a fully green PHPUnit suite, which is why
`tests/Integration/install.sh` now exists and runs in CI.

- **A clean install 500'd on every request.** `FileStorage` creates its data
  file but not the directory holding it, and the published default is
  `storage/firewall/`. With the fail-closed default that is every request, not
  just the first. Directories under `storage_path()` are now created; paths
  outside it are left alone and reported by `firewall:doctor`.
- **The firewall logged nowhere by default.** The shipped config read
  `config('logging.default')`, and Laravel loads config files alphabetically —
  so `firewall.php` is evaluated before `logging.php` and the call returned
  NULL. Every block, every rule that failed to build and every degraded backend
  was discarded on a default installation. Now `env('LOG_CHANNEL', 'stack')`,
  with a structural test asserting the config file calls no `config()` at all.

### Corrected

- **`artisan serve` is not affected by the library's CLI short-circuit.** It
  runs under `cli-server`, not `cli`. Earlier documentation and the
  `firewall:doctor` message said otherwise, which would have sent operators
  looking for a problem that does not exist in their development environment.
  Octane on RoadRunner and Swoole *are* affected — their workers are `cli` —
  and that is what the check now says. Verified over HTTP rather than reasoned
  about.

### Testing

- **`composer show` takes one package, not three.** The phpunit job printed its
  resolved versions with `composer show laravel/framework orchestra/testbench
  kanopi/firewall`, which is a usage error — it exits 1 and failed every phpunit
  job before a test ran. This was the fault the *first* pipeline was reporting;
  it was misdiagnosed as the coverage problem below, which is real but sits
  downstream and was never reached.
- **`tests/Integration/ci-job.sh`** runs a CI job's own commands inside
  `cimg/php`, so a fault in the CI configuration is found before a push rather
  than one per pipeline. A pipeline reports only the first command that exited
  non-zero, so a job with two faults hides the second until the first is fixed —
  which is exactly what happened here.
- **CI installs Xdebug for the phpunit jobs.** `cimg/php` ships no coverage
  driver, and `phpunit.xml` declares `<coverage>` with `failOnWarning` — so
  PHPUnit raised a runner warning and executed **zero tests**. The first
  pipeline on this repository failed that way in all seven phpunit jobs while
  static analysis and both install jobs passed, which is the shape that gives
  it away. `composer test:gate` now refuses to start without a driver and says
  which extension is missing, rather than reporting "No tests executed!".

- **`tests/Integration/matrix.sh`** runs the suite in Docker across PHP 8.1–8.5
  against Laravel 12 and 13, on the official multi-arch `php:<version>-cli`
  images. The support table in the README is its output rather than an
  assertion. It found a test that passed on macOS and failed as root in a
  container — the unwritable path it used, `/no/such/directory`, is one root can
  create, so the assertion had been testing the developer's permissions.

### Notes

- The firewall is bound with `scoped()`, not `singleton()`, so the panic switch
  works under Octane. `octane.persist_instance` opts into a true singleton;
  `firewall:doctor` reports that combined with a panic file as an error.
- Per-plugin `metadata.challenge_provider` is not supported and is reported as
  an error by `firewall:doctor`. `ChallengeRequiredException` does not carry the
  matched plugin, so the interstitial can only be rendered from
  `challenge.provider`. Fixing it needs a change in `kanopi/firewall`.
- Laravel 10 and 11 are **not** in the published constraint, and `php: >=8.2`
  rather than the library's own `>=8.1`. Every 10.x and 11.x release currently
  carries unresolved security advisories, so Composer's default audit refuses to
  install them — nothing can test them, and a constraint is a promise. Widening
  later is a minor release; narrowing is a major one, so 1.0.0 starts narrow.
