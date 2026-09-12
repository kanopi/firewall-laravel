# Changelog

All notable changes to `kanopi/firewall-laravel` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

Initial release. Laravel integration for `kanopi/firewall` ^2.24.

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
- Laravel 10 and 11 are within the published constraint and covered by the code,
  but every release of both currently carries unresolved security advisories, so
  Composer's default audit refuses to install them and CI does not claim to test
  them.
