# kanopi/firewall-laravel

Laravel integration for [`kanopi/firewall`](https://github.com/kanopi/firewall).

The library is a framework-agnostic request evaluator built on Symfony
HttpFoundation. It evaluates a request against configured rules and blocks,
allows or challenges it. It is not a WAF appliance — it is middleware-shaped
logic that shipped without any middleware. This package is the middleware, plus
the configuration, the responses, the event wiring and the Artisan surface
around it.

```bash
composer require kanopi/firewall-laravel
php artisan vendor:publish --tag=firewall-config
php artisan firewall:doctor
```

That is the whole installation. The middleware registers itself into the global
stack, positioned after `TrustProxies`; nothing needs editing in
`bootstrap/app.php`, and `storage/firewall/` is created on first use.

Verified by installing into a fresh `laravel/laravel` app: those three commands,
then a request to `/wp-login.php` with one `Url` rule configured, returns a
rendered 400 while `/` still returns 200.

### What the host application has to provide

Nothing, for the default configuration. Everything below is only needed if you
opt into the feature beside it:

| If you use | You need |
|---|---|
| The default `FileStorage` | Nothing — `storage/` is already writable and the subdirectory is created for you. Note it is **per-server**, so more than one web node wants one of the next two rows. |
| `DatabaseStorage` | A reachable database, and `php artisan firewall:migrate` in your deploy. Unreachable is a startup failure, not a silent one. |
| `RedisStorage` / Redis rate limiting | `ext-redis`. Every other backend works without it. |
| `response => challenge` rules | `FIREWALL_CHALLENGE_SECRET` set to a long random string. An empty secret is refused at boot. |
| Turnstile or reCAPTCHA challenges | The service's `site_key` and `secret_key` in `challenge.provider_options`. |
| The `GeoLocation` or `Asn` plugins | A GeoLite2 database on disk, and something keeping it fresh. |
| `metadata.sources` rule lists | `php artisan firewall:sources` on a schedule, plus `sources.offline: true`. |
| The panic switch | A path outside the document root and outside the deployed tree, writable by an operator and readable by the web user. |
| Anything behind a load balancer or CDN | `TrustProxies` configured — see trap 3. Set `global.require_trusted_proxies => true` to make a missing one fail the deploy. |

Run `php artisan firewall:doctor` after any of those. It reads the live
environment rather than the config in the abstract: it opens the storage file,
reaches the database, checks the GeoIP database's age, and builds every rule to
find out whether it can be built. Add it to your deploy — a warning does not
fail the command, so a stale GeoIP database will not block a release, but a rule
that cannot run will.

## Contents

- [Why Laravel is nearly free](#why-laravel-is-nearly-free)
- [The four things that fail silently](#the-four-things-that-fail-silently)
- [Configuration](#configuration)
- [Modes](#modes)
- [Rendering blocks and challenges](#rendering-blocks-and-challenges)
- [Events](#events)
- [Health checks](#health-checks)
- [Artisan commands](#artisan-commands)
- [Automating with Artisan](#on-a-schedule)
- [Octane](#octane)
- [Fail open or fail closed](#fail-open-or-fail-closed)
- [Known limitation: per-plugin challenge providers](#known-limitation-per-plugin-challenge-providers)
- [Supported versions](#supported-versions)
- [Development](#development)

## Why Laravel is nearly free

`Illuminate\Http\Request` extends `Symfony\Component\HttpFoundation\Request`, so
the request Laravel already built is handed to `evaluate()` unchanged. There is
no PSR-7 bridge and no request rebuilding, and that is worth more than the saved
allocation: Symfony holds trusted-proxy state *statically on the request class*,
so a converted request would silently lose it, and every IP-based rule reads a
client address through it.

What is left to do is not the request. It is the four ways this can be wired up
wrong without anything complaining.

## The four things that fail silently

Each of these produces a firewall that looks like it is working. Each is handled
deliberately, and each is checked by `php artisan firewall:doctor`.

### 1. `evaluate()` calls `exit()` unless the mode is `exception`

In its default `block` mode the library writes its own response and terminates
the process. Under Laravel that abandons the request mid-stack: nothing is
rendered, terminating middleware never runs, and the session, the queue and
anything else deferred to the end of the request are dropped. The symptom is a
truncated page, which reads as a crash rather than as a firewall block.

So `mode: block` in your config is delivered to the library as
`mode: exception`, and this package catches what it throws and renders it. The
status code and the message are the same; the difference is that Laravel
produces the response.

The translation is delivered as a PropertyAccess **override**, not as merged
config, because overrides are applied after every config input has been merged.
A preset — or a file written by `firewall-init`, which defaults to writing one —
can carry `global.mode: block`, and merged config would let it win.

And because `Config::load()` applies overrides inside a
`try { } catch (\Exception) { }`, a failed override is *silent*. So the outcome
is asserted rather than assumed: if the firewall comes back reporting `block`,
this package refuses to boot and says why. Two independent things can cause
that, and both are covered — an override that could not be written into a
non-array `global:`, and a panic file asking for `block`.

### 2. The CLI short-circuit

`evaluate()` returns `true` immediately when `PHP_SAPI === 'cli'`, for every
mode except `exception`. That is correct for Artisan and queue workers, which
have no visitor to protect — but **Octane on RoadRunner or Swoole also runs
under `cli` while serving real traffic**.

This is why `block` is translated to `exception` rather than left alone:
`exception` is the one mode that opts out of the short-circuit, so enforcement
works everywhere. `log` mode does not, and cannot be made to without
reimplementing the library's decision reporting. Under `cli`, `log` mode
observes nothing and says nothing, which is indistinguishable from a quiet week
— so `firewall:doctor` reports that combination as an **error**.

| SAPI | Where | `log` mode evaluates? |
|---|---|---|
| `cli` | Artisan, queue workers | No — correct, no visitor to protect |
| `cli` | **Octane on RoadRunner / Swoole** | **No — and it is serving real traffic** |
| `cli-server` | `artisan serve` | Yes |
| `fpm-fcgi`, `apache2handler`, `frankenphp` | Production | Yes |

`artisan serve` is in that table because the obvious guess about it is wrong,
and this package guessed wrong first. It runs under `cli-server`, not `cli`, so
nothing is short-circuited there. That is asserted rather than reasoned about:
`tests/Integration/install.sh` drives a real `artisan serve`, switches the
config to `log` mode, and checks the decision reaches the log — a status code
alone cannot tell a firewall that observed and allowed from one that never ran.

### 3. Middleware ordering against `TrustProxies`

Every rule reads `$request->getClientIp()`, which honours `X-Forwarded-For` only
after `Request::setTrustedProxies()` has run — `TrustProxies`' single job. Run
the firewall first and every rule sees the proxy's own address: an IP allowlist
matches nobody, a per-IP rate limit counts the whole internet as one client, and
a forged `X-Forwarded-For` bypasses both.

Three things make this hold:

- **The middleware is appended** to the global stack with `pushMiddleware()`.
  `TrustProxies` is at the front of Laravel's global stack, so anything appended
  runs after it. (Splicing in immediately after `TrustProxies` would be
  marginally earlier and therefore cheaper — the firewall would reject a request
  before `TrimStrings` walked the input. It lost because there is no public API
  for inserting at an index, and reflecting into `Kernel::$middleware` to rewrite
  it is a poor thing to do to a framework internal for a saving measured in
  microseconds. Appending is already before routing, before the session, before
  authentication and before any application code.)
- **The firewall is resolved inside `handle()`, not injected.** Constructor
  injection would build it when the middleware is resolved, which for global
  middleware is *before* `TrustProxies` runs — and the library performs its
  trusted-proxy posture check inside `create()`. It would be checking a state
  guaranteed to be empty, and warning on every request about a deployment that
  is configured correctly.
- **The ordering is verified, not trusted.** `TrustProxies::handle()` opens by
  resetting the trusted list to empty, so "no proxies in force" cannot be told
  apart from "TrustProxies has not run" by looking at the list. So what the
  application *declares* is compared against what is *in force*, and
  disagreement is the bug. It is checked per request, because middleware order
  is a property of the assembled stack that nothing announces at boot.

Laravel's own configuration is the source of truth for whether a proxy exists —
all three of the mechanisms Laravel has used for it: `TrustProxies::at()` (what
`$middleware->trustProxies()` calls), `config('trustedproxy.proxies')`, and the
`$proxies` property on an application's own `TrustProxies` subclass, which is
how Laravel 10 did it. You do not configure trusted proxies twice.

One deliberate asymmetry: the derived posture is only ever `true` or *unknown*,
never `false`. Asserting "there is no proxy" is the one answer that silences the
library's warning completely, and nothing observable from inside PHP justifies
it — a deployment with no trusted proxies configured is far more often one that
forgot than one that has no proxy. Say it yourself with
`global.behind_proxy => false` if you know, and nothing will override you.

### 4. The challenge submission path

A challenged visitor solves by POSTing to `challenge.path`
(`/_firewall/challenge` by default). If that POST does not reach `evaluate()`,
the visitor is locked out permanently — and nothing reports it, because from the
firewall's side they simply never come back with a valid token.

With global middleware this is automatic: global middleware runs before routing,
so the POST is intercepted before Laravel looks for a route, and before
`VerifyCsrfToken` could reject a form that cannot carry a Laravel CSRF token.

For per-route registration it is not automatic, so this package also registers a
bare `POST` route on `challenge.path`. Three details there are each
load-bearing: it carries **no route group**, so CSRF never runs; its action
**aborts with 404**, because it is only ever reached when the firewall did *not*
intercept, which means challenges are not configured and this path should look
like what it is; and it is registered **only when a path is configured**, so
clearing `challenge.path` removes the route rather than binding `POST /`.

## Configuration

`config/firewall.php` uses the library's own section names — `global`, `storage`,
`plugins`, `challenge`. That is deliberate. A flatter, more Laravel-shaped
vocabulary (`'mode' => 'block'` at the top level, `'block_ips' => [...]`) reads
better in isolation and lost anyway: it would create a second name for every
setting, so every example in [the library's
documentation](https://github.com/kanopi/firewall/tree/2.x/docs) — which is where
the rule syntax, the plugin list and the storage options are actually described —
would need translating in the reader's head before it could be used.

What this package adds is the part YAML cannot express:

```php
'plugins' => [
    [
        'plugin' => \Kanopi\Firewall\Plugins\IpAddress::class,
        'response' => 'allow',
        'weight' => -200,
        'config' => [env('OFFICE_CIDR', '203.0.113.0/24')],
    ],
],

'storage' => [
    'type' => \Kanopi\Firewall\Storage\DatabaseStorage::class,
    'config' => [
        'connection' => ['dsn' => env('DATABASE_URL')],
    ],
],
```

`presets` names the curated rule sets shipped inside the library, without the
directory or the `.yml`:

```php
'presets' => ['wordpress', 'malicious-urls', 'rate-limiting'],
```

A mistyped preset name is refused at boot, with the available list. Left to the
library it would fail silently — config loading is lenient, so
`presets: ['wordpess']` logs an error and starts with no WordPress rules, which
looks exactly like a firewall that is working.

`configs` takes absolute paths to additional YAML, for rule sets that are
genuinely easier to express that way — a long `configs:` include tree, or a file
written by `firewall:rule`.

### Logging

The library logs through Monolog and so does Laravel, so the default is to
borrow the handlers off one of your own channels rather than open a second log
file with its own rotation policy and its own place to forget to ship:

```php
'logger' => [
    'channel' => env('FIREWALL_LOG_CHANNEL', config('logging.default')),
],
```

Firewall records arrive on your existing channel under the Monolog channel name
`firewall`, so they stay filterable. `LoggingFactory::create()` accepts a
ready-made `HandlerInterface` alongside a class name, which is what makes this
possible with no change to the library.

The trade-off: records go through the *handlers*, not through Laravel's `Logger`
wrapper, so Laravel's context processors and `Log::withContext()` do not apply.
The alternative was a delegating handler that would pick those up — and lose the
level filtering and formatting configured on the channel, because a delegating
handler has to accept every record to pass it on. Filtering and formatting are
what a log channel is configured for; `withContext()` is set by application code
that is not running when the firewall evaluates.

## Modes

| Config | Delivered as | What happens |
|---|---|---|
| `block` (default) | `exception` | Blocked and challenged requests are rendered by Laravel with the rule's status code. |
| `log` | `log` | Nothing is enforced; decisions are logged at `warning`. **Does nothing under a CLI SAPI** — see trap 2. |
| `exception` | `exception` | Same as `block`. Use it if you prefer the config to say what the library is actually doing. |
| `disabled` | `disabled` | Rules are loaded and storage is opened, but nothing is evaluated. Useful for measuring the cost of the firewall itself. |

`firewall.enabled => false` is a different thing and usually the one you want
for "off": the middleware becomes a no-op and the firewall is never
constructed, so no storage connection is opened, no config is read and no
plugins are built.

Anything else — a typo like `lgo` — is refused at boot. The library defaults an
unknown mode to `block`, which is the right call for it (failing towards
enforcement), but here `block` is the one mode that cannot be delivered as
written, so defaulting would silently produce the exact behaviour this package
exists to translate away.

## Rendering blocks and challenges

Two Blade views, publishable and replaceable:

```bash
php artisan vendor:publish --tag=firewall-views
```

`firewall::block` receives `$message`, `$status` and `$request`. The message is
the library's interpolated banning message, which can contain the visitor's own
IP and the URL they asked for — attacker-influenced text, so keep it escaped.
The shipped view is self-contained with no layout and no asset references: a
blocked request should not be executing application code or fetching from the
application it was just refused access to.

`firewall::challenge` is a wrapper, and almost nothing about it is yours to
change. `$body` is a complete HTML document from the challenge provider, and it
carries the parts that make the challenge solvable — the form, the signed
per-challenge state, the redirect target, the TTL, the JavaScript that stashes
the token. The default view emits it and nothing else. To brand an interstitial,
replace the *provider* instead: implement `ChallengeProviderInterface` and name
your class in `firewall.challenge.provider`. That is the supported extension
point, and it keeps the form fields and the verification in one place where they
cannot drift apart.

API clients are content-negotiated. A blocked JSON request gets the status and
the message; a challenged one gets `403` with the submission path and header
name, because there is no browser to solve an interstitial in and rendering HTML
into a JSON client's body would just be an unreadable 200.

Exceptions raised **outside** the middleware are covered too. If you call
`evaluate()` from your own code — a controller protecting one action, a job
checking an inbound webhook — the provider registers `renderable()` handlers so a
block still renders as a block. Without that it would reach Laravel's handler as
a plain `RuntimeException` and render as a 500: the wrong status, a stack trace
while `APP_DEBUG` is on, and an error-tracker alert for the firewall doing its
job.

## Events

Laravel's dispatcher is wired into `Firewall::create()`'s third argument, so
listeners register against the library's event classes with no ceremony:

```php
Event::listen(RequestBlocked::class, function (RequestBlocked $event) {
    // …
});
```

All five events — `RequestAllowed`, `RequestBlocked`, `RequestChallenged`,
`ChallengeSolved`, `ChallengeFailed` — are read-only by design. Two consequences
are easy to build against by accident:

- **Returning `false` from a listener does not halt anything.** Laravel treats a
  `false` return as "stop propagating to later listeners", and that much still
  works, but it has no effect on the firewall's decision. The verdict is already
  made when the event is announced.
- **Do not put anything load-bearing in a listener.** A listener that throws is
  caught by the library and logged at `error`, never propagated — deliberately,
  because a StatsD socket or an HTTP notifier failing is not a reason to stop
  blocking an attacker. An audit trail that must exist needs to be written
  somewhere that fails loudly.

Events are the right place for what is genuinely advisory: a counter, a Slack
notification, a queued job for enrichment.

## Health checks

`HealthReport` answers the questions a firewall is worst at announcing:

```php
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Laravel\Support\HealthReport;

Route::get('/internal/firewall', function (Firewall $firewall) {
    $report = (new HealthReport($firewall))->toArray();

    return response()->json($report, $report['healthy'] ? 200 : 503);
})->middleware('auth.internal');
```

It reports four conditions that each look identical to a working firewall:

- **A rule that is not running.** A plugin whose constructor throws — a Redis
  host not answering, a storage path that lost its permissions — is logged and
  skipped, and the request is evaluated by the rules that *did* build. For an
  `allow` rule that is merely annoying; for a `block` rule it is a fail-open,
  and a firewall running three rules short looks exactly like a firewall running
  correctly. This is the only condition reported as **unhealthy**.
- **A rule that is running blind.** The Redis backends catch a connection
  failure, log it, and answer every read as though nothing were stored — so the
  plugin constructs, the rule reports healthy, and a rate limit counts nothing.
  Reported as a warning, because the firewall is still enforcing everything that
  does not depend on that store.
- **A panic file holding the switch down.** The realistic failure is not
  somebody flipping it during an incident; it is nobody noticing three weeks
  later that it is still on.
- **A panic file that did nothing** — empty, unreadable, or naming something
  that is not a mode. Somebody reached for the switch and it did not take, and
  they are watching the site rather than the logs to find that out. Reported as
  an error.

No route is shipped for this. A health endpoint's path and authentication are
application decisions, and a package that guessed at both would be guessed
wrong.

**Do not call it from a request path.** `getFailedRules()` and
`getDegradedBackends()` build every rule to answer, because rules are
constructed lazily and a firewall that has evaluated nothing has nothing that
could have failed yet. Building a rule is what opens its storage connection,
which is what makes the answer worth having.

## Artisan commands

The library ships eight scripts in `bin/`, and they are its operational surface.
Each is wrapped:

| Command | What it does | Exits non-zero when |
|---|---|---|
| `firewall:doctor` | Diagnoses the Laravel wiring **and** runs the library's own checks | Something configured is not happening |
| `firewall:health` | Reports whether the running firewall is working | A rule is not running, or a panic file did not take |
| `firewall:check` | Would this request be blocked, and by what | The request would be blocked |
| `firewall:blocks` | See who is blocked | Storage cannot answer |
| `firewall:block` | Block a client **now**, without writing a rule | The address is invalid, or already blocked |
| `firewall:unblock` | Lift a block, by address or CIDR range, or `--all` | Storage cannot answer |
| `firewall:find-reference` | Turn a reference from a block page back into a client | No block in force carries it |
| `firewall:rule` | Add, remove, enable and disable rules | The change was refused |
| `firewall:sources` | Refresh rule sources out of band | A source failed to load |
| `firewall:migrate` | Bring the firewall's own tables up to the current schema | A change could not be applied |
| `firewall:log-prune` | Delete log rows past their retention window | A handler failed to prune |
| `firewall:init` | Generate a starter YAML from the shipped presets | It refused to overwrite a file |

Most of these forward to the library's own `bin/` scripts. Three do not —
`firewall:block`, `firewall:unblock` and `firewall:find-reference` are real code
here, because `bin/firewall-block` can list, find, show and lift but cannot
*add*, and nothing upstream can look up a reference at all. They are built on
the library's public API (`BlockList`, `StorageInterface`) rather than on its
internals, which is why they can live in this package.

### Singular blocks, plural lists

`firewall:block` adds; `firewall:blocks` reads. Overloading one command with
both — an argument to add, a flag to list — would put the destructive reading
one typo away from the harmless one.

```bash
php artisan firewall:block 203.0.113.9                        # an hour
php artisan firewall:block 203.0.113.9 --duration=0 --reason="Scraping /api"
php artisan firewall:block 203.0.113.9 --duration=86400 --force   # replace an existing block
```

Three behaviours worth knowing, each of which is what the storage layer
actually does rather than what it looks like it should:

- **`--duration` is seconds, and `0` means until somebody lifts it.** A
  non-numeric value falls back to an hour rather than to `0`, so a typo cannot
  silently create a permanent block.
- **Re-blocking is refused without `--force`.** `set()` on an existing key
  replaces the payload and *keeps the original expiry*, so a longer
  `--duration` would appear to apply and would not. `--force` lifts first.
- **Ranges are refused.** Storage keys are the client IP verbatim and lookups
  are exact, so `203.0.113.0/24` stored as a block would sit in the list
  looking authoritative and match no visitor ever. The command says so and
  points at `firewall:rule add --plugin=ip`, which is evaluated rather than
  looked up.

`firewall:unblock` does accept ranges, which is not an inconsistency: lifting
matches against what is already stored.

```bash
php artisan firewall:unblock 203.0.113.9
php artisan firewall:unblock 203.0.113.0/24 --dry-run
php artisan firewall:unblock --all
```

`--all` lifts every address rather than resetting the backend, because a reset
would also discard offense history — and that history drives escalating bans,
so clearing it would quietly reward every address that has ever misbehaved.

Lifting something that is not blocked exits **0**, not 1: "nothing matched" is a
complete answer, and a deploy step that defensively lifts an address should not
start failing once the address is gone.

### From a reference number back to a client

The firewall shows a blocked visitor a hex reference and nothing else
identifying — deliberately, since telling them which rule matched is free
information. That leaves support holding a string they could not use:

```bash
php artisan firewall:find-reference 2CB3B1780E3653DE9C7AFA913F3C1A33
```

```
  INFO  Reference 2CB3B1780E3653DE9C7AFA913F3C1A33 belongs to 203.0.113.9.

  Address ............................................... 203.0.113.9
  Blocked by rule ................................... block-wp-probes
  Blocked at ............................... 2026-09-11T05:40:05+00:00
  Expires .................................. 2026-09-11T06:40:05+00:00
  Offenses ......................................................... 2

  Lift it with: php artisan firewall:unblock 203.0.113.9
```

Matched case-insensitively, and `--json` for a support tool rather than a
person. A reference that finds nothing exits 1 and says why it is usually
innocent: the list holds only what is *currently in force*, so a lapsed block
is gone from it while the log still remembers the decision.

Every one of them is scriptable, and the exit code is the interface. Details
worth knowing before you wire them into anything:

- **Nothing prompts without a TTY.** `firewall:init` is the only command that
  asks questions, and with no terminal attached it takes its defaults and exits
  0 rather than hanging — verified, because a prompt that blocks a container
  build is worse than no generator. Pass `--no-interaction` anyway if you like
  belts as well as braces.
- **`--json` on `firewall:health`, `firewall:doctor`, `firewall:check`,
  `firewall:block` and `firewall:rule`**, for the steps where something other
  than a person is reading.
- **`--dry-run` on `firewall:block --lift`, `firewall:rule`,
  `firewall:sources`, `firewall:migrate` and `firewall:log-prune`**, so a
  deploy step can report what it would change before it is allowed to.
- **`--quiet` is `--quiet-output`.** Symfony Console reserves `--quiet` for its
  own verbosity, so an Artisan command cannot declare it. The underlying script
  still receives `--quiet`.

### On a schedule

```php
// routes/console.php
use Illuminate\Support\Facades\Schedule;

// Move source fetching off the request path. Pair it with `sources.offline: true`
// in global config and the runtime reads cached results and never opens a socket
// — otherwise a cold cache makes a visitor wait on somebody else's HTTP server,
// and an expiry under load sends every concurrent request after the same URL.
Schedule::command('firewall:sources')->hourly()->withoutOverlapping();

// Only needed for the library's own DatabaseHandler. Set `prune_probability: 0`
// on the handler so pruning happens here and nowhere else.
Schedule::command('firewall:log-prune')->dailyAt('03:15');

// Health on a schedule is for the deployments with nowhere to hang a monitor.
// If you have one, prefer the exit code (below) over a log line.
Schedule::command('firewall:health')->everyThirtyMinutes()->onFailure(function () {
    // page somebody
});
```

### As a deploy gate

```bash
php artisan firewall:migrate                 # additive only; never drops or renames
php artisan firewall:sources                 # warm the caches before traffic arrives
php artisan firewall:doctor                  # fails the deploy if a rule cannot run
```

`firewall:doctor` is the one to gate on, and it is built for it: a **warning
does not fail the command**, so a stale GeoIP database will not block a release,
while a rule that cannot be constructed will. It reads the live environment
rather than the config in the abstract — opening the storage file, reaching the
database, building every rule.

`firewall:migrate --dry-run` exits **3** when changes are pending, which lets a
pipeline detect a schema change without applying one. Note that a *fresh*
database exits 0: constructing the storage creates its tables, so 3 means an
existing table is missing something a newer release added.

### As a monitoring probe

```bash
php artisan firewall:health --json
```

```json
{
    "healthy": true,
    "mode": "exception",
    "configured_mode": "exception",
    "mode_overridden": false,
    "panic_switch": { "active": false, "mode": null, "path": null, "problem": null },
    "failed_rules": [],
    "degraded_backends": [],
    "errors": [],
    "warnings": []
}
```

Exit 0 when healthy, 1 when not. The shape is fixed and the field names are the
contract — there is a test asserting each one, because a check keyed off a
renamed field does not fail, it reports "healthy" forever.

`firewall:health` and `firewall:doctor` overlap and answer different questions,
which is why both exist. The doctor asks *is this configured correctly* and
answers in prose for a person, once, at deploy. Health asks *is it working right
now* and answers in a flat shape for a script, repeatedly. Health also reports
the one condition no static check can see: `degraded_backends`, a store that a
successfully-constructed rule cannot reach — a rate limit counting nothing while
everything looks fine.

By default a degraded backend is a **warning** and exits 0, because the firewall
is still enforcing every rule that does not depend on that store. `--strict`
turns warnings into failures if you would rather hear about it.

### During an incident

```bash
php artisan firewall:blocks                            # who is blocked
php artisan firewall:blocks --show=203.0.113.9         # and when they offended
php artisan firewall:find-reference ABC123…            # who a reference belongs to

php artisan firewall:block 203.0.113.9 --reason="Scraping /api"   # stop them now
php artisan firewall:unblock 203.0.113.9               # let them back in
php artisan firewall:unblock 203.0.113.0/24 --dry-run  # rehearse a wider lift

php artisan firewall:check --ip=203.0.113.9 --url=/checkout --explain
```

`firewall:check` is safe to point at a production config: it swaps storage for a
throwaway store, so asking about an address cannot ban it. `--live-storage`
consults the real block list, and says so before it does.

For "stop enforcing, right now, without a deploy", use the panic switch rather
than a command — `echo log > /var/run/firewall/panic` takes effect on the next
request. `firewall:health` then reports `mode_overridden` so the change is
visible to whatever is watching.

They run the real scripts as subprocesses rather than reimplementing them. Every
one of those scripts is built on classes this package could call directly, and
calling them would give native Artisan output and no process overhead — but it
would mean maintaining a parallel copy of roughly 2,500 lines of argument
handling, exit-code policy and output formatting, which would drift from the
originals on every release, silently, in the direction of being wrong.
`firewall-check` exists precisely because assembling the same call by hand has
three edges that fail quietly, and it handles all three. Running the real script
means `php artisan firewall:check` and `bin/firewall-check` cannot disagree, and
an upstream fix arrives with the upstream release. The cost is one PHP process
per invocation, on commands run from a terminal or a deploy step.

Each subclass declares the options its script actually takes, rather than
forwarding a free-form argument list. That is more code for the same behaviour
and it buys `--help` that describes the command, rejection of a mistyped option
before it reaches the script and gets ignored, and shell completion. Exit codes
are the scripts' own, forwarded unchanged, so a deploy step can gate on
`php artisan firewall:doctor` exactly as it would on `bin/firewall-doctor`.

Two names differ from the scripts: `--quiet` becomes `--quiet-output` (Symfony
Console reserves `--quiet` for verbosity), and `firewall:doctor` takes
`--quiet-checks`. The scripts still receive `--quiet`.

Those scripts read YAML and this config is PHP, so each command translates the
config exactly as the middleware does and writes the result to a temporary file.
`--keep-config` leaves it behind, which is the most direct answer to "what did my
PHP config actually become". The challenge secret is deliberately **not** written
into that file — it travels in the subprocess environment and the YAML carries
only an `%env(...)%` reference, because a temp file is removed in a `finally`
and that does not survive a `kill -9`.

`firewall:rule` writes to a file it owns exclusively and refuses to change a
rule it did not write. Rules declared in `config/firewall.php` can be listed but
not edited, which is the right way round: a command that rewrote a PHP config
file would have to preserve comments, `env()` calls and formatting, and would
eventually fail to. That managed file is added to the firewall's config inputs
as soon as it exists, so a rule added there is live on the next request. The
command creates the file on demand, because the script refuses to add a rule to
a file nothing includes — correctly — and the include can only be written once
the file exists.

`firewall:migrate` is deliberately *not* wired into Laravel's migrations. The
firewall's tables are created on first write by the storage backend that owns
them, and their schema is declared on those classes — so a Laravel migration
would be a second description of the same schema, and the two would disagree
the first time the library added a column.

## Octane

**The answer, stated plainly: the firewall is bound with `scoped()`, so under
Octane it is rebuilt for every request. Under PHP-FPM and mod_php that is
identical to a singleton, because there is one request per process.**

The reason it has to be rebuilt is the panic switch. `global.panic_file` names a
file that, when it exists and names a mode, overrides the mode from the next
request onward — no deploy, no cache clear. It works because
`PanicSwitch::read()` runs in the `Firewall` **constructor**: one `stat()` per
instance, which the library documents as one per request.

An instance that outlived the request would keep reporting the mode it read when
the worker booted. Writing `log` to the panic file during an incident would
change nothing until every worker had been restarted — which is the one moment
that is least acceptable, and it would fail silently, because a panic file that
does nothing looks exactly like a panic file nobody has reached for yet.

Two other pieces of per-instance state make the same argument:

- **Failed rules are never retried.** A plugin whose constructor threw is
  recorded as failed and skipped for the life of the instance. Under a
  persistent singleton, a Redis blip during worker boot would disable a rate
  limit rule until the worker was recycled.
- **Degraded backends are recorded at construction.** A backend that reconnects
  is not re-checked, so a health endpoint would go on reporting a store as
  unreachable long after it came back.

What `scoped()` costs is real: the config is re-merged and the plugin registry
rebuilt each request, which is work Octane exists to avoid. The library
mitigates most of it — `Config::load()` caches the merged result per file set,
and plugins are constructed lazily, so a rule is only built on a request that
evaluates it. If you have measured that you still need more:

```php
'octane' => ['persist_instance' => true],
```

That binds a true singleton: config parsed and plugins built once per worker.
Take it only with `panic_file` unset, and `firewall:doctor` reports the
combination of the two as an **error** rather than leaving you to find out
during an incident.

Two more things about Octane specifically:

- **`PHP_SAPI` is `cli`** on RoadRunner and Swoole, so those workers are on the
  wrong side of the library's short-circuit. Enforcement is unaffected —
  `exception` mode opts out of it, which is why this package forces it — but
  `log` mode observes nothing there. See trap 2. (FrankenPHP reports
  `frankenphp` and is unaffected either way.)
- **Trusted proxies are per-request state** on the Symfony request class, set by
  `TrustProxies` each pass. That is why the trusted-proxy posture is re-derived
  on every `translator()` call rather than memoised on the factory, which *is* a
  singleton: a memoised posture would be whatever the first request a worker
  served happened to see.

## Fail open or fail closed

A firewall can fail in a way that has nothing to do with the request in front of
it: a database it cannot reach, a config file that will not parse, a challenge
provider that does not resolve. The library propagates those and deliberately
leaves the policy to the host, so state it:

```php
'on_boot_failure' => env('FIREWALL_ON_BOOT_FAILURE', 'throw'),
```

- **`throw`** (default) — fail closed. The request gets a 500 and the deploy
  that caused it is obvious. Right wherever serving unfiltered traffic is worse
  than serving an error: authenticated apps, checkout, admin surfaces.
- **`allow`** — fail open. Logged at `critical`, and the request proceeds
  unfiltered. Only for public, low-risk content where availability wins, and
  only if that `critical` actually pages somebody — the site will look perfectly
  healthy while nothing at all is being filtered.

This covers the firewall *breaking*, not the firewall *deciding*. A blocked
request is a decision and is always delivered as a block.

There is a separate case worth knowing about, because an exception handler will
not catch it: config loading is lenient by default. A missing, unreadable or
malformed YAML file is logged at `error` and produces a partial — possibly
empty — ruleset, and `create()` succeeds. Turn it into a startup failure in
production:

```php
'global' => ['require_config' => true],
```

`firewall:doctor` reports any configured-but-unreadable path in `configs`, and
says whether `require_config` already makes it fatal.

## Known limitation: per-plugin challenge providers

A challenge rule can name its own provider with
`metadata.challenge_provider`, so a broad heuristic can serve a cheap math
question while a login brute-force rule serves reCAPTCHA. **That does not work
under this integration**, and `firewall:doctor` reports it as an error rather
than leaving a visitor to discover it.

The reason is upstream. In `exception` mode the library throws
`ChallengeRequiredException` *before* it renders the interstitial, and that
exception carries only a message — not the plugin that matched, nor the provider
serving it. So this package rebuilds the provider itself from
`challenge.provider`, and a rule asking for a different one is rendered with the
default.

Everything needed to rebuild the provider is public API (`TokenManager`,
`ChallengeProviderRegistry`, including the registry's own resolution of flat
versus per-provider `provider_options`), with one exception: the library's own
render passes a signed `provider_token` so a submission can say which provider
it answers, and signing it needs a private domain-separation prefix. Reaching
into that would couple this package to the library's internals for a value the
library is willing to do without — a submission carrying no such field is
verified by `challenge.provider`, which is the documented fallback.

Fixing it properly means `ChallengeRequiredException` carrying the matched
plugin's provider name, which is a change in `kanopi/firewall`. Nothing
framework-specific belongs in that package, so it is [an issue to open
there](https://github.com/kanopi/firewall/issues), not something to work around
here.

Until then: use a single `challenge.provider`. Everything else about the
challenge flow — the round-trip, the pass token, the cookie attributes, the
single-use solution consumption, the "wrong answer looks identical to a first
visit" property — works and is tested end to end.

## Supported versions

| PHP | Laravel 12 | Laravel 13 |
|---|---|---|
| 8.1 | not installable | not installable |
| 8.2 | ✅ 316 tests | not installable (needs 8.3) |
| 8.3 | ✅ 316 tests | ✅ 316 tests |
| 8.4 | ✅ 316 tests | ✅ 316 tests |
| 8.5 | ✅ 316 tests | ✅ 316 tests |

Measured, not asserted: every ✅ above is a run of the full suite in a container
for that PHP version, against `laravel/framework` pinned to that major. Reproduce
it with `composer test:matrix`, which is what produced the table.

Exact versions at the time of writing: `laravel/framework` v12.69.2 and
v13.31.0, `kanopi/firewall` 2.24.0, PHP 8.2.32 / 8.3.32 / 8.4.23 / 8.5.8 (the
official `php:<version>-cli` images).

The published constraint is wider than that table — `^10.0 || ^11.0 || ^12.0 ||
^13.0` — and the honest reason is worth stating rather than leaving as a
mismatch somebody discovers.

The code genuinely supports Laravel 10 and 11: everything it touches
(`pushMiddleware()`, scoped container bindings, `renderable()`, and all three of
Laravel's trusted-proxy mechanisms including the Laravel 10 middleware property)
exists in both, and the Laravel 10 path has its own tests. But **every 10.x and
11.x release currently carries unresolved security advisories**, so Composer's
default `audit.block-insecure` refuses to install them. A project with a
pre-existing lock file, or one that has deliberately relaxed that setting, can
use this package on those versions; neither CI nor the local matrix can install
them, so neither claims to test them.

`php: >=8.1` is published because that is what the library requires and the code
is 8.1-compatible (PHPCS checks it against 8.1). In practice PHP 8.1 has no
installable Laravel at all, which is why it appears in the matrix and skips: 12
needs 8.2, 13 needs 8.3, and 10 and 11 are blocked as above.

## Development

```bash
composer install
composer test           # both suites, no coverage — the fast loop
composer test:gate      # both suites with coverage, the figure CI reads
composer check          # PHPCS + PHPStan at max
composer test:install    # install into a real Laravel app and drive it over HTTP
composer test:matrix     # the suite on every supported PHP and Laravel, in Docker
```

### Running a CI job before pushing

```bash
composer test:ci                                  # the phpunit job, PHP 8.3, Laravel 13
tests/Integration/ci-job.sh phpunit 8.5 '^12.0'   # a specific cell
tests/Integration/ci-job.sh static-analysis
```

Runs a job's own commands inside `cimg/php`, the image CI uses. It exists
because the first two pipelines on this repository each failed on a different
fault in the CI configuration, one per push — and a pipeline only ever reports
the *first* command that exited non-zero, so a job with two faults hides the
second until the first is fixed. Both were reproducible locally in seconds.

It is slow on Apple silicon: `cimg/php` publishes amd64 only, so it runs under
emulation. That is the cost of testing the actual CI image rather than
something like it, and worth paying before a push. The version matrix below is
the fast native counterpart — it runs the *suite*, not the *job*, so it cannot
catch a fault in the CI config.

The job's steps are written out in both the script and `.circleci/config.yml`,
which can drift. They are short, they sit next to each other in review, and the
alternative — parsing the YAML and re-implementing CircleCI's interpolation —
would be a different approximation with more moving parts.

### The version matrix

`tests/Integration/matrix.sh` runs the suite in a container per PHP version, on
the official multi-arch `php:<version>-cli` images. It exists because "it passes
here" is a claim about one PHP build, and the support table above is a claim
about five.

```bash
composer test:matrix                      # the whole grid
tests/Integration/matrix.sh 8.3           # one PHP version, both Laravels
tests/Integration/matrix.sh 8.5 '^13.0'   # one cell
FIREWALL_MATRIX_LOWEST=1 composer test:matrix   # oldest allowed dependencies
```

Each cell gets its own container and its own `composer update`, deliberately: a
shared `vendor/` would let one cell's resolution mask another's conflict, which
is the failure a matrix exists to catch. The PHP floor for each Laravel major is
declared in the script as data rather than sniffed from Composer's error text —
on PHP 8.1 the real cause is that no compatible `orchestra/testbench` exists and
Composer reports it as a Laravel conflict, so classifying on the message would
be reading tea leaves. A cell below its floor skips; anything else that fails to
install fails the run.

It earns its keep. It immediately caught a test that passed on macOS and failed
in a container: the assertion used `/no/such/directory` as an unwritable path,
which **root can create**, so it had been testing the developer's permissions
rather than the command.

### The install test

`tests/Integration/install.sh` creates a Laravel application, installs this
package from the working tree, publishes the config, adds a rule and drives the
result over HTTP through `artisan serve`. It takes a couple of minutes and it
earns them: it is the only test that exercises the four things Testbench
structurally cannot.

| | PHPUnit (Testbench) | Install test |
|---|---|---|
| Composer runs | No — the provider is loaded by class name | Yes — auto-discovery, the `laravel.providers` extra |
| `vendor:publish` | Not exercised | Yes |
| Storage | `InMemoryStorage` | Real `FileStorage` under `storage/` |
| SAPI | `cli` | `cli-server` |

Both defects found in this package so far were invisible to a green suite and
obvious within a minute here: a missing storage directory that 500'd every
request of a clean install, and a default log channel that resolved to NULL so
the firewall reported nothing. It also settles the `artisan serve` SAPI question
that the table in trap 2 depends on.

It asserts the application is healthy *before* installing the package, so a
broken skeleton can never be mistaken for a broken firewall — a distinction that
cost real time before the assertion existed. Pass a constraint to pin the
framework, and `FIREWALL_INSTALL_KEEP=1` to walk into a failure:

```bash
tests/Integration/install.sh '^12.0'
FIREWALL_INSTALL_KEEP=1 tests/Integration/install.sh
```

The quality bar matches the parent project: **100% line and method coverage**,
PHPStan at `max` with no baseline and no `ignoreErrors`, and PHPCS on
PSR-1/2/12 plus PHPCompatibility.

`composer test:gate` needs a coverage driver — Xdebug or PCOV — and refuses to
run without one rather than letting PHPUnit report "No tests executed!". That
message names the symptom and not the cause: `phpunit.xml` declares `<coverage>`
and `failOnWarning`, so a missing driver makes PHPUnit run **zero tests** and
fail. CI installs Xdebug for exactly this reason; `composer test` is the
no-coverage loop and needs nothing.

Coverage is measured across both suites in a single pass, and it has to be: the
middleware, the service provider and the responder are only exercised end to
end by the feature suite, and the unit suite alone understates them badly.

The 100% floor is a constraint rather than a vanity number, and it is enforced
in a specific way: where a defensive branch turned out to be genuinely
unreachable, the code was **restructured so there is no unreachable branch**
rather than annotated to be skipped. That is why `glob(...) ?: []` replaced a
`=== false` arm, why one `property_exists()` replaced a `class_exists()` plus a
`try`/`catch` that static analysis could prove dead, and why `PHP_SAPI` and
`runningInConsole()` are constructor arguments on `IntegrationDoctor` — both
decide a finding, and a test suite can vary neither.

The console tests genuinely fork PHP and run the library's own scripts. They are
the slowest tests here and the only ones that can catch what matters most about
that layer: that the YAML written out of a PHP config array is something the
scripts can actually consume.

## License

MIT. See [LICENSE](LICENSE).
