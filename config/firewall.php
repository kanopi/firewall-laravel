<?php

declare(strict_types=1);

/*
 * This file is part of the kanopi/firewall-laravel package.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*
 * Firewall configuration.
 *
 * The section names below — `global`, `storage`, `plugins`, `challenge` — are
 * the ones `kanopi/firewall` itself uses, deliberately. The alternative was a
 * flatter, more Laravel-shaped vocabulary (`'mode' => 'block'` at the top
 * level, `'block_ips' => [...]`, and so on), which reads better in isolation
 * and lost anyway: it would have created a second name for every setting, so
 * every example in the library's own documentation — which is where the rule
 * syntax, the plugin list and the storage options are actually described —
 * would need translating in the reader's head before it could be used. Keeping
 * the section names means the library docs are this file's reference manual.
 *
 * What this integration adds on top is the parts YAML cannot express: Laravel's
 * `env()` and `storage_path()`, the trusted-proxy posture read from Laravel's
 * own `TrustProxies`, log handlers borrowed from a Laravel channel, and the
 * `middleware` / `octane` / `views` sections at the bottom, which have no
 * library equivalent because they describe the framework, not the firewall.
 *
 * @see https://github.com/kanopi/firewall/blob/2.x/docs/configuration/index.md
 */

return [

    /*
    |--------------------------------------------------------------------------
    | Enabled
    |--------------------------------------------------------------------------
    |
    | The master switch. FALSE makes the middleware a no-op and — more to the
    | point — never constructs the firewall at all, so no storage connection is
    | opened and no config is read. Distinct from `global.mode = disabled`,
    | which still builds everything and then declines to evaluate; that one is
    | what you want when you are measuring the cost of the firewall itself.
    |
    */

    'enabled' => env('FIREWALL_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | When the firewall itself is broken
    |--------------------------------------------------------------------------
    |
    | A firewall can fail in a way that is nothing to do with the request in
    | front of it: a database it cannot reach, a config file that will not
    | parse, a challenge provider that does not resolve. The library propagates
    | those and deliberately leaves the policy to the host, so state it here.
    |
    |   'throw'  Fail closed. The request gets a 500 and the deploy that caused
    |            it is obvious. Right wherever serving unfiltered traffic is
    |            worse than serving an error: authenticated apps, checkout,
    |            admin surfaces.
    |
    |   'allow'  Fail open. Logged at critical, and the request proceeds
    |            unfiltered. Only for public, low-risk content where
    |            availability wins — and only if that critical actually pages
    |            somebody, because the site will look perfectly healthy while
    |            nothing at all is being filtered.
    |
    | Note that this covers the firewall breaking, not the firewall deciding. A
    | blocked request is a decision and is always delivered as a block.
    |
    */

    'on_boot_failure' => env('FIREWALL_ON_BOOT_FAILURE', 'throw'),

    /*
    |--------------------------------------------------------------------------
    | Global
    |--------------------------------------------------------------------------
    |
    | Passed to the library as its `global:` block.
    |
    | `mode` takes the four values the library documents — block, log,
    | exception, disabled — and means the same thing here, with one difference
    | in how it is delivered. `block` makes the library write its own response
    | and call exit(), which under Laravel would terminate the process with a
    | half-built response and no rendered view. So this integration runs the
    | library in `exception` mode whenever you ask for `block`, catches what it
    | throws, and renders the response through Laravel instead. The visible
    | behaviour is the same status code and the same message; the difference is
    | that middleware after this one still runs its terminating half, and the
    | body comes from a Blade view you can publish and override.
    |
    | `log` and `disabled` are passed through untouched, because neither of
    | them writes a response. One caveat on `log`, covered in the README: the
    | library evaluates nothing when PHP_SAPI is exactly "cli", which is right
    | for Artisan and queue workers and wrong for Octane on RoadRunner or
    | Swoole, whose workers serve real traffic under that SAPI. `artisan serve`
    | is not affected — it runs as "cli-server".
    |
    */

    'global' => [
        'mode' => env('FIREWALL_MODE', 'block'),

        /*
         * Whether a proxy sits in front of this application.
         *
         * NULL — the default — means "work it out from Laravel". The
         * integration reads Laravel's own trusted-proxy configuration and
         * tells the library what it found, so a deployment that has already
         * configured `TrustProxies` does not have to say so twice. Set TRUE or
         * FALSE only to assert something Laravel's config does not show.
         *
         * This matters more than it looks: every firewall rule reads
         * `$request->getClientIp()`, which honours X-Forwarded-For only after
         * `Request::setTrustedProxies()` has run. Get it wrong and an IP
         * allowlist is bypassable with a forged header.
         */
        'behind_proxy' => env('FIREWALL_BEHIND_PROXY'),

        /*
         * Refuse to boot when the trusted-proxy posture is unresolved.
         * Recommended in production behind a load balancer or CDN.
         */
        'require_trusted_proxies' => env('FIREWALL_REQUIRE_TRUSTED_PROXIES', false),

        /*
         * Refuse to boot when any config input failed to load, instead of
         * starting with a partial — possibly empty — ruleset that allows
         * everything. Only relevant when you add YAML through `configs` or
         * `presets` below; a PHP array cannot fail to load.
         */
        'require_config' => env('FIREWALL_REQUIRE_CONFIG', false),

        /*
         * A file that, when it exists and names a mode, overrides `mode` from
         * the next request onward — no deploy, no cache clear. Keep it outside
         * the document root and outside the deployed tree.
         *
         * Under Octane this needs `octane.persist_instance = false` (the
         * default) to work at all. See the Octane section of the README.
         */
        'panic_file' => env('FIREWALL_PANIC_FILE'),

        /*
         * Everything else the library's `global:` block accepts —
         * `status_code`, `banning_message`, `multiple_offenses`, `sources`,
         * `stale_source_error_after` — can be added here verbatim.
         */
    ],

    /*
    |--------------------------------------------------------------------------
    | Presets
    |--------------------------------------------------------------------------
    |
    | Curated rule sets shipped inside kanopi/firewall, named without the
    | directory or the .yml. Resolved to absolute paths and merged before
    | `configs` and before the `plugins` below, so a preset is a starting
    | point you then override rather than a thing you have to fork.
    |
    | Available: wordpress, drupal, drupal-admin, malicious-requests,
    | malicious-urls, rate-limiting, search-bots, ai-crawlers,
    | ai-crawlers-challenge, ai-answer-engines, logging-pantheon,
    | storage-pantheon.
    |
    */

    'presets' => [],

    /*
    |--------------------------------------------------------------------------
    | Extra config files
    |--------------------------------------------------------------------------
    |
    | Absolute paths to additional YAML, merged after `presets` and before
    | `plugins`. Use this for rule sets that are genuinely easier to express in
    | the library's YAML — a long `configs:` include tree, or a file written by
    | `php artisan firewall:rule add`, which owns its own file.
    |
    */

    'configs' => [],

    /*
    |--------------------------------------------------------------------------
    | Storage
    |--------------------------------------------------------------------------
    |
    | Where blocks and offense counts persist between requests. FileStorage is
    | the default because it needs nothing else to exist; it is also per-server,
    | so anything running on more than one web node wants DatabaseStorage or
    | RedisStorage instead, or a block earned on one node will not be known to
    | the others.
    |
    | A database that cannot be reached is a startup failure, not a silent one:
    | construction throws StorageConnectionException.
    |
    */

    'storage' => [
        'type' => env('FIREWALL_STORAGE', \Kanopi\Firewall\Storage\FileStorage::class),
        'config' => [
            'storage_file' => storage_path('firewall/blocked.data'),
            'offense_file' => storage_path('firewall/offenses.data'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Plugins
    |--------------------------------------------------------------------------
    |
    | The rules. Each entry names a plugin class, a response (allow, block or
    | challenge), a weight (lower runs first) and its own `config` list. Allow
    | rules are consulted first, then challenge, then block.
    |
    | Empty by default, and that is the safe default rather than a lazy one: a
    | shipped rule set that blocks something a host application depends on is
    | worse than no rules, because it looks like the application is broken.
    | Start with a preset above, or with `php artisan firewall:rule add`.
    |
    | The syntax for the `config` entries — `path:`, `path@starts_with:`,
    | `type: AND`, and the rest — is the library's, and is documented per
    | plugin at https://github.com/kanopi/firewall/blob/2.x/docs/plugins/.
    |
    */

    'plugins' => [
        // [
        //     'plugin' => \Kanopi\Firewall\Plugins\IpAddress::class,
        //     'response' => 'allow',
        //     'weight' => -200,
        //     'enable' => true,
        //     'config' => ['203.0.113.100/32'],
        // ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Challenge
    |--------------------------------------------------------------------------
    |
    | Settings for rules with `response => challenge`. Ignored entirely when no
    | rule uses it.
    |
    | `secret` is REQUIRED as soon as one does — it signs the pass token, and an
    | empty value is a startup failure rather than a silently unsigned token.
    | It is unrelated to any third-party challenge service's secret key.
    |
    | `path` must reach the firewall and must not be routed by your
    | application. With `middleware.global = true` that is automatic: global
    | middleware runs before routing, so the POST is intercepted before Laravel
    | looks for a route and before VerifyCsrfToken would reject a form that
    | cannot carry a token. With per-route registration it is not automatic,
    | which is what `middleware.register_challenge_route` below is for.
    |
    */

    'challenge' => [
        'provider' => env('FIREWALL_CHALLENGE_PROVIDER', 'math'),
        'secret' => env('FIREWALL_CHALLENGE_SECRET', ''),
        'path' => env('FIREWALL_CHALLENGE_PATH', '/_firewall/challenge'),
        'cookie_name' => 'fw_challenge_pass',
        'header_name' => 'X-Firewall-Challenge',
        'provider_options' => [],
        'audience' => env('FIREWALL_CHALLENGE_AUDIENCE', ''),
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    |
    | The library logs through Monolog, and so does Laravel, so the default is
    | to borrow the handlers off one of your own log channels rather than open a
    | second log file with its own rotation policy and its own place to forget
    | to ship. Firewall records arrive on your existing channel under the
    | channel name `firewall`, so they stay filterable.
    |
    | Set `channel` to NULL to opt out, and add library-format handler
    | definitions under `handlers` instead. `handlers` is appended either way,
    | so a channel plus one extra handler is a valid combination.
    |
    */

    'logger' => [
        /*
         * `env()`, never `config()`.
         *
         * Laravel loads config files in alphabetical order, so `firewall.php`
         * is evaluated before `logging.php` — and `config('logging.default')`
         * here returns NULL rather than 'stack'. The firewall then logs
         * nowhere: every block, every rule that failed to build and every
         * degraded backend discarded, on a default installation, with nothing
         * to show for it but a `firewall:doctor` warning.
         *
         * The nesting mirrors what Laravel's own `config/logging.php` does with
         * `LOG_CHANNEL`, so `FIREWALL_LOG_CHANNEL` overrides it and the
         * application's channel is the default.
         */
        'channel' => env('FIREWALL_LOG_CHANNEL', env('LOG_CHANNEL', 'stack')),

        'handlers' => [
            // [
            //     'class' => \Monolog\Handler\StreamHandler::class,
            //     'args' => [storage_path('logs/firewall.log'), 'Monolog\Level::Warning'],
            // ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Middleware
    |--------------------------------------------------------------------------
    |
    | `global` appends the middleware to Laravel's global stack automatically,
    | positioned after TrustProxies. It has to run after TrustProxies or every
    | IP-based rule reads a spoofable address; the integration verifies the
    | ordering it actually got rather than trusting that it worked, and
    | `php artisan firewall:doctor` reports on it.
    |
    | Set `global` to FALSE to place `EvaluateFirewall` yourself — in a route
    | group, or at a chosen index of the global stack. Two consequences:
    | route middleware runs after routing, so an unrouted challenge POST would
    | 404 before reaching the firewall (see `register_challenge_route`), and
    | nothing then guarantees TrustProxies ran first.
    |
    */

    'middleware' => [
        'global' => env('FIREWALL_MIDDLEWARE_GLOBAL', true),

        /*
         * Register a bare POST route on `challenge.path` carrying only the
         * firewall middleware, so a challenged visitor can always submit a
         * solution even when the middleware is not global. It is attached to
         * no route group, so VerifyCsrfToken never sees the request — the
         * interstitial form is served by the firewall and cannot carry a
         * Laravel CSRF token.
         *
         * Harmless when `global` is TRUE, because the global pass intercepts
         * the POST before routing and the route is never reached. Kept on by
         * default anyway: the failure it prevents is a challenged visitor
         * locked out permanently with no way to solve, which is worth one
         * unreachable route.
         */
        'register_challenge_route' => true,

        /*
         * What to do when the middleware is found to be running before
         * TrustProxies: 'log' records it at error level on every request,
         * 'throw' refuses the request. Ordering is a deploy-time property, so
         * 'throw' turns a silently bypassable allowlist into an outage you
         * notice — choose it if that trade is the right one for this app.
         */
        'on_bad_order' => env('FIREWALL_ON_BAD_ORDER', 'log'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Octane
    |--------------------------------------------------------------------------
    |
    | The firewall is bound as a scoped instance, which is a singleton under
    | PHP-FPM and is rebuilt for each request under Octane. That is deliberate,
    | and it is what makes `global.panic_file` work: the panic file is read once
    | per Firewall instance, so an instance that outlives the request would go
    | on reporting the mode it read when the worker booted — you would flip the
    | switch during an incident and nothing would happen until the workers were
    | restarted, which is the one moment that behaviour is least acceptable.
    |
    | Setting this to TRUE binds a true singleton: one Firewall per worker,
    | config parsed and plugins built once instead of per request. Take it only
    | if you have measured that you need it, and only with `panic_file` unset —
    | a panic file that does nothing is worse than no panic file.
    |
    */

    'octane' => [
        'persist_instance' => env('FIREWALL_OCTANE_PERSIST', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Views
    |--------------------------------------------------------------------------
    |
    | Blade views for the two responses this integration renders. Publish them
    | with `php artisan vendor:publish --tag=firewall-views` and edit, or point
    | these at views of your own.
    |
    | `challenge` is only used as a wrapper: the interstitial body itself comes
    | from the challenge provider, which owns the form, the nonce and the
    | JavaScript that carries the token back. The view receives it as `$body`
    | and can decorate around it, but must echo it unescaped for the challenge
    | to be solvable.
    |
    */

    'views' => [
        'block' => 'firewall::block',
        'challenge' => 'firewall::challenge',
    ],

    /*
    |--------------------------------------------------------------------------
    | Artisan
    |--------------------------------------------------------------------------
    |
    | The `firewall:*` commands wrap the scripts shipped in kanopi/firewall's
    | bin/ directory, which is the operational surface: they read the live
    | environment, open the real storage, and are the same code the library
    | documents. `bin_path` is discovered from the installed package and only
    | needs setting for an unusual vendor layout.
    |
    | Those scripts read YAML, and this file is PHP, so each command writes the
    | effective configuration to a temporary YAML file and points the script at
    | it. `keep_effective_config` leaves that file behind for inspection, which
    | is the fastest way to see what your PHP config actually became.
    |
    */

    'artisan' => [
        'bin_path' => null,
        'keep_effective_config' => false,

        /*
         * Where that temporary YAML is written. NULL uses the system temp
         * directory. Point it somewhere else if `/tmp` is read-only or noexec
         * on this host, or if you would rather the dumps landed under
         * `storage/` where the rest of the application's scratch files live.
         *
         * The challenge secret is deliberately not written into these files —
         * it travels to the script in its process environment instead, because
         * a temp file is cleaned up in a `finally` and that does not survive a
         * `kill -9`.
         */
        'temp_path' => null,

        /*
         * Where `firewall:rule` keeps the rules it writes. It owns this file
         * exclusively — it will not edit rules it did not write — so it is a
         * separate path from anything above, and it is added to `configs`
         * automatically once it exists.
         */
        'managed_rules' => base_path('config/firewall-managed.yml'),
    ],
];
