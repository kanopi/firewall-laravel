{{--
    The page a blocked visitor sees.

    Publish it with `php artisan vendor:publish --tag=firewall-views` and edit
    freely — nothing here is load-bearing. A blocked request is over: there is
    no form to preserve and no state to carry, unlike the challenge view.

    Available data:
      $message  The firewall's banning message, with the library's template
                tokens already interpolated. It can contain the visitor's own
                IP address and the URL they asked for, which makes it
                attacker-influenced text — keep it escaped.
      $status   The HTTP status this is being served with.
      $request  The Illuminate request that was blocked.

    Deliberately self-contained, with no layout and no asset references. A
    blocked request should not be executing application code or fetching from
    the application it was just refused access to, and a layout would do both.
--}}
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>{{ $status }} &mdash; Request blocked</title>
    <style>
        :root { color-scheme: light dark; }
        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
            box-sizing: border-box;
            font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f4f4f5;
            color: #18181b;
        }
        main { max-width: 32rem; }
        .code { font-size: 0.8125rem; letter-spacing: 0.08em; text-transform: uppercase; opacity: 0.6; }
        h1 { font-size: 1.5rem; margin: 0.25rem 0 0.75rem; }
        p { margin: 0; }
        @media (prefers-color-scheme: dark) {
            body { background: #18181b; color: #f4f4f5; }
        }
    </style>
</head>
<body>
    <main>
        <p class="code">Error {{ $status }}</p>
        <h1>Request blocked</h1>
        <p>{{ $message !== '' ? $message : 'This request was blocked by the firewall.' }}</p>
    </main>
</body>
</html>
