{{--
    The challenge interstitial.

    Unlike the block view, this one is a wrapper and almost nothing about it is
    yours to change. `$body` is a complete HTML document rendered by the
    challenge provider, and it carries the parts that make the challenge
    solvable: the form posting to the submission path, the signed per-challenge
    state a stateless provider needs to verify an answer, the redirect target,
    the TTL, and the JavaScript that stashes the pass token for XHR callers.

    So the default is to emit it and nothing else, unescaped. Two consequences
    worth being explicit about:

      * `{!! !!}` is correct here, not a lapse. The provider owns this document
        and escaping it would render the markup as visible text. The provider is
        library code building its own output, not user input passing through.

      * Wrapping it in a layout produces a document inside a document. If you
        want a branded interstitial, replace the provider instead — implement
        `Kanopi\Firewall\Challenge\ChallengeProviderInterface`, render whatever
        you like, and name your class in `firewall.challenge.provider`. That is
        the supported extension point, and it keeps the form fields and the
        verification in one place where they cannot drift apart.

    Available data:
      $body     The provider's interstitial document.
      $request  The Illuminate request that was challenged.
--}}
{!! $body !!}
