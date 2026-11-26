# Turning on one-tap sign-in

Everything is off until configured. This is the whole list, and it needs
accounts and hosting that only the operator has.

## What you are setting up

Signing in costs one tap and the user holds no secret, yet **no single company
can reach their key** — not Google, not Microsoft, not you. That requires two
OAuth clients at two different providers, and two OPRF servers run by two
different operators. Each piece below exists for that reason; skipping any of
them quietly removes the guarantee.

## 1. Two OAuth clients

**Google** — [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
→ Create credentials → OAuth client ID → **Web application**.

- Authorized JavaScript origins: `https://your-domain`
- Authorized redirect URIs: `https://your-domain/` (the page itself — the popup
  redirects back into this same file)
- Scopes: `openid` only. Nothing else is requested and nothing else is needed;
  the app never reads profile, email or Drive.

**Microsoft** — [Entra admin centre](https://entra.microsoft.com) → App
registrations → New registration.

- Supported account types: personal Microsoft accounts (plus work/school if you
  want them)
- Redirect URI: platform **Single-page application**, `https://your-domain/`
- Under Authentication, enable **ID tokens (implicit)**

Copy both client IDs.

> Redirect URIs are per-origin, so a self-hosted copy on another domain needs
> its own clients. That is why the shipped config is empty.

## 2. Two OPRF servers, two operators

**They must be run by different people or organisations.** Two endpoints on one
provider's infrastructure are one operator wearing two hats, and the guarantee
is only as strong as those two not colluding. See
[server/README.md](server/README.md).

Each operator, independently:

```sh
node server/oprf-server.mjs --genkey        # keep this; losing it kills every PIN
OPRF_KEY=<that key> \
OPRF_AUDIENCES=<google-client-id>,<microsoft-client-id> \
OPRF_ORIGIN=https://your-domain \
PORT=8787 node server/oprf-server.mjs
```

Or with the container image:

```sh
docker build -f server/Dockerfile -t moments-oprf .   # build from the repo root
docker run -e OPRF_KEY=... -e OPRF_AUDIENCES=... -e OPRF_ORIGIN=... -p 8787:8787 moments-oprf
```

`server/compose.yml` brings up both at once **for local testing only** — it
puts them on one host under one operator, which is exactly what production must
not do.

Before going further, note the two things that will silently void the
guarantee: the two servers sharing a key, and the in-memory rate limiter behind
more than one instance per server (an attacker spreads guesses across them).
Back the limiter with shared storage before scaling out.

## 3. Check it, then paste the config

```sh
npm run doctor -- https://oprf-a.example https://oprf-b.example \
  --google=<google-client-id> --microsoft=<microsoft-client-id>
```

This verifies the running servers rather than trusting them: reachable, keys
are per-account rather than a global oracle, unproven social requests refused,
CORS answered and pinned, and — the one that matters most — that the two
servers **hold different keys**. It refuses to print a config if anything
fails, and prints the exact meta tag when everything passes.

Paste that tag over the `moments-config` line at the top of `index.html`, and
redeploy. Leave `allowSingleProvider` as `false` unless you have decided that
one-tap Google is worth Google being able to reach your users' keys.

## 4. Confirm with a real account

Nothing above proves a real Google user can sign in — only you can check that,
because it needs a human at a consent screen:

1. Open the site in a fresh browser profile, choose **Continue with Google**
2. Complete both provider prompts (the second usually resolves silently)
3. You should land in the app with no key, code or passphrase typed
4. Open a *different* fresh profile and sign in again — the same account should
   come back
5. Confirm the relay holds only ciphertext (nothing matching `nsec1`)

If step 4 fails, the likely causes are a mismatched redirect URI, a client ID
missing from `OPRF_AUDIENCES`, or the two servers not actually being reachable
from the browser (check CORS).

## What is proven without this setup

`npm run test:login` runs the entire flow in a real browser against a real OIDC
provider — real popup, real redirect, real signature verification, two real
OPRF servers, a real relay — and asserts sign-in costs exactly one click and no
typing. `npm run test:all` runs everything.

The only thing those cannot cover is the providers' own domains and consent
screens, which is what step 4 is for.
