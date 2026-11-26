# Moments

**Private photo, video, and text sharing with your people. No accounts, no algorithms, no servers you have to trust.**

Moments is a single self-contained HTML file that lets a small group — a family, a friend group, a trip, a team — share photos, videos, and short text updates privately. There are no sign-ups, no email, no passwords. You create a network, invite people with a QR code or a join code, and everyone inside can see and share. Nobody outside can see anything.

Live instance: <https://momentsocial.net>

---

## What makes it different

- **No accounts.** Your identity is a cryptographic key generated on your device. There is no server-side account to create, and nothing to log into except your own key.
- **But you can't lose it.** Sign up with a passkey (Face ID / fingerprint) and your key is wrapped and stored encrypted on the relays, recoverable with a passkey, a recovery code, or a handle and passphrase. Nobody — not us, not a relay — can open it. See [Signing in and recovery](#signing-in-and-recovery).
- **Real end-to-end encryption.** Photos, videos, and posts are encrypted in your browser before they ever leave your device, using audited cryptographic libraries rather than hand-rolled crypto. Hosting servers only ever see ciphertext.
- **No algorithm, no feed manipulation.** You see exactly what the people in your network share, in order. That's it.
- **One file.** The entire app is a single HTML file. Open it locally, or drop it on any static host.

---

## Features

- **Feed** — photos, videos, and text posts from everyone in your network, newest first, with automatic date rollover after 7 days so older moments read like a diary rather than a live wall.
- **Camera capture** — built-in camera with a zoom slider, capturing at up to 1920px / 0.92 JPEG quality.
- **My Page** — a personal activity view of everything you've shared into the network.
- **Member profiles** — tap any member's name or avatar to see their profile within the network.
- **Reliable uploads** — photos upload by racing multiple Blossom servers in parallel and taking whichever responds first, so a single slow or dead server doesn't block a post.
- **Offline support** — an offline banner and IndexedDB caching mean the feed still loads with previously-seen content when you lose connection.
- **Accessibility** — expanded labels for screen readers throughout the interface.
- **Lightning tips** — an optional Lightning support button for tipping the project.
- **Resilient media** — broken or slow-to-load images fall back gracefully rather than leaving broken icons in the feed.

---

## How it works

Moments is built on top of **[Nostr](https://nostr.com/)**, an open decentralized protocol, used here as invisible infrastructure — none of the protocol details are exposed to the people using the app.

- **Identity** — each user has a secp256k1 keypair (a Nostr `nsec`/`npub`). The key *is* the account. Events are signed with BIP-340 Schnorr signatures.
- **Networks** — creating a network generates a random join code. A shared group key and a network "tag" are derived from that code via HKDF. Everyone who has the code can derive the same key.
- **Encryption** — photos, videos, and posts are encrypted client-side with AES-256-GCM using the network's group key (a fresh random IV per item) before upload. The encrypted blob is uploaded to a **[Blossom](https://github.com/hzrd149/blossom)** server; only the resulting ciphertext, its hash, and the IV travel inside the (also encrypted) event payload.
- **Sync** — encrypted events are published to and fetched from public Nostr relays. Relays see only ciphertext under an opaque tag.
- **Caching** — decrypted media is cached in-memory and in IndexedDB (image and avatar caches are kept in separate namespaces) so the feed loads fast and works offline once seen.

The custom event kind used for Moments content is `1818`.

---

## Signing in and recovery

There are three ways in. All of them end with the same key on your device, and
none of them involves an account on anybody's server.

| | What you hold | Works on a new device | Notes |
|---|---|---|---|
| **Google + Microsoft** | Nothing at all | Always | Usually **one tap**. **No single company can reach your key.** The default |
| **Continue with Google** | Nothing at all | Always | One tap, but Google *could* reach your key. Off unless an operator enables it |
| **Passkey** | Face ID / fingerprint | Only if your passkey syncs *and* carries its PRF secret | One tap. Not guaranteed — see below |
| **Handle + PIN** | 6+ digits | Always, while the PIN servers are up | Needs two OPRF servers — see below |
| **Recovery code** | 26 characters, ~125 bits | Always | Generated at signup; save it |
| **Handle + passphrase** | Something you remember | Always | Salted with your handle |
| **Moment key (nsec)** | The raw key | Always | The original path, unchanged |

### How recovery works

Each factor is enrolled *independently*. A factor's secret is stretched into
two values — a locator keypair and a wrapping key:

```
factor secret ──KDF──┬──> locSk    (secp256k1, LOCATES that enrollment)
                     └──> wrapKey  (AES-256-GCM, OPENS it)
```

Your nsec is encrypted under `wrapKey` and published as a NIP-78 replaceable
event (kind `30078`, `d=moments:vault:v1`) signed by `locSk`. Any single factor
recovers the account on its own, and each enrollment is a complete, independent
copy — there is no master blob whose loss takes the account with it.

What a relay can see: an opaque blob under an opaque pubkey. Because every
enrollment is signed by a *different* derived key, and never by your identity
key, relays cannot tell that two enrollments belong to one person, and cannot
link either to the npub it restores. There is nothing to enumerate — finding a
vault requires already knowing the factor that derives its locator.

### "Continue with Google" — what it does and does not protect

This is the easiest way in: tap one button, no key, no code, nothing to
remember, on any device. Here is exactly what it is worth.

**Your key is not in your Google account, and Google cannot passively read
it.** The encrypted vault lives on relays. The key that opens it is not in the
token and is not derivable from it — which matters, because the `sub` claim a
Google login yields is an *identifier, not a secret*: it is stable and handed
to every app you authorize. A design that derived the key from `sub` would let
anyone who learns your Google user ID open your vault. So instead the key comes
from the two OPRF servers, which apply their secret only on proof of a fresh
login.

**But Google issues that proof.** Google can mint an ID token for any of its
own users, present it, and obtain the key. No arrangement of storage or
encryption changes this: *any lock whose only key is "can prove you are her to
Google" is a lock Google can open.* The same is true of anyone who takes over
the Google account.

What the OPRF buys is the difference between Google **having** your key and
Google having to **go and take** it — a deliberate, targeted act that mints a
token for a named user and leaves a record on two independent third-party
servers. Passive access becomes an active attack. That is a real improvement,
and it is not the same as end-to-end encryption. Moments does not claim it is.

### Closing the gap completely: link two providers

A provider can always mint a token for its own user. It cannot mint another
company's signature. So linking **two independent providers** removes the
problem entirely:

```
root = KDF( OPRF_A(both identities, proved to Google)
          ‖ OPRF_B(both identities, proved to Microsoft) )
```

Each OPRF server is addressed under a *different* provider's tag, and answers
only on a proof matching that tag. Google can mint a Google token and satisfy
the first server; it cannot satisfy the second, so the root is never formed.
Microsoft is in the same position. Neither company — nor one OPRF operator, nor
a relay — can reach the key.

This costs the user nothing to remember, and usually nothing extra to do: the
second provider is asked with `prompt=none` first, so if the person already has
a session there it resolves silently and they never see it. Signing in is one
tap, no secrets, no backups, and it works on a brand-new device with nothing
saved. Only when the second provider has no session does it ask for a second
tap, and the suite covers both paths. It is the recommended mode,
and it is what `test/no-single-provider.test.mjs` exists to prove — that suite
plays Google at full strength (minting tokens for any user, knowing both public
`sub` values, reaching both servers) and asserts it still cannot derive the key.

Two accounts at the *same* provider are refused, since that would leave that
one company able to mint both halves.

**A PIN can be added on top of either mode**, which also defeats a provider
that mints a token, since it does not know the PIN and the OPRF servers
rate-limit guesses.

This is the default: new social accounts are enrolled as a pair, and
single-provider sign-in has to be switched on deliberately
(`allowSingleProvider`), because that mode is reachable by the provider.

### Has this actually been run?

Yes, end to end, in a real browser — see `test/live-login.e2e.mjs`, which runs
in CI. A real OIDC provider performs a real popup navigation and redirect, the
app really postMessages the token back to its opener, two real OPRF servers
really fetch the JWKS and verify the signature, and the vault really goes to a
real relay. The user side is **one click and nothing typed**. Then a brand-new browser
profile, **one click**, and the same identity comes back — asserted exactly, as
a click count. With the second provider's session removed, the suite also
covers the fallback asking for the extra tap.

The one thing not real is the issuer's domain: signing in as an actual Google
user needs Google-registered OAuth credentials and a human at a consent
screen. `test/live-providers.test.mjs` covers what can be checked against the
real Google and Microsoft endpoints without those — their live issuer strings,
the JWKS URLs derived from them, and that every published key imports through
the same code path the verifier uses.

### Turning it on

Everything is off until configured, and configuring it is one line — the
`moments-config` meta tag at the top of `index.html`:

```html
<meta name="moments-config" content='{
  "oprfServers": ["https://oprf-a.example", "https://oprf-b.example"],
  "providers": {"google": "...apps.googleusercontent.com", "microsoft": "..."},
  "allowSingleProvider": false
}'/>
```

Only `https` endpoints are accepted, so a misconfigured plaintext endpoint
cannot silently carry proofs in the clear. The two OPRF servers must be run by
**different operators** — see [server/README.md](server/README.md).

Step-by-step, including the OAuth console settings and how to confirm it with
a real account: **[SETUP.md](SETUP.md)**.

Check a deployment before trusting it, and get the tag to paste:

```sh
npm run doctor -- https://oprf-a.example https://oprf-b.example   --google=...apps.googleusercontent.com --microsoft=...
```

It verifies the running servers rather than assuming: that they are reachable,
that they **hold different keys** (identical output means one operator holds
both halves), that keys are per-account rather than a global oracle, that
unproven social requests are refused, and that CORS will not block the browser.
It refuses to print a config if any of that fails.

For most people — someone who would otherwise lose the account outright — a key
protected by their Google account, with its 2FA and recovery flows, is far
safer than a text file they will lose. Pick the row of the table that matches
what you actually worry about.

(On the others: Proton has no third-party auth API. Discord works the same way
as Google here, since the blob goes on relays rather than at the provider.
Redirect URIs are per-origin, so self-hosted copies need their own client ID —
`SOCIAL_PROVIDERS` is empty by default and the buttons stay hidden until it is
filled in.)

### How a 6-digit PIN can possibly be safe

A PIN has about 20 bits of entropy, and no amount of local stretching fixes
that — anyone holding the ciphertext just tries all million. A PIN is safe only
if guessing requires asking someone who can refuse.

So the PIN is stretched by an **Oblivious PRF**. Your device maps the PIN to a
curve point, blinds it with a fresh random scalar, and asks a server to apply
its secret key:

```
you:     P = hash_to_curve(pin)      B = r·P      ← r random, fresh each time
server:  E = k·B                                  ← k never leaves the server
you:     N = r⁻¹·E = k·P                          ← your stretched PIN
```

The server sees only `B`, a uniformly random point. It cannot learn your PIN,
cannot link two of your requests, and cannot compute the answer for a PIN it was
not asked about. Guessing now means making a request per guess — and the server
rate-limits those, which is what makes 20 bits enough.

**This needs two servers run by different operators.** One operator alone could
brute-force every PIN: knowing `k`, it could derive each candidate's locator
itself and fetch the blob from a public relay, offline and unthrottled. Folding
two independent keys together removes that:

```
root = KDF(k_A·P ‖ k_B·P)
```

Neither operator alone can compute the root. **The safety of a PIN therefore
rests on those two operators not colluding** — and two endpoints on one
provider's infrastructure are one operator wearing two hats. If no two servers
are configured, Moments hides the PIN option entirely rather than offering a
weaker version of it. See [server/README.md](server/README.md).

The trade-offs, stated plainly:

- **A PIN adds a liveness dependency** the other factors do not have. If either
  server is down you cannot unlock with a PIN; if either loses its key, every
  PIN enrollment is dead.
- **A known handle can be locked out on purpose.** Rate limiting has to count
  attempts against something, and that something is derived from your handle —
  which is guessable. Anyone can spend your attempt budget and keep your PIN
  unlock unavailable until the window decays.

Both are reasons a PIN is never your only recovery factor.

### The passkey caveat, stated plainly

A passkey is the nicest path and the least certain one. No vendor documents
that the WebAuthn PRF output stays identical after a passkey syncs to a second
device, and it has been reported to differ within one ecosystem (iPhone → Mac).
So Moments treats a passkey as a convenience unlock, never as your only factor:
signup enrolls a recovery code alongside it, and the "back up your key" nudge
stays until you have actually saved a device-independent factor.

---

## Running it

The app still ships as a single self-contained `index.html` — but that file is
now generated from `src/`. See [CONTRIBUTING.md](CONTRIBUTING.md).

```sh
npm run build   # src/ -> index.html (and re-pins the CSP hashes)
```

**Locally:** open `index.html` in a browser. (Some browsers restrict camera or download APIs on `file://`; serving over `http` avoids that — e.g. `python3 -m http.server` then open the printed URL.)

**Self-hosting:** upload `index.html` to any static host (Netlify, Cloudflare Pages, GitHub Pages, an S3 bucket, your own server). Rename it to `index.html` if you want it served at the domain root. No backend is required.

That's the whole deployment story. There is no database, no API server, no environment configuration.

---

## Security model — please read before trusting it

Moments uses real cryptography, but it makes deliberate tradeoffs in favor of simplicity. Understand these before sharing anything sensitive.

- **The join code is the security boundary.** Anyone who has a network's join code can derive the group key and decrypt everything in that network — past and future. Treat the code like a password. Share it over a channel you trust.
- **Member removal is cooperative-soft.** Removing someone stops their content from showing and signals the removal to others, but it does **not** rotate the group key. A removed member who kept the join code can still decrypt content and could rejoin. There is no cryptographic eviction.
- **Recovery is only as good as your factors.** If you enroll no recovery factor, your secret key remains the only way back in, and losing it is permanent. If you do enroll one, that factor becomes an equally powerful credential: anyone holding your recovery code can take over the account, and you cannot revoke it remotely. There is still no password reset, and no way for us to help — we hold nothing.
- **Durability is not guaranteed.** Media lives on free, public Blossom servers and Nostr relays, which may prune or drop old data at any time. Moments is not a backup or an archive. Keep your own copies of anything you care about.
- **Password handling.** Network passwords are never carried in invite URLs, and ownership of a network's password is locked to its verified original signer.
- **Metadata.** Relays can see the opaque network tag, event timing, and sizes of encrypted blobs, even though they cannot read content.
- **A recovery factor is a credential.** Anyone holding your recovery code — or your handle and PIN, or handle and passphrase — can take over the account, and you cannot revoke a factor remotely. Enroll only what you can keep private.
- **Single-provider social sign-in trusts that provider.** With "Continue with
  Google" alone, Google can obtain your key if it chooses to, because it issues
  the only credential involved. Linking a second provider removes this, and so
  does adding a PIN. The non-social factors involve neither party.
- **Unanimous OPRF collusion breaks a social pair, and always will.** Each leg
  goes to every configured server, so it takes *all* the operators rather than
  any two. But the limit is not fixable by better engineering. If the user
  supplies no secret and recovery must work on a brand-new device, the key is
  by definition a function of the provider identities and public data — and the
  operators collectively hold every OPRF key, so they can evaluate any input
  offline, with no proof and no rate limit. They *are* the oracle.
  `test/no-single-provider.test.mjs` demonstrates the coalition succeeding,
  rather than leaving it as a caveat, and demonstrates the only thing that
  stops it: a PIN the servers never see.
- **OPRF keys are per-account.** A server derives its scalar from its master
  secret *and* the account's tag, so it is never an oracle that will apply one
  global key to any point it is handed. Without this, anyone holding a valid
  account of their own could have a victim's input evaluated under their own
  tag — which would break social sign-in outright, since `sub` is public, and
  would let a victim's PIN rate limit be bypassed.
- **PIN servers see a rate-limit tag.** To count attempts, each OPRF server receives an opaque hash of your handle. It never sees your handle, your PIN, or your npub, but it can tell that *some* account is being unlocked, and how often. That is the minimum a lockout requires.

This software is provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). It has not been independently audited. Do not rely on it for high-stakes confidentiality.

---

## Tech notes

- Pure client-side JavaScript, no framework, no build-time dependency resolution — libraries are bundled inline directly in `index.html`, which is assembled from `src/` by `scripts/build.mjs` (a ~60-line Node script with no dependencies).
- Recovery factors use PBKDF2-SHA256 (600k iterations) for passphrases, HKDF-SHA256 for key separation, the WebAuthn `prf` extension for passkeys, and a two-server secp256k1 OPRF for PINs.
- The OPRF hashes to the curve by try-and-increment on the audited library's own point decompression, rather than a hand-rolled SSWU map. The vendored `@noble/curves` bundle carries exactly one modification: its export object additionally exposes the curve object, so the point arithmetic the OPRF needs is reachable. No library logic is changed.
- Cryptography uses the audited [`@noble/curves`](https://github.com/paulmillr/noble-curves), [`@noble/hashes`](https://github.com/paulmillr/noble-hashes), and [`@scure/base`](https://github.com/paulmillr/scure-base) libraries for secp256k1/Schnorr signing, hashing, and encoding, alongside the Web Crypto API for AES-256-GCM and HKDF.
- QR generation and scanning are built in (scanning uses `jsQR`, loaded on demand).
- Designed mobile-first and tested on real Android devices (Pixel, Samsung; Brave and Chrome); installable as a PWA via "Add to Home Screen".

---

## Contributing

This is a personal project shared as open source. Feel free to fork it, self-host it, and adapt it for your own group.

If you'd like to contribute changes, open an issue first to discuss the idea. Because the app is security-sensitive and intentionally minimal, changes that affect the cryptography, the data model, or the threat model will get extra scrutiny — please describe the security implications of anything you propose in those areas.

Edit `src/`, not `index.html` — the latter is generated, and CI fails if the two disagree. Run `npm run build && npm run check && npm test`, and test in a real browser — ideally a real mobile browser, since that's the primary target. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENSE) © 2026 CallumVibes

Signal: callum.21

Nostr: callum@nostr.fan

npub: npub15qc45zlcpftk8e9865h0g5k2zyl3grddr028fdr9plh7ksu7wdwqqmkr83
