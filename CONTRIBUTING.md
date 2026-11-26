# Contributing

## index.html is a build artifact — do not edit it

The app still ships as one self-contained `index.html` you can drop on any
static host. That file is now **generated**. Edit `src/` and rebuild:

```sh
npm run build      # src/ -> index.html, and re-pins the CSP hashes
npm run check      # verifies index.html matches src/ and the CSP is sound
npm test           # unit tests (no browser needed)
npm run test:e2e   # real Chromium against a local relay
```

Commit both your `src/` change **and** the rebuilt `index.html`. CI fails if
they disagree.

### Why there is a build step at all

The CSP pins a `sha256` of the inline bundle, so every source edit invalidates
it. Recomputing that by hand is a footgun: get it wrong and the app loads a
blank page with a single console error. `scripts/build.mjs` is the only
supported way to produce `index.html`.

`src/index.html` pulls modules in with `// @include <path>` on its own line.
That is the whole module system — no bundler, no dependency resolution, same
as before.

## Testing

`npm test` runs pure-logic tests in Node. `npm run test:e2e` drives real
Chromium with a WebAuthn virtual authenticator and a local in-memory Nostr
relay (`test/relay.mjs`), so vault enrollment and recovery are exercised
against actual relay traffic.

One limit worth knowing: Chrome's virtual authenticator exposes no PRF material
over CDP, so a **synced** passkey cannot be emulated. Cross-device passkey
recovery is therefore not covered by CI and must be checked on real hardware.
The recovery-code and passphrase factors have no such limitation — a fresh
browser profile is a faithful "new device" for those, and CI covers them.

## Security-sensitive areas

Changes to cryptography, the vault, the data model or the threat model get
extra scrutiny. Please describe the security implications in the PR, and read
the security model section of the README first. In particular:

- Never let a recovery factor's secret reach a relay, a server or a log.
- Vault reads are hostile input: signature-check before decrypting.
- An nsec carries no provenance. If you touch key import or recovery, preserve
  `origin` so NIP-62 vanish is never offered for a key the user brought.
