# Moments

**Private photo, video, and text sharing with your people. No accounts, no algorithms, no servers you have to trust.**

Moments is a single self-contained HTML file that lets a small group — a family, a friend group, a trip, a team — share photos, videos, and short text updates privately. There are no sign-ups, no email, no passwords. You create a network, invite people with a QR code or a join code, and everyone inside can see and share. Nobody outside can see anything.

Live instance: <https://momentsocial.net>

---

## What makes it different

- **No accounts.** Your identity is a cryptographic key generated on your device. There is no server-side account to create, and nothing to log into except your own key.
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

## Running it

Because the whole app is one file, there's no build step.

**Locally:** open `index.html` in a browser. (Some browsers restrict camera or download APIs on `file://`; serving over `http` avoids that — e.g. `python3 -m http.server` then open the printed URL.)

**Self-hosting:** upload `index.html` to any static host (Netlify, Cloudflare Pages, GitHub Pages, an S3 bucket, your own server). Rename it to `index.html` if you want it served at the domain root. No backend is required.

That's the whole deployment story. There is no database, no API server, no environment configuration.

---

## Security model — please read before trusting it

Moments uses real cryptography, but it makes deliberate tradeoffs in favor of simplicity. Understand these before sharing anything sensitive.

- **The join code is the security boundary.** Anyone who has a network's join code can derive the group key and decrypt everything in that network — past and future. Treat the code like a password. Share it over a channel you trust.
- **Member removal is cooperative-soft.** Removing someone stops their content from showing and signals the removal to others, but it does **not** rotate the group key. A removed member who kept the join code can still decrypt content and could rejoin. There is no cryptographic eviction.
- **No account recovery.** Your secret key is the only way back into your identity. Lose it and it is gone permanently — by design, there is no reset.
- **Durability is not guaranteed.** Media lives on free, public Blossom servers and Nostr relays, which may prune or drop old data at any time. Moments is not a backup or an archive. Keep your own copies of anything you care about.
- **Password handling.** Network passwords are never carried in invite URLs, and ownership of a network's password is locked to its verified original signer.
- **Metadata.** Relays can see the opaque network tag, event timing, and sizes of encrypted blobs, even though they cannot read content.

This software is provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). It has not been independently audited. Do not rely on it for high-stakes confidentiality.

---

## Tech notes

- Pure client-side JavaScript, no framework, no build-time dependency resolution — libraries are bundled inline directly in `index.html`.
- Cryptography uses the audited [`@noble/curves`](https://github.com/paulmillr/noble-curves), [`@noble/hashes`](https://github.com/paulmillr/noble-hashes), and [`@scure/base`](https://github.com/paulmillr/scure-base) libraries for secp256k1/Schnorr signing, hashing, and encoding, alongside the Web Crypto API for AES-256-GCM and HKDF.
- QR generation and scanning are built in (scanning uses `jsQR`, loaded on demand).
- Designed mobile-first and tested on real Android devices (Pixel, Samsung; Brave and Chrome); installable as a PWA via "Add to Home Screen".

---

## Contributing

This is a personal project shared as open source. Feel free to fork it, self-host it, and adapt it for your own group.

If you'd like to contribute changes, open an issue first to discuss the idea. Because the app is security-sensitive and intentionally minimal, changes that affect the cryptography, the data model, or the threat model will get extra scrutiny — please describe the security implications of anything you propose in those areas.

There is no build pipeline: edit `index.html` directly, keep it as the single source of truth, and test in a real browser — ideally a real mobile browser, since that's the primary target.

---

## License

[MIT](LICENSE) © 2026 CallumVibes

Signal: callum.21

Nostr: callum@nostr.fan

npub: npub15qc45zlcpftk8e9865h0g5k2zyl3grddr028fdr9plh7ksu7wdwqqmkr83
