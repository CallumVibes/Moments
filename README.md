# Moments

**Private photo sharing with your people. No accounts, no algorithms, no servers you have to trust.**

Moments is a single self-contained HTML file that lets a small group — a family, a friend group, a trip, a team — share photos and short videos privately. There are no sign-ups, no email, no passwords. You create a network, invite people with a QR code or a join code, and everyone inside can see and share. Nobody outside can see anything.

Live instance: <https://momentsocial.net>

---

## What makes it different

- **No accounts.** Your identity is a cryptographic key generated on your device. There is no server-side account to create, and nothing to log into except your own key.
- **Real end-to-end encryption.** Photos and videos are encrypted in your browser before they ever leave your device. The hosting servers only ever see ciphertext.
- **No algorithm, no feed manipulation.** You see exactly what the people in your network share, in order. That's it.
- **One file.** The entire app is a single HTML file. Open it locally, or drop it on any static host.

---

## How it works

Moments is built on top of **[Nostr](https://nostr.com/)**, an open decentralized protocol, used here as invisible infrastructure — none of the protocol details are exposed to the people using the app.

- **Identity** — each user has a secp256k1 keypair (a Nostr `nsec`/`npub`). The key *is* the account. Events are signed with BIP-340 Schnorr signatures.
- **Networks** — creating a network generates a random join code. A shared group key and a network "tag" are derived from that code via HKDF. Everyone who has the code can derive the same key.
- **Encryption** — photos and videos are encrypted client-side with AES-256-GCM using the network's group key (a fresh random IV per file) before upload. The encrypted blob is uploaded to a **[Blossom](https://github.com/hzrd149/blossom)** server; only the resulting ciphertext, its hash, and the IV travel inside the (also encrypted) event payload.
- **Sync** — encrypted events are published to and fetched from public Nostr relays. Relays see only ciphertext under an opaque tag.
- **Caching** — decrypted media is cached in-memory and in IndexedDB (still encrypted on disk) so the feed loads fast and works offline once seen.

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
- **Avatars (historical note).** Earlier versions uploaded profile avatars unencrypted; current versions encrypt them per-network like other media. Externally-linked avatars (pasted `https://` URLs) are treated as already-public by the user's choice.
- **Metadata.** Relays can see the opaque network tag, event timing, and sizes of encrypted blobs, even though they cannot read content.

This software is provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). It has not been independently audited. Do not rely on it for high-stakes confidentiality.

---

## Tech notes

- Pure client-side JavaScript, no framework, no dependencies bundled at build time.
- Cryptography via the Web Crypto API (AES-GCM, HKDF, SHA-256) plus a small secp256k1/Schnorr implementation for Nostr signing.
- QR generation and scanning are built in (scanning uses `jsQR`, loaded on demand).
- Designed mobile-first; installable as a PWA via "Add to Home Screen".

---

## Contributing

This is a personal project shared as open source. Feel free to fork it, self-host it, and adapt it for your own group.

If you'd like to contribute changes, open an issue first to discuss the idea. Because the app is security-sensitive and intentionally minimal, changes that affect the cryptography, the data model, or the threat model will get extra scrutiny — please describe the security implications of anything you propose in those areas.

There is no build pipeline: edit `moments-home.html` directly and test in a real browser (ideally a real mobile browser, since that's the primary target).

---

## License

[MIT](LICENSE) © 2026 Callum Field

Contact: callum@nostr.fan
