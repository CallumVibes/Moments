#!/usr/bin/env node
/* Moments OPRF server — stretches a PIN without ever learning it.
 *
 * It holds a secret scalar k and answers exactly one question: given a curve
 * point B, what is k·B? Because the client blinds B with a fresh random scalar,
 * B is uniformly random and reveals nothing about the PIN, and two requests for
 * the same PIN are unlinkable.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * RUN TWO OF THESE, UNDER DIFFERENT OPERATORS.
 *
 * A single operator can brute-force every PIN: it knows k, so for each
 * candidate PIN it can derive that enrollment's locator itself and fetch the
 * blob from a public relay, with no rate limit in the way. The client folds
 * two servers' outputs together so neither alone can do this. The security of
 * a PIN rests on the two operators not colluding — so two endpoints on one
 * provider's infrastructure do NOT count as two operators.
 *
 * THE RATE LIMIT IS THE SECURITY BOUNDARY.
 * A 6-digit PIN is a million guesses. What makes it safe is this server
 * refusing them. The in-memory limiter below is correct for a single process
 * only; behind more than one instance it is a hole, because an attacker can
 * spread guesses across instances. For production, back it with shared,
 * persistent storage (Redis, or your platform's KV).
 *
 * LOSING k DESTROYS EVERY PIN ENROLLMENT.
 * Back it up, and keep it out of the process's own logs and crash dumps.
 * Clients are told never to rely on a PIN as their only recovery factor.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * Usage:
 *   OPRF_KEY=<64 hex chars> PORT=8787 node server/oprf-server.mjs
 *   node server/oprf-server.mjs --genkey     # print a fresh key and exit
 */
import http from 'node:http';
import { webcrypto, createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { secp256k1 } from './vendor-secp256k1.mjs';

const { ProjectivePoint, CURVE } = secp256k1;
const N = CURVE.n;

if (process.argv.includes('--genkey')) {
  const b = new Uint8Array(32);
  for (;;) {
    webcrypto.getRandomValues(b);
    const v = BigInt('0x' + Buffer.from(b).toString('hex'));
    if (v > 1n && v < N) { console.log(Buffer.from(b).toString('hex')); process.exit(0); }
  }
}

// Importing this module must have no side effects — no reading config, no
// exiting. Key loading happens in createServer() so tests (and any embedder)
// can construct a server without the process-level environment.
function loadKey(keyHex) {
  if (!/^[0-9a-f]{64}$/i.test(keyHex || '')) throw new Error('OPRF_KEY must be 64 hex characters. Generate one with --genkey.');
  const k = BigInt('0x' + keyHex);
  if (!(k > 1n && k < N)) throw new Error('OPRF_KEY is not a valid scalar for this curve.');
  return k;
}

/* ── Per-tag keys ──
 *
 * The server must NOT apply one global scalar to whatever point it is handed.
 * With a global key it is an oracle for arbitrary inputs, and the proof check
 * only gates *access*, not *which point* gets evaluated. An attacker holding
 * any valid account of their own could then blind a victim's point, present
 * their own tag and their own proof, and recover the victim's OPRF output —
 * which fully breaks social enrollment, because `sub` is public. The same hole
 * lets an attacker sidestep a victim's PIN rate limit by spending their own.
 *
 * Deriving the scalar from (master, tag) binds each evaluation to the account
 * the caller proved. An attacker's request is answered under the attacker's
 * key, which is useless against anyone else's vault.
 *
 * Consequence to be aware of when operating this: the master secret and the
 * tag together define every account's key, so the master still must never
 * change or be lost.
 */
export function keyForTag(master, tag) {
  for (let i = 0; i < 256; i++) {
    const h = createHash('sha256')
      .update('moments:oprf:tagkey:v1:').update(master).update(':').update(tag).update(Buffer.from([i]))
      .digest();
    const v = BigInt('0x' + h.toString('hex'));
    if (v > 1n && v < N) return v;      // rejection-sample rather than reduce, to avoid modulo bias
  }
  throw new Error('key-derivation-failed');
}

/* ── Social proof verification ──
 *
 * A social enrollment's OPRF input is derived from the provider's `sub`, and
 * `sub` is an IDENTIFIER, NOT A SECRET — stable, account-level, and handed to
 * every app the user authorizes. So this server must NOT evaluate a social tag
 * for anyone who merely knows a `sub`: it requires a fresh, signed ID token
 * proving the caller just authenticated as that user.
 *
 * What this cannot defend against, by construction: the identity provider
 * itself, which can mint a token for any of its users. That limitation is
 * inherent to social sign-in and is documented in the app, not papered over.
 */
const JWKS_TTL_MS = 60 * 60 * 1000;
const jwksCache = new Map();   // issuer -> { at, keys }

/* Issuers whose ID tokens count as proof. Microsoft's `iss` carries the
 * tenant GUID, so issuers are matched by predicate rather than by equality. */
const ISSUERS = [
  { test: i => i === 'https://accounts.google.com',
    jwks: () => 'https://www.googleapis.com/oauth2/v3/certs' },
  { test: i => /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/v2\.0$/i.test(i),
    jwks: i => i.replace(/\/v2\.0$/, '') + '/discovery/v2.0/keys' },
];
function issuerCfg(iss) { return ISSUERS.find(c => c.test(iss)) || null; }

function b64urlToBuf(s) { return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'); }

async function fetchJwks(issuer, fetchImpl) {
  const cfg = issuerCfg(issuer);
  if (!cfg) throw new Error('unknown-issuer');
  const hit = jwksCache.get(issuer);
  if (hit && Date.now() - hit.at < JWKS_TTL_MS) return hit.keys;
  const res = await (fetchImpl || fetch)(cfg.jwks(issuer));
  if (!res.ok) throw new Error('jwks-fetch-failed');
  const body = await res.json();
  const keys = body && Array.isArray(body.keys) ? body.keys : [];
  if (!keys.length) throw new Error('jwks-empty');
  jwksCache.set(issuer, { at: Date.now(), keys });
  return keys;
}

/* Verifies signature, issuer, audience, expiry and freshness, then returns the
 * claims. Audience must match a configured client id: a token minted for some
 * other app must not unlock anything here. */
export async function verifyIdToken(jwt, { audiences, now = Date.now(), fetchImpl, maxAgeMs = 10 * 60 * 1000 } = {}) {
  const parts = String(jwt).split('.');
  if (parts.length !== 3) throw new Error('bad-jwt');
  let header, claims;
  try {
    header = JSON.parse(b64urlToBuf(parts[0]).toString('utf8'));
    claims = JSON.parse(b64urlToBuf(parts[1]).toString('utf8'));
  } catch { throw new Error('bad-jwt'); }
  if (header.alg !== 'RS256') throw new Error('bad-alg');       // never accept "none", never HS*
  if (!claims.sub || !claims.iss) throw new Error('bad-claims');
  if (!issuerCfg(claims.iss)) throw new Error('unknown-issuer');

  const auds = [].concat(claims.aud || []);
  if (!audiences || !audiences.length) throw new Error('no-audience-configured');
  if (!auds.some(a => audiences.includes(a))) throw new Error('bad-audience');

  const expMs = Number(claims.exp || 0) * 1000;
  const iatMs = Number(claims.iat || 0) * 1000;
  if (!expMs || expMs < now) throw new Error('expired');
  // Freshness: an old-but-unexpired token should not be replayable for long.
  if (!iatMs || now - iatMs > maxAgeMs) throw new Error('stale');
  if (iatMs - now > 5 * 60 * 1000) throw new Error('future');

  const keys = await fetchJwks(claims.iss, fetchImpl);
  const jwk = keys.find(k => k.kid === header.kid) || null;
  if (!jwk) throw new Error('unknown-kid');
  const pub = createPublicKey({ key: jwk, format: 'jwk' });
  const signed = Buffer.from(parts[0] + '.' + parts[1], 'utf8');
  if (!cryptoVerify('RSA-SHA256', signed, pub, b64urlToBuf(parts[2]))) throw new Error('bad-signature');
  return claims;
}

// The tag a social enrollment must present, recomputed from the verified token
// so a caller cannot pair someone else's proof with their own tag.
export function socialTag(issuer, sub) {
  return createHash('sha256').update('moments:oprf:social:v1:' + issuer + ':' + sub).digest('hex');
}

/* ── Rate limiter ──
 * Two windows per tag: a short burst allowance so a mistyped PIN is not
 * punished, and a long one that makes sustained guessing pointless. Tags are
 * opaque hashes; this server never sees a handle or a PIN.
 */
function defaultLimits(env = process.env) {
  return [
    { windowMs: 10 * 60 * 1000, max: Number(env.OPRF_BURST || 10) },
    { windowMs: 24 * 60 * 60 * 1000, max: Number(env.OPRF_DAILY || 60) },
  ];
}

function makeLimiter(LIMITS) {
const hits = new Map();   // tag -> number[] (timestamps)

function rateLimit(tag, now = Date.now()) {
  const longest = Math.max(...LIMITS.map(l => l.windowMs));
  const times = (hits.get(tag) || []).filter(t => now - t < longest);
  for (const { windowMs, max } of LIMITS) {
    if (times.filter(t => now - t < windowMs).length >= max) {
      const oldest = Math.min(...times.filter(t => now - t < windowMs));
      return { ok: false, retryAfter: Math.ceil((oldest + windowMs - now) / 1000) };
    }
  }
  times.push(now);
  hits.set(tag, times);
  return { ok: true };
}

// Keep the map from growing without bound on a long-lived process.
setInterval(() => {
  const now = Date.now(), longest = Math.max(...LIMITS.map(l => l.windowMs));
  for (const [tag, times] of hits) {
    const live = times.filter(t => now - t < longest);
    if (live.length) hits.set(tag, live); else hits.delete(tag);
  }
}, 10 * 60 * 1000).unref();
return rateLimit;
}

const CORS = {
  'access-control-allow-origin': process.env.OPRF_ORIGIN || '*',   // see README: pin this in production
  'access-control-allow-headers': 'content-type',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-max-age': '86400',
};
const json = (res, code, body, extra = {}) => {
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS, ...extra });
  res.end(JSON.stringify(body));
};

function readBody(req, cap = 4096) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > cap) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export function createServer(opts = {}) {
  const masterHex = (opts.key || process.env.OPRF_KEY || '').toLowerCase();
  loadKey(masterHex);                    // validate up front, at construction
  const LIMITS = opts.limits || defaultLimits();
  const rateLimit = makeLimiter(LIMITS);
  // Client IDs whose ID tokens this server will accept as proof. Without any,
  // social tags are refused outright rather than evaluated unproven.
  const audiences = opts.audiences
    || String(process.env.OPRF_AUDIENCES || '').split(',').map(s => s.trim()).filter(Boolean);
  const fetchImpl = opts.fetchImpl;
  const nowFn = opts.now || (() => Date.now());
  const srv = http.createServer(async (req, res) => {
    if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }

    const path = (req.url || '').split('?')[0];
    // Deliberately exposes no key material and no per-tag counts: a probe
    // must not be able to ask whether a given account is being attacked.
    if (path === '/health') return json(res, 200, { ok: true, v: 1 });
    if (path !== '/evaluate') return json(res, 404, { error: 'not-found' });
    if (req.method !== 'POST') return json(res, 405, { error: 'method-not-allowed' });

    let body;
    try { body = JSON.parse(await readBody(req)); }
    catch { return json(res, 400, { error: 'bad-json' }); }

    const tag = body && body.tag;
    const blinded = body && body.blinded;
    if (typeof tag !== 'string' || !/^[0-9a-f]{64}$/i.test(tag)) return json(res, 400, { error: 'bad-tag' });
    if (typeof blinded !== 'string' || !/^0[23][0-9a-f]{64}$/i.test(blinded)) return json(res, 400, { error: 'bad-point' });

    let P;
    try { P = ProjectivePoint.fromHex(blinded); P.assertValidity(); }
    catch { return json(res, 400, { error: 'bad-point' }); }
    // The identity would make the answer independent of k, turning this into an
    // oracle that confirms nothing but wastes a slot; refuse it outright.
    if (P.equals(ProjectivePoint.ZERO)) return json(res, 400, { error: 'bad-point' });

    /* A social tag is only evaluated on proof of a fresh login, because the
     * `sub` it derives from is public. Checked BEFORE the rate limit, so a
     * stranger spraying unproven requests cannot burn a real user's budget. */
    if (typeof body.proof === 'string' && body.proof) {
      let claims;
      try {
        claims = await verifyIdToken(body.proof, { audiences, now: nowFn(), fetchImpl });
      } catch (e) {
        return json(res, 401, { error: 'bad-proof', detail: String(e.message) });
      }
      if (socialTag(claims.iss, claims.sub) !== tag.toLowerCase()) {
        return json(res, 401, { error: 'proof-tag-mismatch' });
      }
    } else if (body.social === true) {
      return json(res, 401, { error: 'proof-required' });
    }

    const rl = rateLimit(tag.toLowerCase());
    if (!rl.ok) return json(res, 429, { error: 'rate-limited', retry_after: rl.retryAfter },
                            { 'retry-after': String(rl.retryAfter) });

    try {
      // Per-tag key, never a global scalar. See keyForTag().
      return json(res, 200, { v: 1, evaluated: P.multiply(keyForTag(masterHex, tag.toLowerCase())).toHex(true) });
    } catch {
      return json(res, 500, { error: 'eval-failed' });
    }
  });
  srv.oprfLimits = LIMITS;
  return srv;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT || 8787);
  let srv;
  try { srv = createServer(); }
  catch (e) { console.error(String(e.message)); process.exit(1); }
  srv.listen(port, () => {
    // Log the key's fingerprint, never the key. Lets two deployments be told
    // apart in logs, and makes an accidental key rotation visible.
    const fp = createHash('sha256').update('moments:oprf:kid:' + process.env.OPRF_KEY).digest('hex').slice(0, 16);
    console.log(`moments-oprf listening on :${port}  key-fingerprint=${fp}`);
    console.log(`rate limits: ${srv.oprfLimits.map(l => `${l.max}/${l.windowMs / 60000}min`).join(', ')} per tag (in-memory, single process)`);
  });
}
