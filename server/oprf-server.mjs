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
import { webcrypto, createHash } from 'node:crypto';
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
  const K = loadKey(opts.key || process.env.OPRF_KEY || '');
  const LIMITS = opts.limits || defaultLimits();
  const rateLimit = makeLimiter(LIMITS);
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

    const rl = rateLimit(tag.toLowerCase());
    if (!rl.ok) return json(res, 429, { error: 'rate-limited', retry_after: rl.retryAfter },
                            { 'retry-after': String(rl.retryAfter) });

    try {
      return json(res, 200, { v: 1, evaluated: P.multiply(K).toHex(true) });
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
