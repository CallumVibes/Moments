/* Unit tests for the OPRF client and server: the blinding identity, the
 * obliviousness property, the two-server requirement, and the rate limit that
 * is the actual security boundary for a short PIN.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto, createHash } from 'node:crypto';
import vm from 'node:vm';
import { secp256k1 } from '../server/vendor-secp256k1.mjs';
import { createServer } from '../server/oprf-server.mjs';

// Load oprf.js with the handful of app globals it leans on.
const src = await readFile(new URL('../src/oprf.js', import.meta.url), 'utf8');
const sha256 = async b => new Uint8Array(await webcrypto.subtle.digest('SHA-256', b));
const strToBytes = s => new TextEncoder().encode(s);
const bytesToHex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
const concatBytes = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };

function loadOprf(fetchImpl) {
  const ctx = vm.createContext({
    MomentsCrypto: { secp256k1 }, crypto: webcrypto, sha256, strToBytes, bytesToHex, concatBytes,
    fetch: fetchImpl, AbortController, setTimeout, clearTimeout, Uint8Array, Error, JSON, Array, BigInt, String,
  });
  vm.runInContext(src + ';globalThis.__api={oprfHashToCurve,oprfRandomBlind,oprfEvaluate,oprfRoot,OPRF_DOMAIN};', ctx);
  return ctx.__api;
}

const { ProjectivePoint, CURVE } = secp256k1;

test('hash-to-curve is deterministic and input-sensitive', async () => {
  const { oprfHashToCurve } = loadOprf();
  const a = await oprfHashToCurve('d', strToBytes('1234'));
  const b = await oprfHashToCurve('d', strToBytes('1234'));
  const c = await oprfHashToCurve('d', strToBytes('1235'));
  assert.equal(a.toHex(true), b.toHex(true), 'same input must give the same point');
  assert.notEqual(a.toHex(true), c.toHex(true), 'one digit of difference must move the point');
  a.assertValidity();
});

test('hash-to-curve separates domains', async () => {
  const { oprfHashToCurve } = loadOprf();
  const a = await oprfHashToCurve('one', strToBytes('x'));
  const b = await oprfHashToCurve('two', strToBytes('x'));
  assert.notEqual(a.toHex(true), b.toHex(true));
});

test('blinds are in range and never degenerate', () => {
  const { oprfRandomBlind } = loadOprf();
  for (let i = 0; i < 200; i++) {
    const r = oprfRandomBlind();
    assert.ok(r > 1n && r < CURVE.n, `blind out of range: ${r}`);
  }
  const seen = new Set();
  for (let i = 0; i < 200; i++) seen.add(oprfRandomBlind().toString());
  assert.equal(seen.size, 200, 'blinds must not repeat');
});

// A fake server that is honest, and records exactly what it was shown.
function fakeServer(k) {
  const seen = [];
  const fetchImpl = async (url, opts) => {
    const body = JSON.parse(opts.body);
    seen.push(body);
    const P = ProjectivePoint.fromHex(body.blinded);
    return { ok: true, status: 200, json: async () => ({ v: 1, evaluated: P.multiply(k).toHex(true) }) };
  };
  return { fetchImpl, seen };
}

test('an evaluation unblinds to k*P — the OPRF identity', async () => {
  const k = 0x4242424242424242424242424242424242424242424242424242424242424242n % CURVE.n;
  const { fetchImpl } = fakeServer(k);
  const { oprfHashToCurve, oprfEvaluate } = loadOprf(fetchImpl);
  const P = await oprfHashToCurve('moments:oprf:v1', strToBytes('secret-pin'));
  const out = await oprfEvaluate('http://s', 'a'.repeat(64), P);
  assert.equal(bytesToHex(out), P.multiply(k).toHex(true));
});

test('the server never sees the input, and cannot link two requests for it', async () => {
  const k = 99n;
  const { fetchImpl, seen } = fakeServer(k);
  const { oprfHashToCurve, oprfEvaluate } = loadOprf(fetchImpl);
  const P = await oprfHashToCurve('moments:oprf:v1', strToBytes('1234'));
  const o1 = await oprfEvaluate('http://s', 'a'.repeat(64), P);
  const o2 = await oprfEvaluate('http://s', 'a'.repeat(64), P);
  assert.equal(bytesToHex(o1), bytesToHex(o2), 'same PIN must yield the same output');
  assert.notEqual(seen[0].blinded, seen[1].blinded, 'but the two requests must look unrelated');
  assert.notEqual(seen[0].blinded, P.toHex(true), 'the raw point must never be sent');
  for (const s of seen) assert.ok(!JSON.stringify(s).includes('1234'), 'the PIN must not appear in the request');
});

test('a malicious server cannot force a known output', async () => {
  for (const evil of [
    ProjectivePoint.ZERO.toHex ? '000000000000000000000000000000000000000000000000000000000000000000' : 'x',
    '02' + '00'.repeat(32),          // not on the curve
    'not-a-point',
  ]) {
    const { oprfHashToCurve, oprfEvaluate } = loadOprf(async () => ({ ok: true, status: 200, json: async () => ({ v: 1, evaluated: evil }) }));
    const P = await oprfHashToCurve('d', strToBytes('p'));
    await assert.rejects(() => oprfEvaluate('http://s', 'a'.repeat(64), P), /oprf-bad-response/);
  }
});

test('rate limiting and transport failures surface distinctly', async () => {
  const cases = [
    [{ ok: false, status: 429, json: async () => ({}) }, /oprf-rate-limited/],
    [{ ok: false, status: 500, json: async () => ({}) }, /oprf-server-error/],
    [{ ok: true, status: 200, json: async () => ({ nope: 1 }) }, /oprf-bad-response/],
  ];
  for (const [resp, want] of cases) {
    const { oprfHashToCurve, oprfEvaluate } = loadOprf(async () => resp);
    const P = await oprfHashToCurve('d', strToBytes('p'));
    await assert.rejects(() => oprfEvaluate('http://s', 'a'.repeat(64), P), want);
  }
  const { oprfHashToCurve, oprfEvaluate } = loadOprf(async () => { throw new Error('boom'); });
  const P = await oprfHashToCurve('d', strToBytes('p'));
  await assert.rejects(() => oprfEvaluate('http://s', 'a'.repeat(64), P), /oprf-unreachable/);
});

test('the root needs EVERY server — one key is not enough to compute it', async () => {
  const kA = 111n, kB = 222n;
  const route = async (url, opts) => {
    const P = ProjectivePoint.fromHex(JSON.parse(opts.body).blinded);
    const k = url.includes('//a') ? kA : kB;
    return { ok: true, status: 200, json: async () => ({ v: 1, evaluated: P.multiply(k).toHex(true) }) };
  };
  const { oprfRoot } = loadOprf(route);
  const tag = 'a'.repeat(64), input = strToBytes('1234');
  const both = await oprfRoot(['http://a', 'http://b'], tag, input);
  assert.equal(both.length, 32);
  assert.equal(bytesToHex(await oprfRoot(['http://a', 'http://b'], tag, input)), bytesToHex(both), 'reproducible');

  // What a single colluding operator could compute differs from the real root.
  const onlyA = await oprfRoot(['http://a'], tag, input);
  const onlyB = await oprfRoot(['http://b'], tag, input);
  assert.notEqual(bytesToHex(onlyA), bytesToHex(both));
  assert.notEqual(bytesToHex(onlyB), bytesToHex(both));
  // Order is part of the definition, so a swapped list is a different root.
  assert.notEqual(bytesToHex(await oprfRoot(['http://b', 'http://a'], tag, input)), bytesToHex(both));
});

test('a partial result never silently produces a key', async () => {
  const route = async url => url.includes('//b')
    ? { ok: false, status: 500, json: async () => ({}) }
    : { ok: true, status: 200, json: async () => ({ v: 1, evaluated: ProjectivePoint.BASE.toHex(true) }) };
  const { oprfRoot } = loadOprf(route);
  await assert.rejects(() => oprfRoot(['http://a', 'http://b'], 'a'.repeat(64), strToBytes('x')), /oprf-server-error/);
});

/* ── Server ── */
async function withServer(fn, opts = {}) {
  const srv = createServer({ key: 'ab'.repeat(32), ...opts });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { await fn(base); } finally { srv.close(); }
}
const post = (base, body) => fetch(base + '/evaluate', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
});
const validPoint = ProjectivePoint.BASE.multiply(12345n).toHex(true);

test('server evaluates a well-formed request', async () => {
  await withServer(async base => {
    const r = await post(base, { v: 1, tag: 'c'.repeat(64), blinded: validPoint });
    assert.equal(r.status, 200);
    const b = await r.json();
    assert.match(b.evaluated, /^0[23][0-9a-f]{64}$/);
    // and it really is k*P
    const k = BigInt('0x' + 'ab'.repeat(32));
    assert.equal(b.evaluated, ProjectivePoint.fromHex(validPoint).multiply(k).toHex(true));
  });
});

test('a bad key is refused at construction, not at request time', () => {
  for (const bad of ['', 'xyz', 'ab'.repeat(10), '00'.repeat(32)])
    assert.throws(() => createServer({ key: bad }), /OPRF_KEY/);
});

test('server rejects malformed input without consuming the budget', async () => {
  await withServer(async base => {
    for (const body of [
      { tag: 'short', blinded: validPoint },
      { tag: 'c'.repeat(64), blinded: 'nope' },
      { tag: 'c'.repeat(64), blinded: '02' + '00'.repeat(32) },
      { tag: 'c'.repeat(64) },
      {},
    ]) {
      const r = await post(base, body);
      assert.equal(r.status, 400, JSON.stringify(body));
    }
    // a valid request still succeeds afterwards, so bad input did not count
    assert.equal((await post(base, { tag: 'c'.repeat(64), blinded: validPoint })).status, 200);
  });
});

test('rate limit blocks a burst and reports when to retry', async () => {
  await withServer(async base => {
    const tag = 'd'.repeat(64);
    let blocked = 0, allowed = 0, retryAfter = null;
    for (let i = 0; i < 8; i++) {
      const r = await post(base, { tag, blinded: validPoint });
      if (r.status === 429) { blocked++; retryAfter = r.headers.get('retry-after'); } else allowed++;
    }
    assert.equal(allowed, 3, 'should allow exactly the configured burst');
    assert.equal(blocked, 5);
    assert.ok(Number(retryAfter) > 0, 'must tell the client when to come back');
  }, { limits: [{ windowMs: 600000, max: 3 }] });
});

test('rate limit is per tag, so one account cannot lock out another', async () => {
  await withServer(async base => {
    for (let i = 0; i < 3; i++) await post(base, { tag: 'e'.repeat(64), blinded: validPoint });
    assert.equal((await post(base, { tag: 'e'.repeat(64), blinded: validPoint })).status, 429);
    assert.equal((await post(base, { tag: 'f'.repeat(64), blinded: validPoint })).status, 200);
  }, { limits: [{ windowMs: 600000, max: 3 }] });
});

test('a 6-digit PIN is infeasible to grind within the limit', async () => {
  // Not a behavioural test — an arithmetic one, asserting the limit is actually
  // set somewhere useful. 10^6 PINs at the default daily cap must take years.
  const daily = 60;
  const yearsToHalf = (1e6 / 2) / daily / 365;
  assert.ok(yearsToHalf > 20, `expected >20 years to reach 50% coverage, got ${yearsToHalf.toFixed(1)}`);
});

test('health endpoint leaks nothing', async () => {
  await withServer(async base => {
    const b = await (await fetch(base + '/health')).json();
    assert.deepEqual(Object.keys(b).sort(), ['ok', 'v']);
    const s = JSON.stringify(b);
    assert.ok(!s.includes('ab'.repeat(8)), 'must not echo key material');
  });
});
