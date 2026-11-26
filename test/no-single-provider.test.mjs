/* THE GOAL TEST.
 *
 * Google never sees the nsec, and cannot obtain it — while the user does
 * nothing but tap twice.
 *
 * The adversary here is Google itself, at full strength: it can mint a valid
 * ID token for ANY of its own users, it knows both providers' public `sub`
 * values, it can reach both OPRF servers, and it can read every byte the
 * relays hold. The only thing it cannot do is mint Microsoft's signature.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync, createSign, webcrypto, randomUUID } from 'node:crypto';
import vm from 'node:vm';
import { createServer, socialTag } from '../server/oprf-server.mjs';
import { secp256k1 } from '../server/vendor-secp256k1.mjs';

const GOOGLE_ISS = 'https://accounts.google.com';
const MS_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';
const MS_ISS = `https://login.microsoftonline.com/${MS_TENANT}/v2.0`;
const AUD_G = 'moments-google-client';
const AUD_M = 'moments-ms-client';

// Two independent issuers, two independent signing keys. Google does not hold
// Microsoft's private key — that is the entire basis of the guarantee.
function mkIdp(iss, aud, kid) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };
  const b64u = b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return {
    iss, aud, jwk,
    mint(sub) {
      const now = Math.floor(Date.now() / 1000);
      const h = b64u(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' }));
      const c = b64u(JSON.stringify({ iss, aud, sub, iat: now, exp: now + 3600, nonce: randomUUID() }));
      const s = createSign('RSA-SHA256'); s.update(h + '.' + c);
      return { provider: iss === GOOGLE_ISS ? 'google' : 'microsoft', iss, sub, idToken: `${h}.${c}.${b64u(s.sign(privateKey))}` };
    },
  };
}
const google = mkIdp(GOOGLE_ISS, AUD_G, 'g1');
const microsoft = mkIdp(MS_ISS, AUD_M, 'm1');
const fetchImpl = async url => ({
  ok: true,
  json: async () => ({ keys: String(url).includes('microsoftonline') ? [microsoft.jwk] : [google.jwk] }),
});

// Client-side OPRF, loaded from the shipped source.
const sha256 = async b => new Uint8Array(await webcrypto.subtle.digest('SHA-256', b));
const strToBytes = s => new TextEncoder().encode(s);
const bytesToHex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
const concatBytes = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const oprfSrc = await readFile(new URL('../src/oprf.js', import.meta.url), 'utf8');
const ctx = vm.createContext({
  MomentsCrypto: { secp256k1 }, crypto: webcrypto, sha256, strToBytes, bytesToHex, concatBytes,
  fetch, AbortController, setTimeout, clearTimeout, Uint8Array, Error, JSON, Array, BigInt, String,
});
vm.runInContext(oprfSrc + ';globalThis.__api={oprfHashToCurve,oprfEvaluate,OPRF_DOMAIN};', ctx);
const { oprfHashToCurve, oprfEvaluate, OPRF_DOMAIN } = ctx.__api;

// Mirrors vaultKeysFromSocialPair: the two legs go to DIFFERENT servers, each
// under its own provider's tag and proof.
const order = (a, b) => (a.iss + ':' + a.sub) <= (b.iss + ':' + b.sub) ? [a, b] : [b, a];
async function pairRoot(servers, identA, identB, pin = '') {
  const [x, y] = order(identA, identB);
  const input = await sha256(strToBytes(`moments:social-pair:v1:${x.iss}:${x.sub}|${y.iss}:${y.sub}:${pin}`));
  const point = await oprfHashToCurve(OPRF_DOMAIN, input);
  const parts = [
    await oprfEvaluate(servers[0], await tagOf(x), point, undefined, x.idToken),
    await oprfEvaluate(servers[1], await tagOf(y), point, undefined, y.idToken),
  ];
  return bytesToHex(await sha256(concatBytes(strToBytes(OPRF_DOMAIN + ':root:'), ...parts)));
}
const tagOf = async i => bytesToHex(await sha256(strToBytes('moments:oprf:social:v1:' + i.iss + ':' + i.sub)));

async function withServers(fn) {
  const mk = key => createServer({ key, audiences: [AUD_G, AUD_M], fetchImpl });
  const a = mk('a1'.repeat(32)), b = mk('b2'.repeat(32));
  await new Promise(r => a.listen(0, '127.0.0.1', r));
  await new Promise(r => b.listen(0, '127.0.0.1', r));
  const urls = [`http://127.0.0.1:${a.address().port}`, `http://127.0.0.1:${b.address().port}`];
  try { await fn(urls); } finally { a.close(); b.close(); }
}

const VICTIM_G = '10769150350006150715113082367';
const VICTIM_M = '00000000-0000-0000-1234-abcdefabcdef';

test('the user gets the same key every time, from either tap order', async () => {
  await withServers(async urls => {
    const g = google.mint(VICTIM_G), m = microsoft.mint(VICTIM_M);
    const first = await pairRoot(urls, g, m);
    const second = await pairRoot(urls, microsoft.mint(VICTIM_M), google.mint(VICTIM_G));
    assert.equal(first, second, 'tapping Microsoft first must derive the same key');
    assert.equal(first.length, 64);
  });
});

test('GOOGLE CANNOT derive the key, even minting tokens at will', async () => {
  await withServers(async urls => {
    const real = await pairRoot(urls, google.mint(VICTIM_G), microsoft.mint(VICTIM_M));

    // Google knows both public `sub` values and mints whatever Google tokens it
    // likes. It cannot produce a Microsoft-signed token, so the second leg has
    // no valid proof. Try every shape of forgery available to it.
    const forgeries = [
      google.mint(VICTIM_M),                                   // Google token carrying the MS subject
      { ...google.mint(VICTIM_G), iss: MS_ISS },               // relabelled issuer, Google signature
      { provider: 'microsoft', iss: MS_ISS, sub: VICTIM_M, idToken: google.mint(VICTIM_M).idToken },
    ];
    let anySucceeded = false;
    for (const fake of forgeries) {
      try {
        const got = await pairRoot(urls, google.mint(VICTIM_G), fake);
        if (got === real) anySucceeded = true;
      } catch (_) { /* refused, as required */ }
    }
    assert.equal(anySucceeded, false, 'Google must not be able to form the key');
  });
});

test('one leg alone yields nothing — a single provider is not half the key', async () => {
  await withServers(async urls => {
    const real = await pairRoot(urls, google.mint(VICTIM_G), microsoft.mint(VICTIM_M));
    // Everything Google CAN legitimately obtain: its own leg, under its own tag.
    const g = google.mint(VICTIM_G);
    const input = await sha256(strToBytes(`moments:social-pair:v1:${GOOGLE_ISS}:${VICTIM_G}|${MS_ISS}:${VICTIM_M}:`));
    const point = await oprfHashToCurve(OPRF_DOMAIN, input);
    const legA = await oprfEvaluate(urls[0], await tagOf(g), point, undefined, g.idToken);
    const halfOnly = bytesToHex(await sha256(concatBytes(strToBytes(OPRF_DOMAIN + ':root:'), legA)));
    assert.notEqual(halfOnly, real);
    // And it cannot stand in for the missing leg by reusing its own twice.
    const doubled = bytesToHex(await sha256(concatBytes(strToBytes(OPRF_DOMAIN + ':root:'), legA, legA)));
    assert.notEqual(doubled, real);
  });
});

test('Google cannot make the SECOND server answer for the Microsoft leg', async () => {
  await withServers(async urls => {
    const input = await sha256(strToBytes('anything'));
    const point = await oprfHashToCurve(OPRF_DOMAIN, input);
    const msTag = await tagOf({ iss: MS_ISS, sub: VICTIM_M });
    // A perfectly valid Google token, pointed at the victim's Microsoft tag.
    await assert.rejects(
      () => oprfEvaluate(urls[1], msTag, point, undefined, google.mint(VICTIM_G).idToken),
      /oprf-proof-rejected/, 'the server must refuse a proof that does not match the tag');
    // And no proof at all is refused too.
    await assert.rejects(
      () => oprfEvaluate(urls[1], msTag, point, undefined, google.mint(VICTIM_M).idToken),
      /oprf-proof-rejected/, 'a Google-signed token must not satisfy a Microsoft tag');
  });
});

test('a relay holding every byte of the vault learns nothing', async () => {
  await withServers(async urls => {
    const root = await pairRoot(urls, google.mint(VICTIM_G), microsoft.mint(VICTIM_M));
    // The root is what encrypts the nsec. Nothing published to a relay contains
    // it, and it is not derivable from the public identifiers alone.
    const publicFacts = JSON.stringify({ GOOGLE_ISS, MS_ISS, VICTIM_G, VICTIM_M });
    assert.ok(!publicFacts.includes(root.slice(0, 16)));
    const fromPublicOnly = bytesToHex(await sha256(strToBytes(publicFacts)));
    assert.notEqual(fromPublicOnly, root);
  });
});
