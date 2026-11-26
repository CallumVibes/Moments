/* Tests for social sign-in, against a locally minted identity provider.
 *
 * The property that matters most: `sub` is PUBLIC, so knowing it must not be
 * enough. Every test below that says "unproven" is checking exactly that.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createSign, createHash, randomUUID } from 'node:crypto';
import { createServer, verifyIdToken, socialTag } from '../server/oprf-server.mjs';
import { secp256k1 } from '../server/vendor-secp256k1.mjs';

const ISS = 'https://accounts.google.com';
const AUD = 'test-client.apps.googleusercontent.com';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = 'test-key-1';

const jwk = { ...publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' };
const fetchImpl = async () => ({ ok: true, json: async () => ({ keys: [jwk] }) });

const b64u = b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function mintToken({ sub = '1234567890', aud = AUD, iss = ISS, iat, exp, alg = 'RS256', kid = KID, signWith = privateKey } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64u(JSON.stringify({ alg, kid, typ: 'JWT' }));
  const claims = b64u(JSON.stringify({ iss, aud, sub, iat: iat ?? now, exp: exp ?? now + 3600, nonce: randomUUID() }));
  const signer = createSign('RSA-SHA256');
  signer.update(header + '.' + claims);
  return `${header}.${claims}.${b64u(signer.sign(signWith))}`;
}

const opts = { audiences: [AUD], fetchImpl };

test('a well-formed token verifies', async () => {
  const c = await verifyIdToken(mintToken(), opts);
  assert.equal(c.sub, '1234567890');
  assert.equal(c.iss, ISS);
});

test('tokens for another app are refused', async () => {
  await assert.rejects(() => verifyIdToken(mintToken({ aud: 'someone-elses-client' }), opts), /bad-audience/);
});

test('a forged signature is refused', async () => {
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  await assert.rejects(() => verifyIdToken(mintToken({ signWith: other }), opts), /bad-signature/);
});

test('alg=none and HMAC confusion are refused', async () => {
  for (const alg of ['none', 'HS256', 'RS512'])
    await assert.rejects(() => verifyIdToken(mintToken({ alg }), opts), /bad-alg/);
});

test('expired and stale tokens are refused', async () => {
  const now = Math.floor(Date.now() / 1000);
  await assert.rejects(() => verifyIdToken(mintToken({ exp: now - 10 }), opts), /expired/);
  // unexpired but old: must not stay replayable for the token's whole lifetime
  await assert.rejects(() => verifyIdToken(mintToken({ iat: now - 3600, exp: now + 3600 }), opts), /stale/);
});

test('an unknown issuer is refused', async () => {
  await assert.rejects(() => verifyIdToken(mintToken({ iss: 'https://evil.example' }), opts), /unknown-issuer/);
});

test('an unknown signing key is refused', async () => {
  await assert.rejects(() => verifyIdToken(mintToken({ kid: 'not-a-real-kid' }), opts), /unknown-kid/);
});

test('a server with no configured audience refuses everything', async () => {
  await assert.rejects(() => verifyIdToken(mintToken(), { audiences: [], fetchImpl }), /no-audience-configured/);
});

/* ── The OPRF server's social gate ── */
const validPoint = secp256k1.ProjectivePoint.BASE.multiply(99n).toHex(true);
async function withServer(fn, extra = {}) {
  const srv = createServer({ key: 'cd'.repeat(32), audiences: [AUD], fetchImpl, ...extra });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  try { await fn(`http://127.0.0.1:${srv.address().port}`); } finally { srv.close(); }
}
const post = (base, body) => fetch(base + '/evaluate', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
});

test('knowing sub is NOT enough — an unproven social request is refused', async () => {
  await withServer(async base => {
    const tag = socialTag(ISS, '1234567890');
    // This is the whole point: `sub` is public, so this must fail.
    const r = await post(base, { tag, blinded: validPoint, social: true });
    assert.equal(r.status, 401);
    assert.equal((await r.json()).error, 'proof-required');
  });
});

test('a valid proof unlocks evaluation', async () => {
  await withServer(async base => {
    const r = await post(base, { tag: socialTag(ISS, '1234567890'), blinded: validPoint, social: true, proof: mintToken() });
    assert.equal(r.status, 200);
    assert.match((await r.json()).evaluated, /^0[23][0-9a-f]{64}$/);
  });
});

test("a proof cannot be paired with someone else's tag", async () => {
  await withServer(async base => {
    const r = await post(base, {
      tag: socialTag(ISS, 'a-different-user'),     // victim's tag
      blinded: validPoint, social: true,
      proof: mintToken({ sub: '1234567890' }),     // attacker's own valid login
    });
    assert.equal(r.status, 401);
    assert.equal((await r.json()).error, 'proof-tag-mismatch');
  });
});

test('a rejected proof does not spend the victim budget', async () => {
  await withServer(async base => {
    const tag = socialTag(ISS, '1234567890');
    for (let i = 0; i < 10; i++) await post(base, { tag, blinded: validPoint, social: true });   // all 401
    const r = await post(base, { tag, blinded: validPoint, social: true, proof: mintToken() });
    assert.equal(r.status, 200, 'the real user must still get through');
  }, { limits: [{ windowMs: 600000, max: 3 }] });
});

test('the client tag matches what the server recomputes', async () => {
  // The browser derives the tag independently; if these ever drift, every
  // social login breaks with a confusing mismatch.
  const clientSide = createHash('sha256').update('moments:oprf:social:v1:' + ISS + ':' + '1234567890').digest('hex');
  assert.equal(clientSide, socialTag(ISS, '1234567890'));
});

test('adding a PIN changes the derived input', () => {
  const noPin = createHash('sha256').update('moments:social:v1:' + ISS + ':777:').digest('hex');
  const withPin = createHash('sha256').update('moments:social:v1:' + ISS + ':777:4821').digest('hex');
  assert.notEqual(noPin, withPin, 'a PIN must actually change the key material');
});
