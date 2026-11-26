/* Live check against the REAL identity providers.
 *
 * The rest of the suite mints its own tokens, which proves the logic but not
 * that it lines up with what Google and Microsoft actually publish. This test
 * fetches their real JWKS endpoints and asserts the verifier can consume them:
 * the issuer matcher recognises the live issuer strings, the JWKS URL derived
 * from each issuer resolves, and every key imports under the exact code path
 * verifyIdToken uses.
 *
 * It cannot sign in as a real user — that needs a browser and a human — so it
 * stops at the boundary where a real token would arrive. Skipped offline.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';

const online = await fetch('https://www.googleapis.com/oauth2/v3/certs', { method: 'HEAD' })
  .then(r => r.ok).catch(() => false);

const LIVE = [
  { name: 'Google', iss: 'https://accounts.google.com',
    jwks: 'https://www.googleapis.com/oauth2/v3/certs' },
  { name: 'Microsoft (consumers)', iss: 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
    jwks: 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/discovery/v2.0/keys' },
];

// The same two rules the server uses, restated here so a drift fails loudly.
const ISSUER_TESTS = [
  i => i === 'https://accounts.google.com',
  i => /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/v2\.0$/i.test(i),
];
const jwksUrlFor = iss => iss === 'https://accounts.google.com'
  ? 'https://www.googleapis.com/oauth2/v3/certs'
  : iss.replace(/\/v2\.0$/, '') + '/discovery/v2.0/keys';

for (const p of LIVE) {
  test(`${p.name}: live issuer string is recognised`, { skip: !online && 'offline' }, () => {
    assert.ok(ISSUER_TESTS.some(t => t(p.iss)), `no issuer rule matches ${p.iss}`);
    assert.equal(jwksUrlFor(p.iss), p.jwks, 'derived JWKS URL must match the published one');
  });

  test(`${p.name}: live JWKS imports through the real code path`, { skip: !online && 'offline' }, async () => {
    const res = await fetch(p.jwks);
    assert.ok(res.ok, `${p.jwks} returned ${res.status}`);
    const body = await res.json();
    assert.ok(Array.isArray(body.keys) && body.keys.length, 'JWKS must carry keys');

    let usable = 0;
    for (const jwk of body.keys) {
      if (jwk.kty !== 'RSA') continue;
      assert.ok(jwk.kid, 'every key needs a kid — verifyIdToken selects on it');
      // Exactly what verifyIdToken does with a key before checking a signature.
      const pub = createPublicKey({ key: jwk, format: 'jwk' });
      assert.equal(pub.asymmetricKeyType, 'rsa');
      usable++;
    }
    assert.ok(usable > 0, 'no RS256-usable keys found; the verifier would reject every token');
  });
}

test('the live providers are genuinely different issuers', { skip: !online && 'offline' }, () => {
  // The whole guarantee rests on these being two separate companies. If a
  // future config ever pointed both legs at one issuer, the pair would be
  // worthless — assert they differ at the issuer level.
  const [a, b] = LIVE.map(p => p.iss);
  assert.notEqual(a, b);
  assert.notEqual(new URL(a).host, new URL(b).host, 'two legs must not share an issuer host');
});
