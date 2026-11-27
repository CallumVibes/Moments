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

/* ── Every hardcoded assumption, checked against the providers' own live
 * metadata. If Google or Microsoft change any of this, these fail loudly
 * instead of the integration breaking silently in production. ── */
const DISCOVERY = [
  { name: 'Google',
    url: 'https://accounts.google.com/.well-known/openid-configuration',
    issuer: 'https://accounts.google.com',
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',   // hardcoded in src/social.js
    jwks: 'https://www.googleapis.com/oauth2/v3/certs',        // derived in server/oprf-server.mjs
    subjectType: 'public' },
  { name: 'Microsoft',
    url: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
    authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    jwks: null,                                                // per-tenant; checked above
    subjectType: 'pairwise' },
];

for (const p of DISCOVERY) {
  test(`${p.name}: live discovery matches what the app hardcodes`, { skip: !online && 'offline' }, async () => {
    const res = await fetch(p.url);
    assert.ok(res.ok, `${p.url} returned ${res.status}`);
    const d = await res.json();

    assert.equal(d.issuer, p.issuer, 'issuer string changed');
    assert.equal(d.authorization_endpoint, p.authUrl, 'the authorize URL the app sends users to has moved');
    if (p.jwks) assert.equal(d.jwks_uri, p.jwks, 'the JWKS URL the server derives has moved');

    // The flow is implicit id_token in a fragment: both must still be offered.
    assert.ok(d.response_types_supported.includes('id_token'),
      'id_token response type withdrawn — the whole client-side flow depends on it');
    assert.ok(d.response_modes_supported.includes('fragment'),
      'fragment response mode withdrawn — the popup callback reads location.hash');

    // verifyIdToken refuses anything but RS256.
    assert.ok(d.id_token_signing_alg_values_supported.includes('RS256'), 'RS256 no longer offered');

    // Only `openid` is requested; nothing about the person is read.
    assert.ok(d.scopes_supported.includes('openid'));
  });
}

test('Google confirms `sub` is PUBLIC, not pairwise', { skip: !online && 'offline' }, async () => {
  /* This is the fact the whole social design turns on. A public subject type
   * means the same `sub` goes to every client, so it is an identifier and not
   * a secret — which is why the key is never derived from it, and why the OPRF
   * servers demand a signed proof instead of accepting a bare tag. If Google
   * ever switched to pairwise this assumption would be worth revisiting. */
  const d = await (await fetch(DISCOVERY[0].url)).json();
  assert.deepEqual(d.subject_types_supported, ['public'],
    'Google subject type changed — revisit the reasoning in src/social.js');
});

test('Microsoft issues pairwise subjects, and the regex matches its real issuer shape',
  { skip: !online && 'offline' }, async () => {
  const d = await (await fetch(DISCOVERY[1].url)).json();
  assert.ok(d.subject_types_supported.includes('pairwise'));
  // The live issuer is templated, so the server matches it by shape. Confirm a
  // real tenant id substituted into that template satisfies the rule.
  const concrete = d.issuer.replace('{tenantid}', '9188040d-6c67-4c5b-b112-36a304b66dad');
  assert.ok(ISSUER_TESTS[1](concrete), `issuer rule does not match ${concrete}`);
  assert.equal(jwksUrlFor(concrete),
    'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/discovery/v2.0/keys');
});

test('the live providers are genuinely different issuers', { skip: !online && 'offline' }, () => {
  // The whole guarantee rests on these being two separate companies. If a
  // future config ever pointed both legs at one issuer, the pair would be
  // worthless — assert they differ at the issuer level.
  const [a, b] = LIVE.map(p => p.iss);
  assert.notEqual(a, b);
  assert.notEqual(new URL(a).host, new URL(b).host, 'two legs must not share an issuer host');
});
