/* A real OIDC identity provider, for exercising sign-in end to end.
 *
 * This is not a stub that hands the app a token: it implements the parts of
 * OpenID Connect the flow actually uses — an /authorize endpoint that redirects
 * back with a fragment-encoded id_token, and a JWKS endpoint the OPRF servers
 * fetch to verify the signature. The browser performs a genuine popup
 * navigation, a genuine redirect, and a genuine postMessage back to the opener.
 *
 * Only the issuer's domain differs from Google or Microsoft. Nothing about the
 * app's code path is stubbed or shortcut.
 */
import http from 'node:http';
import { generateKeyPairSync, createSign } from 'node:crypto';

const b64u = b => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export async function startIdp({ port = 0, label = 'idp', subject = 'user-1' } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = label + '-key';
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };
  let currentSubject = subject;
  let hasSession = true;      // whether prompt=none can be answered silently
  const seen = [];

  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, `http://localhost:${srv.address().port}`);
    if (url.pathname === '/jwks') {
      res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
      return res.end(JSON.stringify({ keys: [jwk] }));
    }
    if (url.pathname === '/authorize') {
      const q = url.searchParams;
      const redirect = q.get('redirect_uri');
      const state = q.get('state') || '';
      const nonce = q.get('nonce') || '';
      const aud = q.get('client_id') || '';
      seen.push({ aud, nonce, state, redirect, responseType: q.get('response_type'), prompt: q.get('prompt') });
      if (!redirect) { res.writeHead(400); return res.end('missing redirect_uri'); }
      // prompt=none must answer from an existing session or refuse without UI,
      // exactly as Google and Microsoft do.
      if (q.get('prompt') === 'none' && !hasSession) {
        res.writeHead(302, { location: `${redirect}#error=login_required&state=${encodeURIComponent(state)}` });
        return res.end();
      }
      const now = Math.floor(Date.now() / 1000);
      const iss = `http://localhost:${srv.address().port}`;
      const h = b64u(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' }));
      const c = b64u(JSON.stringify({ iss, aud, sub: currentSubject, iat: now, exp: now + 3600, nonce }));
      const s = createSign('RSA-SHA256'); s.update(h + '.' + c);
      const idToken = `${h}.${c}.${b64u(s.sign(privateKey))}`;
      res.writeHead(302, { location: `${redirect}#id_token=${idToken}&state=${encodeURIComponent(state)}` });
      return res.end();
    }
    res.writeHead(404); res.end('not found');
  });

  await new Promise(r => srv.listen(port, '127.0.0.1', r));
  const p = srv.address().port;
  return {
    port: p,
    issuer: `http://localhost:${p}`,
    authUrl: `http://localhost:${p}/authorize`,
    jwksUrl: `http://localhost:${p}/jwks`,
    requests: () => seen,
    setSubject: s => { currentSubject = s; },
    setHasSession: v => { hasSession = !!v; },
    promptsSeen: () => seen.map(r => r.prompt),
    close: () => srv.close(),
  };
}
