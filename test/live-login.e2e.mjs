/* A genuine sign-in, end to end, in a real browser.
 *
 * Everything in the path is real: a real OIDC provider doing a real popup
 * navigation and redirect, real postMessage back to the opener, real ID token
 * signature verification against a real JWKS fetch, two real OPRF servers
 * applying real per-account keys, a real Nostr relay, and the real vault.
 *
 * The user's side is two clicks and nothing else — no key, no code, no
 * passphrase, no typing. Then a brand-new browser profile, two clicks again,
 * and the same identity comes back.
 *
 * The one thing not real is the issuer's domain. Signing in as an actual
 * Google user needs Google-registered OAuth credentials and a human at a
 * consent screen; test/live-providers.test.mjs covers the parts of the real
 * Google and Microsoft endpoints that can be checked without those.
 */
import { chromium } from 'playwright';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import http from 'node:http';
import { startRelay } from './relay.mjs';
import { startIdp } from './idp.mjs';
import { createServer as createOprf, makeExtraIssuer } from '../server/oprf-server.mjs';

const root = new URL('..', import.meta.url).pathname;
const OUT = join(root, 'test/.tmp-login');
const PORT = 8299, RELAY = 7557;
const AUD_A = 'moments-test-client-a', AUD_B = 'moments-test-client-b';

const fails = [];
const ok = (n, c, extra) => { console.log((c ? '  PASS  ' : '  FAIL  ') + n + (extra ? '  [' + extra + ']' : '')); if (!c) fails.push(n); };

const idpA = await startIdp({ label: 'alpha', subject: 'alpha-user-1' });
const idpB = await startIdp({ label: 'beta', subject: 'beta-user-1' });
const relay = await startRelay(RELAY);

const extraIssuers = [makeExtraIssuer(idpA.issuer, idpA.jwksUrl), makeExtraIssuer(idpB.issuer, idpB.jwksUrl)];
const oprfA = createOprf({ key: 'a7'.repeat(32), audiences: [AUD_A, AUD_B], extraIssuers });
const oprfB = createOprf({ key: 'b8'.repeat(32), audiences: [AUD_A, AUD_B], extraIssuers });
await new Promise(r => oprfA.listen(8897, '127.0.0.1', r));
await new Promise(r => oprfB.listen(8898, '127.0.0.1', r));
const OPRF = ['http://localhost:8897', 'http://localhost:8898'];

// Build the app configured exactly as an operator would configure it.
let html = await readFile(join(root, 'index.html'), 'utf8');
html = html.replace(/const DEFAULT_RELAYS=\[[^\]]*\];/, `const DEFAULT_RELAYS=['ws://localhost:${RELAY}'];`);
html = html.replace('connect-src https: wss:',
  `connect-src https: wss: ws://localhost:${RELAY} ${OPRF.join(' ')} ${idpA.issuer} ${idpB.issuer}`);
html = html.replace(String.raw`/^https:\/\/[^\s]+$/i`, String.raw`/^https?:\/\/[^\s]+$/i`);
const cfg = JSON.stringify({
  oprfServers: OPRF,
  providers: {
    google: { clientId: AUD_A, authUrl: idpA.authUrl, issuer: idpA.issuer },
    microsoft: { clientId: AUD_B, authUrl: idpB.authUrl, issuer: idpB.issuer },
  },
  allowSingleProvider: false,
}).replace(/'/g, '&#39;');
html = html.replace(/<meta name="moments-config" content='[^']*'\/>/, `<meta name="moments-config" content='${cfg}'/>`);
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
html = html.replace(/script-src ([^;]*);/,
  'script-src ' + scripts.map(x => `'sha256-${createHash('sha256').update(x, 'utf8').digest('base64')}'`).join(' ') + ';');
await mkdir(OUT, { recursive: true });
await writeFile(join(OUT, 'index.html'), html);

const site = http.createServer(async (req, res) => {
  try {
    const body = await readFile(join(OUT, 'index.html'));
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
await new Promise(r => site.listen(PORT, '127.0.0.1', r));

const browser = await chromium.launch();
const APP = `http://localhost:${PORT}/index.html`;

async function freshProfile() {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push(e.message));
  await page.goto(APP);
  await page.waitForTimeout(900);
  return { ctx, page, errs };
}

console.log('-- signing up: two clicks, nothing typed --');
const A = await freshProfile();
ok('the Google button is offered once configured', await A.page.isVisible('#btn-social-google'));
ok('signup warns about the second tap up front', await A.page.isVisible('#social-pair-note'));

await A.page.evaluate(() => openModal('signup'));
await A.page.waitForTimeout(200);
// Click one. Both provider popups open, redirect, and post back on their own.
await A.page.click('#btn-social-google');
await A.page.waitForFunction(() => document.getElementById('ss5')?.classList.contains('active')
  || document.getElementById('ss3')?.classList.contains('active')
  || (document.getElementById('social-err') || {}).textContent, { timeout: 60000 }).catch(() => {});
const sErr = await A.page.evaluate(() => (document.getElementById('social-err') || {}).textContent || '');
const nsecA = await A.page.evaluate(() => _nsec);
ok('signup completed with no typing at all', /^nsec1[a-z0-9]{58}$/.test(nsecA || ''), sErr);

ok('both providers were actually visited', idpA.requests().length >= 1 && idpB.requests().length >= 1,
   `alpha=${idpA.requests().length} beta=${idpB.requests().length}`);
ok('the app asked for an id_token, bound to a nonce',
   idpA.requests().every(r => r.responseType === 'id_token' && r.nonce));
ok('each provider saw only its OWN client id',
   idpA.requests().every(r => r.aud === AUD_A) && idpB.requests().every(r => r.aud === AUD_B));

const stored = relay.stored().filter(e => e.kind === 30078);
ok('the vault is on the relay as ciphertext only',
   stored.length >= 1 && !stored.some(e => e.content.includes('nsec1')));

console.log('\n-- a brand-new device: two clicks, identity returns --');
const B = await freshProfile();
ok('starts logged out', await B.page.evaluate(() => !_nsec));
await B.page.evaluate(() => openModal('login'));
await B.page.waitForTimeout(200);
await B.page.click('#btn-social-login-google');
// First leg finds no single-provider vault, so the second tap is offered.
await B.page.waitForSelector('#btn-social-second:visible', { timeout: 60000 }).catch(() => {});
ok('after the first tap the second account is requested', await B.page.isVisible('#btn-social-second'));
await B.page.click('#btn-social-second');
await B.page.waitForFunction(() => !!window._nsec || (document.getElementById('social-login-err') || {}).textContent,
  { timeout: 60000 }).catch(() => {});
const lErr = await B.page.evaluate(() => (document.getElementById('social-login-err') || {}).textContent || '');
ok('SIGNED IN on a new device and recovered the SAME nsec',
   await B.page.evaluate(() => _nsec) === nsecA, lErr);
ok('no uncaught errors anywhere in the flow', A.errs.length === 0 && B.errs.length === 0,
   (A.errs[0] || B.errs[0] || ''));

console.log('\n-- a different person at the same providers gets a different account --');
idpA.setSubject('alpha-user-2'); idpB.setSubject('beta-user-2');
const C = await freshProfile();
await C.page.evaluate(() => openModal('login'));
await C.page.click('#btn-social-login-google');
await C.page.waitForSelector('#btn-social-second:visible', { timeout: 60000 }).catch(() => {});
await C.page.click('#btn-social-second');
await C.page.waitForFunction(() => !!window._nsec || (document.getElementById('social-login-err') || {}).textContent,
  { timeout: 60000 }).catch(() => {});
ok('another user does not land in the first user\'s account', await C.page.evaluate(() => _nsec) !== nsecA);

console.log('\n' + (fails.length ? `FAILED: ${fails.length} — ${fails.join(' | ')}` : 'ALL CHECKS PASSED'));
await browser.close(); site.close(); relay.close(); oprfA.close(); oprfB.close(); idpA.close(); idpB.close();
process.exit(fails.length ? 1 : 0);
