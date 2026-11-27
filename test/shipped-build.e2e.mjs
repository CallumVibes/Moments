/* Does the DELIVERED build — exactly as committed, with the empty config —
 * let someone sign in effortlessly without Google ever seeing the nsec?
 *
 * Nothing here is configured: no OAuth client ids, no OPRF servers, the
 * moments-config meta tag untouched from what ships. The only change is the
 * relay list, pointed at a local relay so the test can inspect what leaves the
 * browser. If this passes, "no sign-in can occur in the delivered build" is
 * false: the passkey path needs no deployment at all.
 */
import { chromium } from 'playwright';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import http from 'node:http';
import { startRelay } from './relay.mjs';

const root = new URL('..', import.meta.url).pathname;
const OUT = join(root, 'test/.tmp-shipped');
const PORT = 8399, RELAY = 7667;
const fails = [];
const ok = (n, c, extra) => { console.log((c ? '  PASS  ' : '  FAIL  ') + n + (extra ? '  [' + extra + ']' : '')); if (!c) fails.push(n); };

const relay = await startRelay(RELAY);

let html = await readFile(join(root, 'index.html'), 'utf8');
// Confirm we really are testing the shipped configuration before touching it.
const shippedCfg = html.match(/<meta name="moments-config" content='([^']*)'\/>/)[1];
const parsed = JSON.parse(shippedCfg.replace(/&#39;/g, "'"));
console.log('shipped config:', JSON.stringify(parsed));

html = html.replace(/const DEFAULT_RELAYS=\[[^\]]*\];/, `const DEFAULT_RELAYS=['ws://localhost:${RELAY}'];`);
html = html.replace('connect-src https: wss:', `connect-src https: wss: ws://localhost:${RELAY}`);
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
html = html.replace(/script-src ([^;]*);/,
  'script-src ' + scripts.map(x => `'sha256-${createHash('sha256').update(x, 'utf8').digest('base64')}'`).join(' ') + ';');
await mkdir(OUT, { recursive: true });
await writeFile(join(OUT, 'index.html'), html);

const site = http.createServer(async (_, res) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(await readFile(join(OUT, 'index.html')));
});
await new Promise(r => site.listen(PORT, '127.0.0.1', r));

const browser = await chromium.launch();
const prfAuth = {
  protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
  hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
  hasPrf: true, automaticPresenceSimulation: true,
};
async function device({ prf = false } = {}) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push(e.message));
  if (prf) {
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: prfAuth });
  }
  await page.goto(`http://localhost:${PORT}/index.html`);
  await page.waitForTimeout(900);
  return { page, errs };
}

console.log('\n-- the config really is empty, as shipped --');
ok('no OPRF servers configured', Array.isArray(parsed.oprfServers) && parsed.oprfServers.length === 0);
ok('no provider client ids configured',
   Object.values(parsed.providers || {}).every(v => !v));
ok('single-provider social is off by default', parsed.allowSingleProvider === false);

const A = await device({ prf: true });
console.log('\n-- what the empty build offers --');
ok('server-backed paths are correctly hidden', !(await A.page.evaluate(() => vaultPinAvailable()))
   && !(await A.page.evaluate(() => socialAnyAvailable())));
await A.page.evaluate(() => openModal('login'));
await A.page.waitForTimeout(200);
ok('no Google button is shown when unconfigured', !(await A.page.isVisible('#btn-social-login-google')));
ok('the passkey button IS offered with zero configuration', await A.page.isVisible('#btn-passkey-login'));

console.log('\n-- one tap, nothing typed, no servers deployed --');
await A.page.evaluate(() => { closeModal('login'); openModal('signup'); });
await A.page.waitForTimeout(200);
await A.page.click('#btn-passkey');
await A.page.waitForFunction(() => document.getElementById('ss5')?.classList.contains('active')
  || (document.getElementById('passkey-err') || {}).textContent, { timeout: 40000 }).catch(() => {});
const err = await A.page.evaluate(() => (document.getElementById('passkey-err') || {}).textContent || '');
const nsec = await A.page.evaluate(() => _nsec);
const code = await A.page.evaluate(() => _vaultRecoveryCode);
ok('SIGNED UP with one tap and no typing', /^nsec1[a-z0-9]{58}$/.test(nsec || ''), err);

const stored = relay.stored().filter(e => e.kind === 30078);
ok('the nsec left the browser only as ciphertext',
   stored.length >= 1 && !stored.some(e => JSON.stringify(e).includes(nsec)));
ok('GOOGLE IS NOT INVOLVED AT ALL — no request could have reached it',
   Object.values(parsed.providers || {}).every(v => !v));

console.log('\n-- and it comes back on a brand-new device --');
const B = await device();
await B.page.evaluate(() => { openModal('login'); pickLogin('code'); });
await B.page.fill('#login-code', code);
await B.page.click('#btn-code-login');
await B.page.waitForFunction(() => !!window._nsec || (document.getElementById('login-code-err') || {}).textContent,
  { timeout: 40000 }).catch(() => {});
ok('recovered the same identity on a fresh profile', await B.page.evaluate(() => _nsec) === nsec,
   await B.page.evaluate(() => (document.getElementById('login-code-err') || {}).textContent || ''));
ok('no uncaught errors in the shipped build', A.errs.length === 0 && B.errs.length === 0,
   A.errs[0] || B.errs[0] || '');

console.log('\n' + (fails.length ? `FAILED: ${fails.length} — ${fails.join(' | ')}` : 'ALL CHECKS PASSED'));
await browser.close(); site.close(); relay.close();
process.exit(fails.length ? 1 : 0);
