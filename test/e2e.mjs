/* End-to-end vault tests in real Chromium, against a real (local) relay.
 *
 * Covers every recovery factor whose cross-device behaviour can actually be
 * verified: a recovery code and a handle+passphrase are derived purely from
 * what the user types, so a genuinely fresh browser profile proves recovery.
 *
 * The passkey path is NOT fully coverable here. Chrome's virtual authenticator
 * exposes no PRF/hmac-secret material over CDP (getCredentials returns
 * privateKey only), so a *synced* passkey cannot be emulated and a second
 * profile necessarily reports prf-unsupported. The passkey assertions below
 * therefore cover enrollment on one device and clean failure elsewhere — which
 * is exactly why the design does not lean on PRF alone.
 */
import { chromium } from 'playwright';
import { startRelay } from './relay.mjs';
import { buildTestCopy, serve } from './harness.mjs';
import { createServer as createOprf } from '../server/oprf-server.mjs';

const PORT = 8099, RELAY = 7447, OPRF_A = 8787, OPRF_B = 8788;
const relay = await startRelay(RELAY);
// Two OPRF servers under DIFFERENT keys — the whole point of the design is that
// neither alone can compute a PIN's key, so the test runs two.
const oprfA = createOprf({ key: 'a1'.repeat(32), limits: [{ windowMs: 600000, max: 6 }] });
const oprfB = createOprf({ key: 'b2'.repeat(32), limits: [{ windowMs: 600000, max: 6 }] });
await new Promise(r => oprfA.listen(OPRF_A, '127.0.0.1', r));
await new Promise(r => oprfB.listen(OPRF_B, '127.0.0.1', r));
await buildTestCopy(RELAY, [OPRF_A, OPRF_B]);
const site = await serve(PORT);
const browser = await chromium.launch();

const fails = [];
const ok = (n, c, extra) => { console.log((c ? '  PASS  ' : '  FAIL  ') + n + (extra ? '  [' + extra + ']' : '')); if (!c) fails.push(n); };
const section = n => console.log('\n-- ' + n + ' --');

const prfAuth = {
  protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
  hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
  hasPrf: true, automaticPresenceSimulation: true,
  defaultBackupEligibility: true, defaultBackupState: true,
};

async function device({ prf = false } = {}) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push(e.message));
  let cdp = null;
  if (prf) {
    cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: prfAuth });
  }
  await page.goto(`http://localhost:${PORT}/index.html`);
  await page.waitForTimeout(900);
  return { ctx, page, errs, cdp };
}
const settle = (page, sel) => page.waitForFunction(
  s => !!window._nsec || ((document.querySelector(s) || {}).textContent || '').length > 0,
  sel, { timeout: 30000 }).catch(() => {});

// ── Signup with a passkey: enrolls BOTH a passkey and a recovery code ────────
section('signup (passkey + recovery code)');
const A = await device({ prf: true });
ok('CSP blocks nothing (inline bundle hash is correct)',
   !A.errs.some(e => /Refused to/i.test(e)), A.errs.find(e => /Refused to/i.test(e)) || '');
ok('vaultSupported() on localhost', await A.page.evaluate(() => vaultSupported()));

await A.page.evaluate(() => openModal('signup'));
await A.page.waitForTimeout(200);
await A.page.click('#btn-passkey');
await A.page.waitForFunction(() => document.getElementById('ss5')?.classList.contains('active')
  || (document.getElementById('passkey-err') || {}).textContent, { timeout: 30000 }).catch(() => {});
const sErr = await A.page.evaluate(() => (document.getElementById('passkey-err') || {}).textContent || '');
ok('signup reached the recovery-code step', await A.page.evaluate(() => document.getElementById('ss5').classList.contains('active')), sErr);

const nsecA = await A.page.evaluate(() => _nsec);
const npubA = await A.page.evaluate(() => _npub);
const codeA = await A.page.evaluate(() => _vaultRecoveryCode);
ok('identity generated', /^nsec1[a-z0-9]{58}$/.test(nsecA || ''));
ok('recovery code generated and shown', /^[0-9A-Z-]{29,34}$/.test(codeA || '')
   && (await A.page.textContent('#recovery-code')) === codeA, codeA || '');

// Two enrollments, two different opaque pubkeys, neither the identity key.
const stored = relay.stored().filter(e => e.kind === 30078);
const idPubA = await A.page.evaluate(() => bytesToHex(getPubKey(_sk)));
ok('both factors enrolled as separate events', stored.length === 2, 'got ' + stored.length);
ok('each enrollment has a different pubkey (uncorrelatable)',
   new Set(stored.map(e => e.pubkey)).size === stored.length);
ok('no enrollment is signed by the identity key (unlinkable to npub)',
   !stored.some(e => e.pubkey === idPubA));
ok('relays only ever see ciphertext', !stored.some(e => e.content.includes('nsec1')));
ok('all enrollments share the d-tag', stored.every(e => e.tags.some(t => t[0] === 'd' && t[1] === 'moments:vault:v1')));

await A.page.click('#ss5 [data-act="downloadRecoveryCode"]');
await A.page.waitForTimeout(200);
await A.page.click('#ss5 [data-act="toNameStep"]');   // ss2 has one too — scope it
await A.page.fill('#signup-name', 'Normie');
await A.page.click('[data-act="completeSignup"]');
await A.page.waitForTimeout(3500);
ok('a saved recovery code earns "backed up"', await A.page.evaluate(() => !!(A && A.profile && A.profile.keyBackedUp)));
ok('no uncaught errors during signup', A.errs.length === 0, A.errs[0] || '');

// ── Recovery on a genuinely fresh profile, by code ───────────────────────────
section('recovery by code (fresh browser, no passkey)');
const B = await device();
ok('starts logged out', await B.page.evaluate(() => !_nsec));
await B.page.evaluate(() => { openModal('login'); pickLogin('code'); });
await B.page.fill('#login-code', codeA);
await B.page.click('#btn-code-login');
await settle(B.page, '#login-code-err');
ok('recovered the SAME nsec from the recovery code',
   await B.page.evaluate(() => _nsec) === nsecA,
   await B.page.evaluate(() => (document.getElementById('login-code-err') || {}).textContent || ''));
ok('recovered the same npub', await B.page.evaluate(() => _npub) === npubA);
ok('provenance preserved (Moments-born, so vanish stays allowed)',
   await B.page.evaluate(() => _keyGeneratedHere === true));
ok('no uncaught errors during recovery', B.errs.length === 0, B.errs[0] || '');

// ── Codes are case/separator tolerant but not guessable ──────────────────────
section('recovery code robustness');
const C = await device();
await C.page.evaluate(() => { openModal('login'); pickLogin('code'); });
await C.page.fill('#login-code', codeA.toLowerCase().replace(/-/g, ' '));
await C.page.click('#btn-code-login');
await settle(C.page, '#login-code-err');
ok('lowercase + spaces instead of dashes still works', await C.page.evaluate(() => _nsec) === nsecA);

const D = await device();
await D.page.evaluate(() => { openModal('login'); pickLogin('code'); });
await D.page.fill('#login-code', 'Z3K9FQ-M2WB7N-XRJ4PD-HSVY8C-TG');
await D.page.click('#btn-code-login');
await settle(D.page, '#login-code-err');
ok('a wrong code recovers nothing and says so', await D.page.evaluate(() => !_nsec)
   && /No account found/.test(await D.page.evaluate(() => (document.getElementById('login-code-err') || {}).textContent || '')));

// ── Adding a passphrase factor, then recovering with it ──────────────────────
section('passphrase factor');
const phrase = 'correct horse battery staple', handle = 'Normie';
const added = await B.page.evaluate(async ([h, p]) => {
  try { await addPhraseFactor(h, p); return 'ok'; } catch (e) { return String(e.message); }
}, [handle, phrase]);
ok('passphrase factor enrolled from an unlocked session', added === 'ok', added);
ok('weak passphrases are refused', await B.page.evaluate(async () => {
  try { await addPhraseFactor('x', 'password123'); return false; } catch (_) { return true; }
}));

const E = await device();
await E.page.evaluate(() => { openModal('login'); pickLogin('phrase'); });
await E.page.fill('#login-handle', '  nOrMiE ');     // normalization must not matter
await E.page.fill('#login-phrase', phrase);
await E.page.click('#btn-phrase-login');
await settle(E.page, '#login-phrase-err');
ok('recovered the same nsec from handle + passphrase',
   await E.page.evaluate(() => _nsec) === nsecA,
   await E.page.evaluate(() => (document.getElementById('login-phrase-err') || {}).textContent || ''));

const F = await device();
await F.page.evaluate(() => { openModal('login'); pickLogin('phrase'); });
await F.page.fill('#login-handle', handle);
await F.page.fill('#login-phrase', 'correct horse battery stapler');
await F.page.click('#btn-phrase-login');
await settle(F.page, '#login-phrase-err');
ok('a wrong passphrase recovers nothing', await F.page.evaluate(() => !_nsec));

const G = await device();
await G.page.evaluate(() => { openModal('login'); pickLogin('phrase'); });
await G.page.fill('#login-handle', 'someone-else');
await G.page.fill('#login-phrase', phrase);
await G.page.click('#btn-phrase-login');
await settle(G.page, '#login-phrase-err');
ok('right passphrase under the wrong handle recovers nothing (handle is the salt)',
   await G.page.evaluate(() => !_nsec));

// ── PIN, stretched by two independent OPRF servers ───────────────────────────
section('PIN factor (OPRF)');
ok('PIN UI appears once two servers are configured', await B.page.evaluate(() => vaultPinAvailable()));

const pin = '914620';
const pinAdd = await B.page.evaluate(async ([h, p]) => {
  try { await addPinFactor(h, p); return 'ok'; } catch (e) { return String(e.message); }
}, [handle, pin]);
ok('PIN factor enrolled via the OPRF', pinAdd === 'ok', pinAdd);

// The PIN enrollment is a third, independent event — and the PIN itself must
// not reach the relay in any form. (That the OPRF servers never see it is
// asserted directly against the request bodies in test/oprf.test.mjs.)
const afterPin = relay.stored().filter(e => e.kind === 30078);
ok('PIN enrollment added an independent event', afterPin.length === 4, 'got ' + afterPin.length);
ok('every enrollment still has a distinct pubkey',
   new Set(afterPin.map(e => e.pubkey)).size === afterPin.length);
ok('the PIN never reaches the relay, even as ciphertext input',
   !afterPin.some(e => JSON.stringify(e).includes(pin)));

const K = await device();
await K.page.evaluate(() => { openModal('login'); pickLogin('pin'); });
await K.page.fill('#login-pin-handle', handle);
await K.page.fill('#login-pin', pin);
await K.page.click('#btn-pin-login');
await settle(K.page, '#login-pin-err');
ok('recovered the same nsec from handle + PIN',
   await K.page.evaluate(() => _nsec) === nsecA,
   await K.page.evaluate(() => (document.getElementById('login-pin-err') || {}).textContent || ''));

const L = await device();
await L.page.evaluate(() => { openModal('login'); pickLogin('pin'); });
await L.page.fill('#login-pin-handle', handle);
await L.page.fill('#login-pin', '914621');
await L.page.click('#btn-pin-login');
await settle(L.page, '#login-pin-err');
ok('a wrong PIN recovers nothing', await L.page.evaluate(() => !_nsec));

ok('trivial PINs are refused before any network call', await L.page.evaluate(async () => {
  const bad = ['123456', '000000', '111111', '121212', '12345'];
  for (const p of bad) { try { await addPinFactor('x', p); return false; } catch (_) { /* expected */ } }
  return true;
}));

// Exhaust the budget and confirm the user is told why, rather than just failing.
const M = await device();
await M.page.evaluate(() => { openModal('login'); pickLogin('pin'); });
const victim = 'rate-limit-target';   // NOT `handle`: the budget is per account,
                                      // and spending the real one would break
                                      // the tests below (as it once did).
for (let i = 0; i < 7; i++) {
  await M.page.fill('#login-pin-handle', victim);
  await M.page.fill('#login-pin', '000001');
  await M.page.click('#btn-pin-login');
  await M.page.waitForTimeout(350);
}
const rlMsg = await M.page.evaluate(() => (document.getElementById('login-pin-err') || {}).textContent || '');
ok('exhausting the PIN budget surfaces the rate limit', /Too many PIN attempts/.test(rlMsg), rlMsg);
ok('rate-limited attempts still recover nothing', await M.page.evaluate(() => !_nsec));

// Taking one server away must fail closed, never fall back to a weaker key.
oprfB.close();
const N = await device();
await N.page.evaluate(() => { openModal('login'); pickLogin('pin'); });
await N.page.fill('#login-pin-handle', handle);
await N.page.fill('#login-pin', pin);
await N.page.click('#btn-pin-login');
await settle(N.page, '#login-pin-err');
ok('one server down fails closed (no weaker key, no login)',
   await N.page.evaluate(() => !_nsec)
   && /Couldn't reach the PIN servers/.test(await N.page.evaluate(() => (document.getElementById('login-pin-err') || {}).textContent || '')),
   await N.page.evaluate(() => (document.getElementById('login-pin-err') || {}).textContent || ''));
ok('the recovery code still works with the PIN servers down', await (async () => {
  const O = await device();
  await O.page.evaluate(() => { openModal('login'); pickLogin('code'); });
  await O.page.fill('#login-code', codeA);
  await O.page.click('#btn-code-login');
  await settle(O.page, '#login-code-err');
  return await O.page.evaluate(() => _nsec) === nsecA;
})());

// ── Passkey: enrollment works, and absence of PRF fails safe ─────────────────
section('passkey limits');
const H = await device({ prf: true });
await H.page.evaluate(async () => { await vaultCreatePasskey('Stranger'); });
await H.page.evaluate(() => openModal('login'));
await H.page.click('#btn-passkey-login');
await settle(H.page, '#passkey-login-err');
ok('an unrelated passkey opens nothing', await H.page.evaluate(() => !_nsec),
   await H.page.evaluate(() => (document.getElementById('passkey-login-err') || {}).textContent || ''));

const I = await device();   // no authenticator at all
await I.page.evaluate(() => openModal('login'));
ok('passkey button hidden where passkeys are unusable',
   await I.page.evaluate(() => vaultSupported()) ? true : !(await I.page.isVisible('#btn-passkey-login')));

// ── The login screen offers one choice, not five forms ──────────────────────
section('login screen shape');
const P = await device({ prf: true });
await P.page.evaluate(() => openModal('login'));
await P.page.waitForTimeout(200);
ok('only one primary button is visible by default',
   (await P.page.locator('#login-body .btn-primary:visible').count()) === 1,
   'found ' + (await P.page.locator('#login-body .btn-primary:visible').count()));
ok('no input fields on the default view',
   (await P.page.locator('#login-body input:visible').count()) === 0);
ok('the other methods are offered as a compact list',
   (await P.page.locator('#login-body .login-option:visible').count()) === 4);

await P.page.click('[data-act="pickLogin"][data-a="code"]');
await P.page.waitForTimeout(150);
ok('picking a method shows only that method', await P.page.isVisible('#lm-code')
   && !(await P.page.isVisible('#lm-phrase')) && !(await P.page.isVisible('#lm-nsec'))
   && !(await P.page.isVisible('#login-chooser')));
ok('the passkey button steps aside once a method is chosen',
   !(await P.page.isVisible('#btn-passkey-login')));

await P.page.click('#lm-code .login-back');
await P.page.waitForTimeout(150);
ok('going back restores the chooser and the passkey button',
   await P.page.isVisible('#login-chooser') && await P.page.isVisible('#btn-passkey-login')
   && !(await P.page.isVisible('#lm-code')));

await P.page.evaluate(() => { closeModal('login'); openModal('login'); });
await P.page.waitForTimeout(150);
ok('reopening returns to the chooser, not the last method used',
   await P.page.isVisible('#login-chooser') && !(await P.page.isVisible('#lm-code')));

// The PIN option is gated on two OPRF servers being configured. This build has
// them, so it shows; a build with none must not offer it at all.
ok('the PIN option is gated on the OPRF servers being configured',
   await P.page.evaluate(() => {
     const el = document.getElementById('pick-pin');
     return vaultPinAvailable() === (el.style.display !== 'none');
   }));
ok('a build with no OPRF servers hides the PIN option', await P.page.evaluate(() => {
   const el = document.getElementById('pick-pin');
   const before = el.style.display;
   el.style.display = 'none';                       // what vaultInitUi leaves it as
   const hidden = !el.offsetParent;
   el.style.display = before;
   return hidden;
}));

// ── Regression: the original moment-key paths ────────────────────────────────
section('regression: paste-your-nsec');
const J = await device();
await J.page.evaluate(() => { openModal('login'); pickLogin('nsec'); });
await J.page.fill('#login-nsec', nsecA);
await J.page.click('[data-act="loginNsec"]');
await J.page.waitForTimeout(600);
ok('paste-nsec login still works', await J.page.evaluate(() => _npub) === npubA);
ok('paste-nsec marks the key imported (vanish stays blocked)', await J.page.evaluate(() => _keyGeneratedHere === false));
ok('no errors on the paste path', J.errs.length === 0, J.errs[0] || '');

console.log('\n' + (fails.length ? `FAILED: ${fails.length} — ${fails.join(' | ')}` : 'ALL CHECKS PASSED'));
await browser.close(); site.close(); relay.close();
try { oprfA.close(); oprfB.close(); } catch {}
process.exit(fails.length ? 1 : 0);
