#!/usr/bin/env node
/* Check a live deployment before trusting it, and print the config to paste.
 *
 *   node scripts/doctor.mjs https://oprf-a.example https://oprf-b.example
 *
 * Everything the app needs from the servers is verified against the running
 * endpoints: reachability, that they are distinct deployments rather than one
 * service behind two names, that each refuses an unproven social request, and
 * that they are per-account rather than acting as a global oracle. The last
 * two are the properties the whole guarantee rests on, so they are checked
 * rather than assumed.
 */
import { secp256k1 } from '../server/vendor-secp256k1.mjs';
import { createHash } from 'node:crypto';

const urls = process.argv.slice(2).filter(a => !a.startsWith('--'));
const googleId = (process.argv.find(a => a.startsWith('--google=')) || '').slice(9);
const msId = (process.argv.find(a => a.startsWith('--microsoft=')) || '').slice(12);
// Only relaxes the https requirement, and only for loopback, so the tool is
// usable against servers you are standing up locally.
const allowInsecure = process.argv.includes('--insecure');

if (urls.length < 2) {
  console.error('usage: node scripts/doctor.mjs <oprf-url-a> <oprf-url-b> [--google=<client-id>] [--microsoft=<client-id>]');
  console.error('\nTwo servers are required: one operator alone can brute-force every PIN.');
  process.exit(2);
}

const P = secp256k1.ProjectivePoint;
const probe = P.BASE.multiply(777n).toHex(true);
const tag = n => createHash('sha256').update('moments:doctor:' + n + ':' + Date.now()).digest('hex');
const fails = [], warns = [];
const ok = (c, msg, detail) => { console.log((c ? '  ok    ' : '  FAIL  ') + msg + (detail ? '  — ' + detail : '')); if (!c) fails.push(msg); };
const warn = (c, msg, detail) => { if (!c) { console.log('  warn  ' + msg + (detail ? '  — ' + detail : '')); warns.push(msg); } else console.log('  ok    ' + msg); };

const post = (base, body) => fetch(base.replace(/\/+$/, '') + '/evaluate', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
}).catch(e => ({ ok: false, status: 0, _err: String(e.message), json: async () => ({}) }));

// Cross-server comparison must use the SAME tag on every server: keys are
// per-(master, tag), so varying the tag makes two servers sharing one master
// look different. (It did, until this was fixed.)
const sharedTag = tag('shared');
const outputs = [];
for (const [i, raw] of urls.entries()) {
  const base = raw.replace(/\/+$/, '');
  console.log(`\n${base}`);
  if (allowInsecure && /^http:\/\/(127\.0\.0\.1|localhost)/i.test(base)) {
    console.log('  skip  https check (--insecure, loopback only)');
  } else {
    ok(/^https:\/\//i.test(base), 'uses https', /^https:/i.test(base) ? '' : 'the app refuses non-https endpoints');
  }

  let health = null;
  try { const r = await fetch(base + '/health'); health = r.ok ? await r.json() : null; } catch (e) { health = null; }
  ok(!!health && health.ok === true, 'reachable and healthy');
  if (!health) { console.log('  (skipping remaining checks for this server)'); continue; }

  const r1 = await post(base, { v: 1, tag: sharedTag, blinded: probe });
  ok(r1.status === 200, 'evaluates a well-formed request', r1.status ? 'HTTP ' + r1.status : r1._err);
  if (r1.status !== 200) continue;
  const b1 = await r1.json();
  outputs.push(b1.evaluated);

  // Per-account keys: the same point under a different tag must differ. A
  // server that returns the same value is applying one global scalar, which
  // makes it an oracle anyone with an account can use against anyone else.
  const b2 = await (await post(base, { v: 1, tag: tag('b' + i), blinded: probe })).json();
  ok(b1.evaluated !== b2.evaluated, 'keys are per-account, not one global scalar',
     b1.evaluated === b2.evaluated ? 'THIS SERVER IS AN ORACLE — do not deploy it' : '');

  // Social requests must be refused without a proof.
  const r3 = await post(base, { v: 1, tag: tag('c' + i), blinded: probe, social: true });
  ok(r3.status === 401, 'refuses an unproven social request', 'HTTP ' + r3.status);

  const r4 = await post(base, { v: 1, tag: 'not-a-tag', blinded: probe });
  ok(r4.status === 400, 'rejects malformed input');

  const cors = await fetch(base + '/evaluate', { method: 'OPTIONS' }).catch(() => null);
  warn(!!cors && !!cors.headers.get('access-control-allow-origin'), 'CORS preflight answered',
       'browsers will be blocked without it');
  warn(cors && cors.headers.get('access-control-allow-origin') !== '*', 'CORS origin is pinned',
       'currently "*" — set OPRF_ORIGIN to your app origin');
}

console.log('\nacross servers');
ok(new Set(urls.map(u => u.replace(/\/+$/, ''))).size === urls.length, 'the URLs are distinct');
if (outputs.length >= 2) {
  ok(new Set(outputs).size === outputs.length, 'servers hold DIFFERENT keys',
     new Set(outputs).size === 1 ? 'identical output: these share a key, so one operator holds both halves' : '');
}
try {
  const hosts = urls.map(u => new URL(u).host.split('.').slice(-2).join('.'));
  warn(new Set(hosts).size === hosts.length, 'servers are on different domains',
       'same domain suggests one operator — the guarantee needs two');
} catch (_) {}

if (googleId && msId) {
  console.log('\nproviders');
  ok(googleId !== msId, 'the two client ids differ');
  warn(/\.apps\.googleusercontent\.com$/.test(googleId), 'google client id looks like a Google one');
}

console.log('\n' + '-'.repeat(60));
if (fails.length) {
  console.log(`${fails.length} check(s) FAILED — do not ship this configuration.`);
} else {
  console.log('All checks passed. Paste this into index.html:\n');
  console.log(`  <meta name="moments-config" content='${JSON.stringify({
    oprfServers: urls.map(u => u.replace(/\/+$/, '')),
    providers: { google: googleId || '', microsoft: msId || '' },
    allowSingleProvider: false,
  })}'/>`);
  if (!googleId || !msId) console.log('\n  (pass --google= and --microsoft= to fill the client ids in)');
  if (warns.length) console.log(`\n${warns.length} warning(s) above are worth fixing before launch.`);
}
process.exit(fails.length ? 1 : 0);
