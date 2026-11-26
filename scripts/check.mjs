#!/usr/bin/env node
/* Verify index.html is exactly what src/ builds to, and that its CSP is sound.
 * Runs in CI so a hand-edited index.html, or a stale one, fails loudly rather
 * than shipping a blank page.
 */
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { writeFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const run = promisify(execFile);
const fail = [];

const before = await readFile(join(root, 'index.html'), 'utf8');
await run('node', [join(root, 'scripts/build.mjs')]);
const after = await readFile(join(root, 'index.html'), 'utf8');
if (before !== after) fail.push('index.html is not up to date with src/ — run `npm run build` and commit the result');

// Every inline script must be syntactically valid and covered by the CSP.
const csp = after.match(/script-src ([^;]*);/)[1];
const scripts = [...after.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const dir = await mkdtemp(join(tmpdir(), 'moments-check-'));
for (const [i, s] of scripts.entries()) {
  const h = `'sha256-${createHash('sha256').update(s, 'utf8').digest('base64')}'`;
  if (!csp.includes(h)) fail.push(`inline script #${i + 1} is not pinned in the CSP`);
  const f = join(dir, `s${i}.js`);
  await writeFile(f, s);
  try { await run('node', ['--check', f]); }
  catch (e) { fail.push(`inline script #${i + 1} is not valid JS: ${String(e.stderr || e).split('\n').slice(0, 3).join(' ')}`); }
}
if (/'unsafe-inline'|'unsafe-eval'/.test(csp)) fail.push("script-src must not use 'unsafe-inline' or 'unsafe-eval'");

console.log(fail.length ? 'FAILED:\n  - ' + fail.join('\n  - ') : `check OK (${scripts.length} script(s), CSP pinned, index.html current)`);
process.exit(fail.length ? 1 : 0);
