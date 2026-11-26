/* Builds a test copy of the app that talks to the local relay instead of the
 * public ones, and serves it over http://localhost (WebAuthn needs a real
 * hostname — a bare IP is rejected as an rp.id — and localhost counts as a
 * secure context). The ONLY change from the shipped file is the relay list.
 */
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import http from 'node:http';
import { extname, join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const OUT = join(root, 'test/.tmp');

export async function buildTestCopy(relayPort, oprfPorts = []) {
  let s = await readFile(join(root, 'index.html'), 'utf8');
  const relays = s.match(/const DEFAULT_RELAYS=\[[^\]]*\];/);
  if (!relays) throw new Error('could not find DEFAULT_RELAYS to redirect');
  s = s.replace(relays[0], `const DEFAULT_RELAYS=['ws://localhost:${relayPort}'];`);
  const oprfOrigins = oprfPorts.map(p => `http://localhost:${p}`);
  s = s.replace('connect-src https: wss:', `connect-src https: wss: ws://localhost:${relayPort} ${oprfOrigins.join(' ')}`);
  if (oprfOrigins.length) {
    const decl = s.match(/const VAULT_OPRF_SERVERS=\[[^\]]*\];/);
    if (!decl) throw new Error('could not find VAULT_OPRF_SERVERS to point at the test servers');
    s = s.replace(decl[0], `const VAULT_OPRF_SERVERS=${JSON.stringify(oprfOrigins)};`);
  }
  // Re-pin the CSP for the edited bundle, exactly as the real build does.
  const scripts = [...s.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  const hashes = scripts.map(x => `'sha256-${createHash('sha256').update(x, 'utf8').digest('base64')}'`);
  s = s.replace(/script-src ([^;]*);/, `script-src ${hashes.join(' ')};`);
  await mkdir(OUT, { recursive: true });
  await writeFile(join(OUT, 'index.html'), s);
}

export function serve(port) {
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.json': 'application/json' };
  const srv = http.createServer(async (req, res) => {
    try {
      const body = await readFile(join(OUT, (req.url || '/').split('?')[0].replace(/^\/+/, '') || 'index.html'));
      res.writeHead(200, { 'content-type': types[extname(req.url || '')] || 'application/octet-stream' });
      res.end(body);
    } catch { res.writeHead(404); res.end('not found'); }
  });
  return new Promise(r => srv.listen(port, '127.0.0.1', () => r(srv)));
}
