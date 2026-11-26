/* Unit tests for the vault's pure logic — code generation, normalization and
 * the passphrase floor. These need no browser: vault.js only touches DOM and
 * Web Crypto inside its async functions, so loading it in a VM is enough.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const src = await readFile(new URL('../src/vault.js', import.meta.url), 'utf8');
const ctx = vm.createContext({ crypto: globalThis.crypto, window: {}, location: {}, navigator: {}, document: {} });
vm.runInContext(src + '\n;globalThis.__api={vaultGenRecoveryCode,vaultNormalizeCode,vaultNormalizeHandle,vaultPhraseStrength,VAULT_CODE_ALPHABET};', ctx);
const { vaultGenRecoveryCode, vaultNormalizeCode, vaultNormalizeHandle, vaultPhraseStrength, VAULT_CODE_ALPHABET } = ctx.__api;

test('recovery code has the advertised shape and entropy', () => {
  const c = vaultGenRecoveryCode();
  assert.match(c, /^[0-9A-Z]{6}(-[0-9A-Z]{6}){3}-[0-9A-Z]{2}$/, 'grouped in sixes: ' + c);
  const bare = c.replace(/-/g, '');
  assert.equal(bare.length, 26);
  for (const ch of bare) assert.ok(VAULT_CODE_ALPHABET.includes(ch), `symbol ${ch} is outside the alphabet`);
  // 26 symbols x log2(29) ~= 126 bits
  assert.ok(26 * Math.log2(VAULT_CODE_ALPHABET.length) > 120, 'at least 120 bits');
});

test('recovery alphabet excludes the characters people mistype', () => {
  for (const ch of 'AEIOULU01') assert.ok(!VAULT_CODE_ALPHABET.includes(ch), `${ch} should not be in the alphabet`);
});

test('recovery codes do not repeat', () => {
  const seen = new Set();
  for (let i = 0; i < 500; i++) seen.add(vaultGenRecoveryCode());
  assert.equal(seen.size, 500);
});

test('every alphabet symbol is reachable (rejection sampling is not stuck)', () => {
  const seen = new Set();
  for (let i = 0; i < 2000; i++) for (const ch of vaultGenRecoveryCode().replace(/-/g, '')) seen.add(ch);
  assert.equal(seen.size, VAULT_CODE_ALPHABET.length, 'all symbols should appear across many codes');
});

test('symbol distribution is not visibly biased', () => {
  const counts = new Map([...VAULT_CODE_ALPHABET].map(c => [c, 0]));
  let total = 0;
  for (let i = 0; i < 4000; i++) for (const ch of vaultGenRecoveryCode().replace(/-/g, '')) { counts.set(ch, counts.get(ch) + 1); total++; }
  const expected = total / VAULT_CODE_ALPHABET.length;
  for (const [ch, n] of counts) {
    assert.ok(Math.abs(n - expected) < expected * 0.25, `symbol ${ch}: ${n} vs expected ~${expected.toFixed(0)}`);
  }
});

test('code normalization folds the confusable characters', () => {
  const c = vaultGenRecoveryCode();
  assert.equal(vaultNormalizeCode(c), vaultNormalizeCode(c.toLowerCase()), 'case-insensitive');
  assert.equal(vaultNormalizeCode(c), vaultNormalizeCode(c.replace(/-/g, ' ')), 'separators ignored');
  assert.equal(vaultNormalizeCode('O0o'), '000');
  assert.equal(vaultNormalizeCode('IiLl'), '1111');
  assert.equal(vaultNormalizeCode('Uu'), 'VV');
  assert.equal(vaultNormalizeCode('  2-3 4 '), '234');
});

test('handle normalization is stable across casing and spacing', () => {
  assert.equal(vaultNormalizeHandle('  Callum  '), 'callum');
  assert.equal(vaultNormalizeHandle('Big  Red\tDog'), 'big red dog');
  assert.equal(vaultNormalizeHandle(''), '');
  assert.equal(vaultNormalizeHandle(null), '');
});

test('passphrase floor rejects what makes the design pointless', () => {
  for (const bad of ['', 'short', 'password123', 'aaaaaaaaaaaaaaaa', 'qwerty', 'moments2026', 'hunter2hunter2'])
    assert.equal(vaultPhraseStrength(bad).ok, false, `should reject: ${JSON.stringify(bad)}`);
  for (const bad of ['', 'short', 'password123'])
    assert.ok(vaultPhraseStrength(bad).why.length > 10, 'rejection should explain itself');
});

test('passphrase floor accepts a reasonable phrase', () => {
  for (const good of ['correct horse battery staple', 'four words is plenty', 'a-much-longer-single-string-here'])
    assert.equal(vaultPhraseStrength(good).ok, true, `should accept: ${JSON.stringify(good)}`);
});
