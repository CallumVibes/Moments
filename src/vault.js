/* ════════════════════════════════════════════
   IDENTITY VAULT — "never lose your key"

   The problem: an nsec is the whole account, and most people will not save a
   63-character secret. Saying it louder does not work.

   What is NOT possible, and shapes everything below: a pure "log in with
   Google" cannot be non-custodial. If the only thing the user supplies is an
   OAuth token, then whoever validates that token and holds the blob can open
   it. The user must hold *something*. So a provider login can locate an
   account; it can never be the key. What follows gives the user the smallest
   "something" that still works.

   The design is multi-enrollment. One identity payload, encrypted
   independently once per recovery factor:

     factor secret --KDF--> locSk    (secp256k1, LOCATES that enrollment)
                       \--> wrapKey  (AES-256-GCM, OPENS it)

   Each enrollment is a complete, self-contained copy published as a NIP-78
   replaceable event (kind 30078, d=moments:vault:v1) signed by its own locSk.
   Any single factor recovers the account on its own.

   Why independent copies rather than one blob behind a shared master key:
   there is no single blob whose loss takes the account with it, and adding a
   factor is one write that cannot corrupt the others. The cost is that
   changing the stored nsec means rewriting every enrollment, which is rare.

   Privacy properties this buys, and the reason for the odd shape:
   - Each enrollment has a DIFFERENT pubkey, so relays cannot tell that two
     enrollments belong to one person, and cannot link either to the npub it
     restores. The user's identity key never signs a vault event.
   - Relays hold ciphertext under an opaque pubkey. There is no account, no
     email, and nothing to enumerate: finding a vault requires already knowing
     the factor that derives its locator.

   Factors, and their honest weaknesses:
   - passkey (PRF): zero friction, and iCloud Keychain / Google Password
     Manager already sync it. But NO vendor documents that PRF output survives
     a sync to a second device, and it has been reported to differ within one
     ecosystem (iPhone -> Mac). Treated here as a convenience unlock, never as
     the only factor.
   - recovery code: 128 bits, so its locator salt can be fixed. This is the
     factor that makes the passkey safe to offer.
   - passphrase: salted with the user's handle, NOT a fixed string, so one
     precomputation cannot cover every user. Still the weakest link, because a
     guess can be tested; see vaultPhraseStrength.
════════════════════════════════════════════ */
const VAULT_KIND=30078;              // NIP-78 app-specific replaceable event
const VAULT_D='moments:vault:v1';    // same d-tag for every enrollment; the pubkey differs
const VAULT_PRF_SALT='moments:vault:prf:v1';
// PBKDF2 cost for passphrase enrollment. A passphrase is the one factor whose
// guesses can be tested, so this is set as high as a mid-range phone will
// tolerate for a once-in-a-while unlock rather than as low as feels snappy.
const VAULT_PBKDF2_ITERS=600000;

/* OPRF servers that stretch a PIN. TWO independent operators is the security
   requirement, not a nicety: one operator alone could grind every PIN offline,
   because it could derive each candidate's locator itself and fetch the blob
   from a public relay. See src/oprf.js.

   These must be run by different parties. Two endpoints on one provider's
   infrastructure are one operator wearing two hats, and a PIN is then only as
   strong as that provider's goodwill. */
const VAULT_OPRF_SERVERS=[];   // e.g. ['https://oprf-a.example','https://oprf-b.example']
function vaultPinAvailable(){ return VAULT_OPRF_SERVERS.length>=2; }

function _vaultRand(n){ const b=new Uint8Array(n); crypto.getRandomValues(b); return b; }

/* ── Factor-independent key material ──
   Both outputs come from one HKDF root under different salts, so a relay that
   somehow learned a locator key still learns nothing about the wrapping key. */
async function vaultKeysFromRoot(rootBytes, tag){
  const base=await crypto.subtle.importKey('raw', rootBytes, 'HKDF', false, ['deriveKey','deriveBits']);
  const wrapKey=await crypto.subtle.deriveKey(
    {name:'HKDF',hash:'SHA-256',salt:strToBytes('moments-vault-wrap:'+tag),info:strToBytes('vault-wrap-key')},
    base, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
  // 32 HKDF bytes are a valid secp256k1 scalar with overwhelming probability;
  // re-derive under a fresh info string in the vanishingly unlikely case they
  // are not, rather than failing a signup or — worse — a recovery.
  let sk=null, pub=null;
  for(let i=0;i<4 && !sk;i++){
    const bits=await crypto.subtle.deriveBits(
      {name:'HKDF',hash:'SHA-256',salt:strToBytes('moments-vault-sk:'+tag),info:strToBytes('vault-signing-key'+(i?':'+i:''))},
      base, 256);
    const cand=new Uint8Array(bits);
    try{ pub=bytesToHex(getPubKey(cand)); sk=cand; }catch(_){ sk=null; }
  }
  if(!sk) throw new Error('vault-derive-failed');
  return { locSk:sk, locPub:pub, wrapKey };
}

async function vaultPbkdf2(secret, salt, iters){
  const base=await crypto.subtle.importKey('raw', strToBytes(secret), 'PBKDF2', false, ['deriveBits']);
  const bits=await crypto.subtle.deriveBits(
    {name:'PBKDF2', hash:'SHA-256', salt:strToBytes(salt), iterations:iters}, base, 256);
  return new Uint8Array(bits);
}

/* ── Recovery code ──
   Crockford-style base32 with no vowels, so a code cannot spell anything, and
   with every symbol that vaultNormalizeCode treats as a typo (I, L, O, U) left
   out — otherwise generation could emit a character that normalization rewrites.
   26 symbols from an alphabet of 28 is ~125 bits. */
const VAULT_CODE_ALPHABET='23456789BCDFGHJKMNPQRSTVWXYZ';
function vaultGenRecoveryCode(){
  const out=[];
  // Rejection-sample so every symbol is equally likely — a plain modulo over
  // a 29-symbol alphabet would quietly bias the first few symbols.
  while(out.length<26){
    for(const b of _vaultRand(32)){
      if(b < 256-(256%VAULT_CODE_ALPHABET.length)){ out.push(VAULT_CODE_ALPHABET[b%VAULT_CODE_ALPHABET.length]); if(out.length===26) break; }
    }
  }
  return out.join('').replace(/(.{6})(?=.)/g,'$1-');   // XXXXXX-XXXXXX-…
}
function vaultNormalizeCode(raw){
  const up=String(raw||'').toUpperCase().replace(/[^0-9A-Z]/g,'')
    .replace(/O/g,'0').replace(/I/g,'1').replace(/L/g,'1').replace(/U/g,'V');
  return up;
}
function vaultNormalizeHandle(raw){
  return String(raw||'').trim().toLowerCase().replace(/\s+/g,' ');
}

async function vaultKeysFromPrf(prfBytes){ return vaultKeysFromRoot(prfBytes, 'passkey'); }
async function vaultKeysFromCode(code){
  const norm=vaultNormalizeCode(code);
  if(norm.length<20) throw new Error('code-too-short');
  // The code already carries ~130 bits, so a fixed salt is fine and a slow KDF
  // would buy nothing; HKDF over the code is enough.
  return vaultKeysFromRoot(await sha256(strToBytes('moments:code:v1:'+norm)), 'code');
}
async function vaultKeysFromPhrase(handle, phrase){
  const h=vaultNormalizeHandle(handle);
  if(!h) throw new Error('handle-required');
  // Salting with the handle is what stops ONE precomputation covering every
  // user of the app. It is public, not secret — it only has to be unique-ish.
  const root=await vaultPbkdf2(String(phrase), 'moments:phrase:v1:'+h, VAULT_PBKDF2_ITERS);
  return vaultKeysFromRoot(root, 'phrase');
}

/* ── PIN factor ──
   The rate-limit tag is the ONLY thing an OPRF server learns about who is
   asking: an opaque hash of the handle, with a domain separator so it cannot
   be correlated with anything else derived from the same handle. The server
   needs something to count attempts against, and this is the least it can be
   given while still allowing a lockout. */
async function vaultPinTag(handle){
  const h=vaultNormalizeHandle(handle);
  if(!h) throw new Error('handle-required');
  return bytesToHex(await sha256(strToBytes('moments:oprf:rl:v1:'+h)));
}

async function vaultKeysFromPin(handle, pin){
  if(!vaultPinAvailable()) throw new Error('pin-unavailable');
  const h=vaultNormalizeHandle(handle);
  const norm=String(pin||'').replace(/\D/g,'');
  if(norm.length<6) throw new Error('pin-too-short');
  // The handle goes into the hashed input as well as the tag, so the same PIN
  // chosen by two people maps to two different curve points and therefore two
  // unrelated OPRF outputs.
  const input=await sha256(strToBytes('moments:pin:v1:'+h+':'+norm));
  const root=await oprfRoot(VAULT_OPRF_SERVERS, await vaultPinTag(h), input);
  return vaultKeysFromRoot(root, 'pin');
}

/* A PIN's safety comes from the servers refusing guesses, not from its own
   entropy — but the handful of PINs that everyone picks would still fall to a
   few attempts inside any sane rate limit, so block those outright. */
function vaultPinStrength(pin){
  const p=String(pin||'').replace(/\D/g,'');
  if(p.length<6) return { ok:false, why:'Use at least 6 digits.' };
  if(/^(\d)\1+$/.test(p)) return { ok:false, why:'That is the same digit repeated.' };
  const asc='01234567890', desc='09876543210';
  if(asc.includes(p)||desc.includes(p)) return { ok:false, why:'That is a run of consecutive digits.' };
  if(['123456','654321','111111','000000','123123','121212','112233','696969','159753'].includes(p))
    return { ok:false, why:'That is one of the most commonly chosen PINs.' };
  // A repeated short block (e.g. 454545, 123123) is barely better than the block itself.
  if(/^(\d{2})\1{2}$/.test(p)||/^(\d{3})\1$/.test(p)) return { ok:false, why:'That is a short pattern repeated.' };
  return { ok:true, why:'' };
}

/* A passphrase is the only factor an attacker can guess at, so refuse the ones
   that make the whole design pointless. Deliberately not a strength meter:
   it is a floor, and it blocks rather than warns. */
function vaultPhraseStrength(phrase){
  const p=String(phrase||'');
  const words=p.trim().split(/\s+/).filter(Boolean).length;
  if(p.length<12) return { ok:false, why:'Use at least 12 characters — ideally four or more words.' };
  if(words<3 && p.length<20) return { ok:false, why:'Use four or more words, or at least 20 characters.' };
  if(/^(.)\1+$/.test(p.replace(/\s/g,''))) return { ok:false, why:'That is a single repeated character.' };
  if(/^(password|passphrase|moments|letmein|qwerty|iloveyou)/i.test(p.trim())) return { ok:false, why:'That starts with a very commonly guessed phrase.' };
  return { ok:true, why:'' };
}

/* ── Relay I/O ── */
// Give the relay pool a moment before a read or write. Without this a vault
// write silently lands in Relay's offline queue and the user is told they have
// a backup they do not yet have.
function vaultWaitForRelay(ms){
  return new Promise(resolve=>{
    try{ Relay.connect(); }catch(_){}
    if(Relay.isConnected()){ resolve(true); return; }
    const started=Date.now();
    const t=setInterval(()=>{
      if(Relay.isConnected()){ clearInterval(t); resolve(true); }
      else if(Date.now()-started>ms){ clearInterval(t); resolve(false); }
    }, 150);
  });
}

function vaultPayload(nsec, origin){
  // origin rides along because provenance cannot be recovered from an nsec, and
  // NIP-62 vanish must never be offered for a key the user brought with them.
  return JSON.stringify({ v:2, nsec:nsec, origin:origin==='moments'?'moments':'imported' });
}

// Write one enrollment. Returns ok only once a relay has actually taken it:
// queued-but-unsent must not be reported as a durable backup.
async function vaultWriteEnrollment(nsec, origin, ek){
  const iv=_vaultRand(12);
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv}, ek.wrapKey, strToBytes(vaultPayload(nsec,origin))));
  const ev=await makeNostrEvent(VAULT_KIND, [['d',VAULT_D]], _b64(concatBytes(iv, ct)), ek.locSk);
  const online=await vaultWaitForRelay(6000);
  const sent=Relay.publish(ev);
  return { ok:!!(online&&sent), event:ev };
}

// Reads are hostile input: signature-check every candidate before decrypting,
// so a lying relay can at worst waste time, never substitute a blob.
function vaultFetch(pubHex, timeoutMs){
  const limit=typeof timeoutMs==='number'?timeoutMs:9000;
  return new Promise(resolve=>{
    const subId='vault-'+Math.random().toString(36).slice(2,10);
    let best=null, grace=null, settled=false;
    const finish=()=>{
      if(settled) return; settled=true;
      if(grace) clearTimeout(grace);
      clearTimeout(hard);
      try{ Relay.unsubscribe(subId); }catch(_){}
      resolve(best);
    };
    const hard=setTimeout(finish, limit);
    Relay.subscribe(subId, [{authors:[pubHex], kinds:[VAULT_KIND], '#d':[VAULT_D], limit:4}],
      ev=>{
        if(!ev || ev.kind!==VAULT_KIND || ev.pubkey!==pubHex) return;
        if(!best || (ev.created_at||0)>(best.created_at||0)) best=ev;
        // Don't block on the slowest relay once there's a plausible answer, but
        // do wait briefly in case a faster relay served a stale copy.
        if(!grace) grace=setTimeout(finish, 1500);
      }, null);
  });
}

async function vaultReadEnrollment(ek){
  const ev=await vaultFetch(ek.locPub);
  if(!ev) return null;
  if(!(await verifyEvent(ev))) return null;
  let packed;
  try{ packed=_unb64(ev.content); }catch(_){ return null; }
  if(packed.length<13) return null;
  let pt;
  try{ pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:packed.slice(0,12)}, ek.wrapKey, packed.slice(12)); }
  catch(_){ return null; }                      // wrong key, or a blob that isn't ours
  let obj;
  try{ obj=JSON.parse(new TextDecoder().decode(new Uint8Array(pt))); }catch(_){ return null; }
  if(!obj || typeof obj.nsec!=='string' || !nsecToNpub(obj.nsec)) return null;
  return obj;
}

// Read an enrollment straight back and confirm it yields the same nsec. This
// is not paranoia about our own AES: it catches a device whose PRF does not
// reproduce what we just encrypted under, and a relay that accepted the event
// and dropped it. Without it the app would promise a backup it cannot open.
async function vaultVerifyEnrollment(nsec, ek){
  const got=await vaultReadEnrollment(ek);
  return !!(got && got.nsec===nsec);
}

// Write and verify together — the only way callers should create an enrollment.
async function vaultEnroll(nsec, origin, ek){
  const res=await vaultWriteEnrollment(nsec, origin, ek);
  if(!res.ok) throw new Error('vault-publish-failed');
  if(!(await vaultVerifyEnrollment(nsec, ek))) throw new Error('vault-verify-failed');
  return res;
}

/* ── Capability detection ── */
function vaultSupported(){
  try{
    if(!(window.PublicKeyCredential && navigator.credentials
         && typeof navigator.credentials.create==='function'
         && window.isSecureContext)) return false;
    const h=location.hostname;
    if(!h) return false;                       // file:// — rp.id would be empty
    // An rp.id must be a registrable domain, never a bare IP literal. A
    // self-hosted copy reached at https://192.168.1.5 would otherwise show the
    // button and then fail with SecurityError at the worst possible moment.
    if(/^\[?[0-9a-f:]+\]?$/i.test(h) && h!=='localhost') return false;   // IPv6
    if(/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return false;                  // IPv4
    return true;
  }catch(_){ return false; }
}

/* ── Passkey ceremonies ──
   PRF output is only reliably delivered on an assertion, not on creation:
   creation-time eval is inconsistent across platform authenticators. So every
   path does create-then-assert rather than trusting create's extension
   results. It costs one extra prompt at signup and proves the credential can
   actually be read back before anything relies on it. */
async function vaultCreatePasskey(label){
  const name=(label&&label.trim())||'Moment’s';
  const cred=await navigator.credentials.create({
    publicKey:{
      rp:{ name:'Moment’s', id:location.hostname },
      user:{ id:_vaultRand(16), name:name, displayName:name },
      challenge:_vaultRand(32),
      pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
      authenticatorSelection:{ residentKey:'required', requireResidentKey:true, userVerification:'required' },
      extensions:{ prf:{} },
      timeout:120000,
    }
  });
  if(!cred) throw new Error('passkey-cancelled');
  return cred;
}

// Discoverable credentials mean no username to type on a new device: omit
// credId at login and the authenticator offers whatever it holds for this site.
async function vaultPrfSecret(credId){
  const pk={
    challenge:_vaultRand(32),
    rpId:location.hostname,
    userVerification:'required',
    extensions:{ prf:{ eval:{ first:strToBytes(VAULT_PRF_SALT) } } },
    timeout:120000,
  };
  if(credId) pk.allowCredentials=[{type:'public-key',id:credId}];
  const assertion=await navigator.credentials.get({publicKey:pk});
  if(!assertion) throw new Error('passkey-cancelled');
  let out=null;
  try{ out=assertion.getClientExtensionResults().prf.results.first; }catch(_){ out=null; }
  if(!out) throw new Error('prf-unsupported');
  const bytes=new Uint8Array(out);
  if(bytes.length<32) throw new Error('prf-unsupported');
  return bytes.slice(0,32);
}

/* ── Messaging ── */
function vaultMsg(id, text, bad){
  const el=document.getElementById(id);
  if(!el) return;
  el.textContent=text||'';
  el.style.display=text?'block':'none';
  el.style.color=bad?'var(--red,#f87171)':'var(--muted)';
}
function vaultErrText(err){
  const m=(err&&err.message)||'';
  if(m==='prf-unsupported') return "This device's passkeys can't store a backup key. Use a recovery code instead.";
  if(m==='passkey-cancelled' || (err&&(err.name==='NotAllowedError'||err.name==='AbortError'))) return 'Passkey cancelled. Nothing was changed.';
  if(err&&err.name==='InvalidStateError') return 'A Moments passkey already exists on this device — try "Sign in" instead.';
  if(err&&err.name==='NotSupportedError') return "This browser can't create the right kind of passkey. Use a recovery code instead.";
  if(err&&err.name==='SecurityError') return 'Passkeys need a proper domain name (not an IP address) over HTTPS.';
  if(m==='vault-publish-failed') return "Couldn't reach the relays to save your backup. Check your connection and try again.";
  if(m==='vault-verify-failed') return "Your backup saved but couldn't be read back, so it isn't trustworthy. Try a recovery code instead.";
  if(m==='code-too-short') return 'That recovery code looks incomplete.';
  if(m==='handle-required') return 'Enter the handle you chose when you set this up.';
  if(m==='pin-unavailable') return 'PIN sign-in is not configured on this copy of Moments.';
  if(m==='pin-too-short') return 'Enter at least 6 digits.';
  if(m==='oprf-rate-limited') return 'Too many PIN attempts for that handle. Wait a while and try again — this is the limit that keeps a short PIN safe.';
  if(m==='oprf-unreachable'||m==='oprf-timeout') return "Couldn't reach the PIN servers. Check your connection, or use a recovery code.";
  if(m==='oprf-server-error'||m==='oprf-bad-response') return 'A PIN server answered incorrectly. Try again, or use a recovery code.';
  if(m==='oprf-no-servers') return 'PIN sign-in needs two independent servers configured.';
  if(m==='oprf-unavailable'||m==='oprf-h2c-failed') return "This browser can't do the PIN calculation. Use a recovery code instead.";
  return 'Something went wrong. '+(m||'Please try again.');
}

/* ── Signup: passkey + recovery code ──
   Both factors are enrolled before the account is adopted. The passkey is the
   one-tap path; the recovery code is what makes offering it honest, because
   cross-device PRF stability is not something any vendor guarantees. */
let _vaultCreated=false;
let _vaultRecoveryCode='';
let _vaultCodeSaved=false;

async function signupPasskey(){
  const btn=document.getElementById('btn-passkey');
  const setLabel=t=>{ if(btn) btn.textContent=t; };
  if(btn) btn.disabled=true;
  vaultMsg('passkey-err','');
  try{
    const keys=nostrGenerate();
    setLabel('Waiting for your passkey…');
    const cred=await vaultCreatePasskey('Moment’s');
    const prf=await vaultPrfSecret(cred.rawId);

    setLabel('Saving your backup…');
    await vaultEnroll(keys.nsec, 'moments', await vaultKeysFromPrf(prf));

    // Second factor, same identity, independent locator. If this fails the
    // passkey enrollment still exists, so the account is recoverable — but say
    // so rather than pretending the setup finished.
    const code=vaultGenRecoveryCode();
    let codeOk=true;
    try{ await vaultEnroll(keys.nsec, 'moments', await vaultKeysFromCode(code)); }
    catch(_){ codeOk=false; }

    // Only now adopt the identity: a half-made account with no backup is
    // exactly the failure this feature exists to prevent.
    _keyGeneratedHere=true;
    _nsec=keys.nsec; _npub=keys.npub;
    const dec=bech32Decode(_nsec); _sk=dec?dec.bytes:null;
    _vaultCreated=true;
    _vaultRecoveryCode=codeOk?code:'';
    _vaultCodeSaved=false;
    const nsecEl=document.getElementById('show-nsec');
    if(nsecEl){ nsecEl.textContent=_nsec; nsecEl.style.filter='blur(5px)'; }
    if(codeOk) showRecoveryCodeStep(); else toNameStep();
  }catch(err){
    vaultMsg('passkey-err', vaultErrText(err), true);
  }finally{
    if(btn){ btn.disabled=false; setLabel('⚡ Create with Face ID / Fingerprint'); }
  }
}

function showRecoveryCodeStep(){
  const el=document.getElementById('recovery-code');
  if(el) el.textContent=_vaultRecoveryCode;
  setStep(5);
}
function copyRecoveryCode(btn){
  copyToClipboard(_vaultRecoveryCode).then(ok=>{
    if(ok){ _vaultCodeSaved=true; flashBtn(btn,'Copied!'); }
    else { selectElementText(document.getElementById('recovery-code')); flashBtn(btn,'Press Ctrl+C'); }
  });
}
function downloadRecoveryCode(){
  const content=[
    "MOMENT'S — RECOVERY CODE",'',
    'Keep this private. Anyone with this code can take over your account.','',
    _vaultRecoveryCode,'',
    'Enter it on the login screen to get back in on any device.',
    'Created: '+new Date().toISOString().split('T')[0],
  ].join('\n');
  try{
    const url=URL.createObjectURL(new Blob([content],{type:'text/plain;charset=utf-8'}));
    const a=document.createElement('a');
    a.href=url; a.download='moments-recovery-code.txt'; a.rel='noopener'; a.style.display='none';
    document.body.appendChild(a); a.click();
    _vaultCodeSaved=true;
    setTimeout(()=>{ document.body.removeChild(a); URL.revokeObjectURL(url); },1500);
  }catch(_){ /* the code is on screen regardless */ }
}

/* ── Login ──
   Three ways in, all landing in the same place. */
async function loginPasskey(){
  const btn=document.getElementById('btn-passkey-login');
  const setLabel=t=>{ if(btn) btn.textContent=t; };
  if(btn) btn.disabled=true;
  vaultMsg('passkey-login-err','');
  try{
    setLabel('Waiting for your passkey…');
    const prf=await vaultPrfSecret(null);
    setLabel('Finding your backup…');
    await vaultWaitForRelay(6000);
    const obj=await vaultReadEnrollment(await vaultKeysFromPrf(prf));
    if(!obj){
      vaultMsg('passkey-login-err', "That passkey works, but no backup turned up for it. If you have a recovery code or your moment key, use those below.", true);
      return;
    }
    vaultAdopt(obj);
  }catch(err){
    vaultMsg('passkey-login-err', vaultErrText(err), true);
  }finally{
    if(btn){ btn.disabled=false; setLabel('⚡ Sign in with Face ID / Fingerprint'); }
  }
}

async function loginRecoveryCode(){
  const inp=document.getElementById('login-code');
  const btn=document.getElementById('btn-code-login');
  if(btn) btn.disabled=true;
  vaultMsg('login-code-err','');
  try{
    await vaultWaitForRelay(6000);
    const obj=await vaultReadEnrollment(await vaultKeysFromCode(inp?inp.value:''));
    if(!obj){ vaultMsg('login-code-err','No account found for that recovery code. Check it and try again.', true); return; }
    if(inp) inp.value='';
    vaultAdopt(obj);
  }catch(err){
    vaultMsg('login-code-err', vaultErrText(err), true);
  }finally{ if(btn) btn.disabled=false; }
}

async function loginPin(){
  const h=document.getElementById('login-pin-handle'), pin=document.getElementById('login-pin');
  const btn=document.getElementById('btn-pin-login');
  if(btn){ btn.disabled=true; btn.textContent='Checking…'; }
  vaultMsg('login-pin-err','');
  try{
    await vaultWaitForRelay(6000);
    const obj=await vaultReadEnrollment(await vaultKeysFromPin(h?h.value:'', pin?pin.value:''));
    if(!obj){ vaultMsg('login-pin-err','No account found for that handle and PIN.', true); return; }
    if(pin) pin.value='';
    vaultAdopt(obj);
  }catch(err){
    vaultMsg('login-pin-err', vaultErrText(err), true);
  }finally{ if(btn){ btn.disabled=false; btn.textContent='Unlock \u2192'; } }
}

async function loginPhrase(){
  const h=document.getElementById('login-handle'), p=document.getElementById('login-phrase');
  const btn=document.getElementById('btn-phrase-login');
  if(btn){ btn.disabled=true; btn.textContent='Unlocking…'; }
  vaultMsg('login-phrase-err','');
  try{
    await vaultWaitForRelay(6000);
    // PBKDF2 at this cost blocks the main thread for a moment on a phone; let
    // the button's new label paint before starting.
    await new Promise(r=>setTimeout(r,30));
    const obj=await vaultReadEnrollment(await vaultKeysFromPhrase(h?h.value:'', p?p.value:''));
    if(!obj){ vaultMsg('login-phrase-err','No account found for that handle and passphrase.', true); return; }
    if(p) p.value='';
    vaultAdopt(obj);
  }catch(err){
    vaultMsg('login-phrase-err', vaultErrText(err), true);
  }finally{ if(btn){ btn.disabled=false; btn.textContent='Unlock →'; } }
}

function vaultAdopt(obj){
  const dec=bech32Decode(obj.nsec);
  _npub=nsecToNpub(obj.nsec); _nsec=obj.nsec; _sk=dec?dec.bytes:null;
  _keyGeneratedHere=(obj.origin==='moments');   // missing/unknown => imported
  persistSession(obj.nsec);
  showLoginSuccess();
}

/* ── Adding a factor later, from an unlocked session ── */
async function addPhraseFactor(handle, phrase){
  const s=vaultPhraseStrength(phrase);
  if(!s.ok) throw new Error(s.why);
  await vaultEnroll(_nsec, _keyGeneratedHere?'moments':'imported', await vaultKeysFromPhrase(handle, phrase));
}
async function addPinFactor(handle, pin){
  const s=vaultPinStrength(pin);
  if(!s.ok) throw new Error(s.why);
  if(!vaultNormalizeHandle(handle)) throw new Error('handle-required');
  await vaultEnroll(_nsec, _keyGeneratedHere?'moments':'imported', await vaultKeysFromPin(handle, pin));
}
async function addCodeFactor(){
  const code=vaultGenRecoveryCode();
  await vaultEnroll(_nsec, _keyGeneratedHere?'moments':'imported', await vaultKeysFromCode(code));
  return code;
}

/* ── Login method chooser ──
   Only one method is on screen at a time. Showing all of them at once made the
   login modal a wall of five forms with three competing primary buttons. */
const LOGIN_METHODS=['code','pin','phrase','nsec'];
function pickLogin(method){
  if(!LOGIN_METHODS.includes(method)) return;
  const pk=document.getElementById('btn-passkey-login');
  if(pk) pk.style.display='none';
  vaultMsg('passkey-login-err','');
  const ch=document.getElementById('login-chooser'); if(ch) ch.style.display='none';
  LOGIN_METHODS.forEach(m=>{
    const el=document.getElementById('lm-'+m);
    if(el) el.style.display = m===method ? '' : 'none';
  });
  // Focus the first input so a chosen method is immediately usable, but never
  // on touch, where it springs the keyboard over the form the user just opened.
  try{
    if(!matchMedia('(hover: none)').matches){
      const inp=document.querySelector('#lm-'+method+' input:not([type=file])');
      if(inp) setTimeout(()=>inp.focus(),60);
    }
  }catch(_){}
}
function backToChooser(){
  LOGIN_METHODS.forEach(m=>{
    const el=document.getElementById('lm-'+m); if(el) el.style.display='none';
  });
  const ch=document.getElementById('login-chooser'); if(ch) ch.style.display='';
  const pk=document.getElementById('btn-passkey-login');
  if(pk && vaultSupported()) pk.style.display='';
  ['login-code-err','login-pin-err','login-phrase-err','passkey-login-err'].forEach(id=>vaultMsg(id,''));
}

/* Reveal the passkey paths only where they can actually work; everywhere else
   the recovery-code and moment-key paths are left exactly as they are. */
function vaultInitUi(){
  if(vaultPinAvailable()){
    const el=document.getElementById('pick-pin'); if(el) el.style.display='';
  }
  if(!vaultSupported()) return;
  ['btn-passkey','passkey-or','btn-passkey-login','login-chooser-or'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.style.display='';
  });
  // With a one-tap path available, generating a key to copy down by hand is the
  // fallback, not the headline.
  const gen=document.getElementById('btn-gen');
  if(gen){ gen.className='btn-ghost'; gen.textContent='Generate a key I save myself'; }
}
