/* ════════════════════════════════════════════
   SOCIAL SIGN-IN — "tied to her Google login"

   The goal: someone who will never save an nsec, never write down a recovery
   code, and should not have to. She taps "Continue with Google" and she is in,
   on any device, forever.

   The obvious design does not work, and it is worth saying why precisely,
   because it is not about where the blob is stored or how it is encrypted.

   Encrypt the nsec, park the blob anywhere, decrypt it on Google login — fine.
   But what is the decryption key? She types nothing, so it has to come out of
   the login itself. The only durable thing a Google login yields is the `sub`
   claim, and `sub` is an IDENTIFIER, NOT A SECRET: stable, account-level, and
   the same value handed to every app she authorizes. Deriving the key from it
   would mean anyone who learns her Google user ID can open her vault. That is
   worse than Google holding the key.

   So the key cannot live in the token. It lives with the OPRF servers, which
   apply their secret only on proof of a fresh login (see oprf.js). Google then
   holds a blob it genuinely cannot open, and no amount of knowing `sub` helps.

   WHAT THIS STILL DOES NOT DO, STATED PLAINLY
   Google issues the proof. It can mint an ID token for any of its own users,
   present that to the OPRF servers, and obtain the key. No arrangement of
   storage or encryption changes this: any lock whose only key is "can prove you
   are her to Google" is a lock Google can open.

   That is not a reason to refuse the feature — it is a reason to label it
   honestly. What the OPRF does buy is the difference between Google *having*
   the key and Google having to *go and take* it: a deliberate, targeted act
   that mints a token for a named user and leaves a record on two independent
   third-party servers. Passive access becomes an active attack.

   And for anyone who wants that gap closed, vaultKeysFromSocial takes an
   optional PIN, which Google does not know and cannot mint, with the OPRF
   servers rate-limiting guesses.
════════════════════════════════════════════ */

/* Provider config. Empty by default: a redirect URI must be pre-registered per
   origin, so a self-hosted copy cannot use this app's client IDs. Fill these in
   with your own and the buttons appear; leave them and they stay hidden rather
   than offering something that will fail on redirect. */
const SOCIAL_PROVIDERS={
  google:{
    label:'Google',
    clientId:'',                                    // e.g. '1234-abc.apps.googleusercontent.com'
    authUrl:'https://accounts.google.com/o/oauth2/v2/auth',
    scope:'openid',
    issuer:'https://accounts.google.com',
  },
};
function socialAvailable(p){ return !!(SOCIAL_PROVIDERS[p] && SOCIAL_PROVIDERS[p].clientId); }
function socialAnyAvailable(){ return Object.keys(SOCIAL_PROVIDERS).some(socialAvailable); }

function _socialRandHex(n){
  const b=new Uint8Array(n); crypto.getRandomValues(b);
  return bytesToHex(b);
}

/* Read a JWT's payload WITHOUT verifying it. Safe here, and deliberately so:
   nothing on the client trusts this token. It is forwarded to the OPRF servers,
   which do verify it. If a user feeds us a bogus token they derive a different
   key and open nothing — they cannot reach anyone else's vault. */
function socialPeekClaims(jwt){
  try{
    const part=String(jwt).split('.')[1];
    const b64=part.replace(/-/g,'+').replace(/_/g,'/');
    const pad=b64+'='.repeat((4-b64.length%4)%4);
    return JSON.parse(new TextDecoder().decode(_unb64(pad)));
  }catch(_){ return null; }
}

/* The OAuth leg, as a popup.
   A popup rather than a full-page redirect because a redirect would throw away
   in-progress state, and rather than an iframe because the CSP sets
   frame-src 'none' (and Google refuses to be framed regardless). */
function socialSignIn(provider){
  return new Promise((resolve,reject)=>{
    const cfg=SOCIAL_PROVIDERS[provider];
    if(!cfg || !cfg.clientId){ reject(new Error('social-unconfigured')); return; }

    const nonce=_socialRandHex(16), state=_socialRandHex(16);
    const redirect=location.origin+location.pathname;
    const url=cfg.authUrl
      +'?client_id='+encodeURIComponent(cfg.clientId)
      +'&redirect_uri='+encodeURIComponent(redirect)
      +'&response_type=id_token'
      +'&scope='+encodeURIComponent(cfg.scope)
      +'&nonce='+nonce
      +'&state='+state
      +'&prompt=select_account'
      +'&response_mode=fragment';

    const win=window.open(url,'moments-signin','width=480,height=640,noopener=no,noreferrer=no');
    if(!win){ reject(new Error('social-popup-blocked')); return; }

    let done=false;
    const cleanup=()=>{
      window.removeEventListener('message',onMsg);
      clearInterval(poll);
    };
    const onMsg=ev=>{
      if(ev.origin!==location.origin) return;             // only our own callback page
      const d=ev.data;
      if(!d || d.type!=='moments-oauth') return;
      if(d.state!==state) return;                         // CSRF / crossed-wires guard
      done=true; cleanup();
      try{ win.close(); }catch(_){}
      if(d.error || !d.id_token){ reject(new Error('social-denied')); return; }
      const claims=socialPeekClaims(d.id_token);
      if(!claims || claims.nonce!==nonce || !claims.sub || claims.iss!==cfg.issuer){
        reject(new Error('social-bad-token')); return;
      }
      resolve({ provider, sub:String(claims.sub), idToken:d.id_token });
    };
    window.addEventListener('message',onMsg);

    // A closed popup is the only signal we get when someone cancels.
    const poll=setInterval(()=>{
      if(done) return;
      let closed=false; try{ closed=win.closed; }catch(_){ closed=true; }
      if(closed){ cleanup(); reject(new Error('social-cancelled')); }
    },500);

    setTimeout(()=>{ if(!done){ cleanup(); try{ win.close(); }catch(_){} reject(new Error('social-timeout')); } },180000);
  });
}

/* Runs in the popup when Google redirects back to this same file: hand the
   fragment to the opener and close. Must run before the app boots — there is no
   app to show in a 480px popup. */
function socialMaybeHandleCallback(){
  try{
    if(!window.opener || window.opener===window) return false;
    const frag=(location.hash||'').replace(/^#/,'');
    if(!frag || !/(^|&)(id_token|error)=/.test(frag)) return false;
    const q=new URLSearchParams(frag);
    window.opener.postMessage({
      type:'moments-oauth',
      state:q.get('state')||'',
      id_token:q.get('id_token')||'',
      error:q.get('error')||'',
    }, location.origin);
    // Clear the token out of the address bar before anything else can read it.
    try{ history.replaceState(null,'',location.pathname); }catch(_){}
    document.documentElement.innerHTML='<p style="font:16px system-ui;padding:24px">Signing you in…</p>';
    setTimeout(()=>{ try{ window.close(); }catch(_){} },200);
    return true;
  }catch(_){ return false; }
}
