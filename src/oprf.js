/* ════════════════════════════════════════════
   OPRF — what makes a 6-digit PIN safe

   A PIN has about 20 bits of entropy. Stretching it locally, however many
   PBKDF2 rounds you use, does not help: anyone holding the ciphertext just
   grinds all million of them. A PIN is only safe if guessing requires talking
   to someone who can refuse.

   So the PIN is stretched by an Oblivious PRF. The client maps the PIN to a
   curve point, blinds it, and asks a server to apply its secret key:

     client:  P = hash_to_curve(pin)        B = r·P        -- r random, fresh
     server:  E = k·B                                      -- k never leaves
     client:  N = r⁻¹·E = k·P                              -- the stretched PIN

   The server sees only B, a uniformly random point. It learns nothing about
   the PIN, cannot link two requests, and cannot compute k·P for a PIN it was
   not asked about. The client learns nothing about k.

   WHY TWO SERVERS, NOT ONE
   One server is not enough, and this is the whole reason for the shape below.
   A single operator knows k, so for each candidate PIN it can compute k·P
   itself, derive that enrollment's locator, and fetch the blob from a public
   relay — brute-forcing the PIN offline with no rate limit to stop it. Running
   the OPRF twice under independent keys fixes this:

     root = KDF(k_A·P ‖ k_B·P)

   Neither operator alone can compute the root, so neither alone can grind.
   The security of a PIN rests on those two operators NOT COLLUDING. Pick
   operators (and jurisdictions) accordingly — two services on one provider's
   infrastructure are one operator wearing two hats.

   WHAT THIS DOES NOT DO
   - It is not a verifiable OPRF. A malicious server can return a wrong point;
     the result is that unlocking fails, not that a key leaks. Adding a DLEQ
     proof would turn that failure into a detectable one.
   - If either server loses its key, every PIN enrollment dies. A PIN is
     therefore never a user's only recovery factor.
════════════════════════════════════════════ */
const OPRF_DOMAIN='moments:oprf:v1';

function _oprfCurve(){
  const C=MomentsCrypto.secp256k1;
  if(!C || !C.ProjectivePoint) throw new Error('oprf-unavailable');
  return C;
}

// Modular inverse via Fermat: n is prime, so a^(n-2) mod n. BigInt modpow is
// not constant-time, but the only secret here is the blind r, which is random
// and used once, so a timing observation on it reveals nothing reusable.
function _oprfModPow(b,e,m){ let r=1n; b%=m; while(e>0n){ if(e&1n) r=r*b%m; b=b*b%m; e>>=1n; } return r; }
function _oprfInvert(a,m){ return _oprfModPow(((a%m)+m)%m, m-2n, m); }
function _oprfBytesToBig(b){ let v=0n; for(const x of b) v=(v<<8n)|BigInt(x); return v; }

/* Hash to curve by try-and-increment: hash to a candidate x, ask the audited
   library to decompress it, and step the counter when x is not on the curve
   (about half the time). Deliberately built on the library's own point
   decompression rather than a hand-rolled SSWU map.

   Not constant-time: the number of attempts depends on the hashed PIN, so a
   local attacker measuring it learns roughly one bit about H(pin). That is a
   far smaller leak than the PIN's own entropy and is not worth a hand-written
   constant-time field implementation here. */
async function oprfHashToCurve(domain, input){
  const C=_oprfCurve();
  for(let ctr=0; ctr<256; ctr++){
    const x=await sha256(concatBytes(strToBytes(domain+':h2c:'), new Uint8Array([ctr]), input));
    try{ return C.ProjectivePoint.fromHex('02'+bytesToHex(x)); }catch(_){ /* not on curve */ }
  }
  throw new Error('oprf-h2c-failed');
}

// A fresh blind per request. Rejects 0 so the blinded point can never be the
// identity, which would hand the server the unblinded input.
function oprfRandomBlind(){
  const n=_oprfCurve().CURVE.n;
  for(;;){
    const b=new Uint8Array(32); crypto.getRandomValues(b);
    const r=_oprfBytesToBig(b)%n;
    if(r>1n) return r;
  }
}

/* One OPRF round against one server. Returns the unblinded point's compressed
   bytes. The caller never sends anything derived from the PIN in the clear;
   `tag` is an opaque per-account value used only for rate limiting. */
async function oprfEvaluate(url, tag, point, timeoutMs){
  const C=_oprfCurve(), n=C.CURVE.n;
  const r=oprfRandomBlind();
  const blinded=point.multiply(r);

  const ctl=new AbortController();
  const timer=setTimeout(()=>ctl.abort(), typeof timeoutMs==='number'?timeoutMs:12000);
  let res;
  try{
    res=await fetch(url.replace(/\/+$/,'')+'/evaluate', {
      method:'POST',
      headers:{'content-type':'application/json'},
      body:JSON.stringify({ v:1, tag:tag, blinded:blinded.toHex(true) }),
      signal:ctl.signal,
      // No cookies, no credentials: the server must not be able to build a
      // profile across requests beyond the rate-limit tag it is given.
      credentials:'omit',
      cache:'no-store',
      referrerPolicy:'no-referrer',
    });
  }catch(e){
    throw new Error(e&&e.name==='AbortError' ? 'oprf-timeout' : 'oprf-unreachable');
  }finally{ clearTimeout(timer); }

  if(res.status===429) throw new Error('oprf-rate-limited');
  if(!res.ok) throw new Error('oprf-server-error');
  let body;
  try{ body=await res.json(); }catch(_){ throw new Error('oprf-bad-response'); }
  if(!body || typeof body.evaluated!=='string') throw new Error('oprf-bad-response');

  let evaluated;
  try{ evaluated=C.ProjectivePoint.fromHex(body.evaluated); }catch(_){ throw new Error('oprf-bad-response'); }
  // Reject a server that hands back the identity or an off-curve point: both
  // would collapse the output to something it fully controls.
  try{ evaluated.assertValidity(); }catch(_){ throw new Error('oprf-bad-response'); }
  if(evaluated.equals(C.ProjectivePoint.ZERO)) throw new Error('oprf-bad-response');

  const unblinded=evaluated.multiply(_oprfInvert(r, n));
  try{ unblinded.assertValidity(); }catch(_){ throw new Error('oprf-bad-response'); }
  return unblinded.toRawBytes(true);
}

/* Run the OPRF against every configured server and fold the results into one
   root secret. Order is fixed by the server list so the root is reproducible,
   and every server's output is required — a partial result must never silently
   produce a weaker key. */
async function oprfRoot(servers, tag, pinInput){
  if(!Array.isArray(servers) || servers.length<1) throw new Error('oprf-no-servers');
  const point=await oprfHashToCurve(OPRF_DOMAIN, pinInput);
  const parts=[];
  for(const url of servers) parts.push(await oprfEvaluate(url, tag, point));
  return await sha256(concatBytes(strToBytes(OPRF_DOMAIN+':root:'), ...parts));
}
