// Minimal in-memory Nostr relay (NIP-01 REQ/EVENT/EOSE + replaceable kind 30078).
// Hand-rolled RFC6455 framing because this container has no `ws` module.
import http from 'node:http';
import crypto from 'node:crypto';
const store=new Map();

function frame(str){
  const b=Buffer.from(str,'utf8'), len=b.length;
  let head;
  if(len<126){ head=Buffer.from([0x81,len]); }
  else if(len<65536){ head=Buffer.alloc(4); head[0]=0x81; head[1]=126; head.writeUInt16BE(len,2); }
  else { head=Buffer.alloc(10); head[0]=0x81; head[1]=127; head.writeBigUInt64BE(BigInt(len),2); }
  return Buffer.concat([head,b]);
}

const srv=http.createServer((_,res)=>{res.writeHead(404);res.end();});
srv.on('upgrade',(req,sock)=>{
  const key=req.headers['sec-websocket-key'];
  const accept=crypto.createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n');
  const send=s=>{ try{ sock.write(frame(s)); }catch(_){} };
  let buf=Buffer.alloc(0);
  sock.on('data',chunk=>{
    buf=Buffer.concat([buf,chunk]);
    for(;;){
      if(buf.length<2) return;
      const op=buf[0]&0x0f, masked=(buf[1]&0x80)!==0; let len=buf[1]&0x7f, off=2;
      if(len===126){ if(buf.length<4) return; len=buf.readUInt16BE(2); off=4; }
      else if(len===127){ if(buf.length<10) return; len=Number(buf.readBigUInt64BE(2)); off=10; }
      const maskLen=masked?4:0;
      if(buf.length<off+maskLen+len) return;
      const mask=masked?buf.slice(off,off+4):null;
      const payload=buf.slice(off+maskLen,off+maskLen+len);
      if(mask) for(let i=0;i<payload.length;i++) payload[i]^=mask[i&3];
      buf=buf.slice(off+maskLen+len);
      if(op===8){ try{sock.end();}catch(_){} return; }
      if(op!==1) continue;
      let m; try{ m=JSON.parse(payload.toString('utf8')); }catch(_){ continue; }
      if(m[0]==='EVENT'){
        const ev=m[1];
        const d=(ev.tags||[]).filter(t=>t[0]==='d').map(t=>t[1])[0]||'';
        const k=ev.pubkey+':'+ev.kind+':'+d;
        const prev=store.get(k);
        if(!prev||prev.created_at<=ev.created_at) store.set(k,ev);
        send(JSON.stringify(['OK',ev.id,true,'']));
        console.log('STORED kind='+ev.kind,'pub='+ev.pubkey.slice(0,12),'d='+d,'clen='+ev.content.length);
      } else if(m[0]==='REQ'){
        const id=m[1], filters=m.slice(2);
        for(const ev of store.values()){
          for(const f of filters){
            if(f.kinds&&!f.kinds.includes(ev.kind)) continue;
            if(f.authors&&!f.authors.includes(ev.pubkey)) continue;
            if(f['#d']){
              const ds=(ev.tags||[]).filter(t=>t[0]==='d').map(t=>t[1]);
              if(!f['#d'].some(x=>ds.includes(x))) continue;
            }
            send(JSON.stringify(['EVENT',id,ev])); break;
          }
        }
        send(JSON.stringify(['EOSE',id]));
      }
    }
  });
  sock.on('error',()=>{});
});
export function startRelay(port=7447){
  return new Promise(res=>srv.listen(port,'127.0.0.1',()=>res({
    port, stored:()=>[...store.values()], close:()=>srv.close() })));
}
if(import.meta.url===`file://${process.argv[1]}`) startRelay().then(r=>console.log('relay on ws://127.0.0.1:'+r.port));
