
<html lang="pt-br"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>SISTEMA OPERACIONAL CENTRAL - V2.0</title>
<style>
:root{--g:#00ff41;--bg:#050505;--pn:rgba(0,20,0,.85);--gl:0 0 10px rgba(0,255,65,.4);box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--g);font-family:'Courier New',monospace;margin:0;overflow-x:hidden}
#mx{position:fixed;inset:0;width:100vw;height:100vh;pointer-events:none;z-index:0}
.c{position:relative;z-index:10;max-width:1600px;margin:0 auto;padding:12px}
.ov{border:1px solid var(--g);background:rgba(0,10,0,.95);padding:12px;margin-bottom:12px;box-shadow:var(--gl)}
.ov h2{margin:0;font-size:1em;letter-spacing:2px}
.dash{display:grid;grid-template-columns:280px 1fr 320px;gap:12px}
@media(max-width:1100px){.dash{grid-template-columns:1fr}}
.p{border:1px solid var(--g);padding:12px;background:var(--pn);box-shadow:var(--gl);display:flex;flex-direction:column;gap:8px;min-width:0}
.h{text-align:center;border-bottom:2px solid var(--g);padding-bottom:6px;font-weight:bold;letter-spacing:1px;font-size:.9em}
input,button,textarea{background:#000;border:1px solid var(--g);color:var(--g);width:100%;padding:8px;font-family:inherit;font-size:.85em}
button{cursor:pointer}
button:hover{background:var(--g);color:#000;box-shadow:0 0 10px var(--g)}
#log{font-size:.78em;white-space:pre-wrap;word-break:break-all;background:#000;border:1px solid var(--g);padding:8px;height:260px;overflow-y:auto}
.ok{text-shadow:0 0 5px var(--g)}.bad{color:#ff4040}
.row{display:flex;gap:6px}.row>*{flex:1}
canvas.r{background:#000;border:1px solid var(--g);width:100%}
label{font-size:.8em}
.bar{height:8px;background:#000;border:1px solid var(--g)}.bar i{display:block;height:100%;background:var(--g);width:0}
</style></head><body>
<canvas id="mx"></canvas>
<div class="c">
<div class="ov"><h2>// SISTEMA OPERACIONAL CENTRAL V2.0 — MÓDULOS REAIS</h2>
<small>SHA-256 · AES-GCM · PBKDF2 · Integridade de arquivos · Terminal · Auditoria · Workers concorrentes (tudo local, no navegador)</small></div>
<div class="dash">
<div class="p">
<div class="h">STATUS</div>
<div>REDE: <span id="net" class="ok">...</span></div>
<div>LINK: <span id="lnk">-</span></div>
<div>UPTIME: <span id="up">0s</span></div>
<div>CARGA (lag do event loop): <span id="cpu">0%</span></div><div class="bar"><i id="cpub"></i></div>
<div class="h">HARDWARE</div>
<button onclick="scanSys()">Escanear sistema</button>
<div class="h">CONCORRÊNCIA</div>
<button onclick="workers()">Executar workers paralelos</button>
<div class="h">AUDITORIA</div>
<button onclick="audit()">Auditar ambiente</button>
</div>
<div class="p">
<div class="h">TERMINAL (digite help)</div>
<div id="log"></div>
<input id="cmd" placeholder="> comando" autocomplete="off" autocapitalize="off">
<div class="h">RADAR</div>
<canvas id="map" class="r" width="550" height="160"></canvas>
</div>
<div class="p">
<div class="h">CRIPTOGRAFIA</div>
<label>TEXTO:</label><textarea id="txt" rows="3"></textarea>
<label>SENHA / CHAVE MESTRA:</label><input type="password" id="pass" autocomplete="off">
<div class="row"><button onclick="ui('hash')">SHA-256</button><button onclick="ui('enc')">Cifrar</button><button onclick="ui('dec')">Decifrar</button></div>
<textarea id="out" rows="3" readonly></textarea>
<div class="row"><button onclick="ui('gen')">Gerar senha</button><button onclick="ui('ent')">Entropia</button></div>
<div class="h">INTEGRIDADE DE ARQUIVO</div>
<input type="file" id="file">
<button onclick="integrity()">Registrar / Verificar SHA-256</button>
<div class="row"><button onclick="exportLog()">Exportar log</button><button onclick="clearAll()">Limpar dados</button></div>
</div></div></div>
<script>
const $=id=>document.getElementById(id),T0=Date.now(),enc=new TextEncoder(),dec=new TextDecoder();
const st={get(k,d){try{const v=localStorage.getItem(k);return v?JSON.parse(v):d}catch(e){return d}},set(k,v){try{localStorage.setItem(k,JSON.stringify(v))}catch(e){}},del(k){try{localStorage.removeItem(k)}catch(e){}}};
// ---------- LOG ----------
let lines=st.get('sos_log',[]);
const ts=()=>new Date().toLocaleTimeString('pt-BR');
function render(){const l=$('log');l.textContent=lines.join('\n');l.scrollTop=l.scrollHeight}
function log(t){lines.push(`[${ts()}] ${t}`);if(lines.length>300)lines=lines.slice(-300);st.set('sos_log',lines);render()}
if(!lines.length)lines=['> [INIT] Sistema iniciado.'];render();
// ---------- CRYPTO ----------
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const b64=b=>{let s='';new Uint8Array(b).forEach(x=>s+=String.fromCharCode(x));return btoa(s)};
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const sha=async d=>hex(await crypto.subtle.digest('SHA-256',typeof d==='string'?enc.encode(d):d));
async function key(pw,salt){const m=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveKey']);
return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},m,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
async function encrypt(t,pw){const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},await key(pw,salt),enc.encode(t));
const o=new Uint8Array(28+ct.byteLength);o.set(salt);o.set(iv,16);o.set(new Uint8Array(ct),28);return b64(o)}
async function decrypt(s,pw){const d=unb64(s.trim()),salt=d.slice(0,16),iv=d.slice(16,28);
return dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv},await key(pw,salt),d.slice(28)))}
function genpass(n=20){const set='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*?-_';
const lim=256-256%set.length;let o='';while(o.length<n){for(const x of crypto.getRandomValues(new Uint8Array(n*2))){if(x<lim&&o.length<n)o+=set[x%set.length]}}return o}
function entropy(s){let p=0;if(/[a-z]/.test(s))p+=26;if(/[A-Z]/.test(s))p+=26;if(/\d/.test(s))p+=10;if(/[^\w]/.test(s)||/_/.test(s))p+=33;
const b=s.length*Math.log2(p||1);return{bits:b.toFixed(1),level:b<40?'FRACA':b<60?'MÉDIA':b<80?'BOA':'FORTE'}}
// ---------- UI CRYPTO ----------
async function ui(a){const t=$('txt').value,pw=$('pass').value,o=$('out');
try{
if(a==='hash'){o.value=await sha(t);log('[SHA-256] hash gerado ('+t.length+' chars).')}
else if(a==='enc'){if(!pw)throw Error('Informe a senha.');o.value=await encrypt(t,pw);log('[AES-GCM] texto cifrado (PBKDF2 250k).')}
else if(a==='dec'){if(!pw)throw Error('Informe a senha.');o.value=await decrypt(t,pw);log('[AES-GCM] decifrado com sucesso.')}
else if(a==='gen'){o.value=genpass(24);log('[GEN] senha de 24 caracteres gerada.')}
else if(a==='ent'){const e=entropy(t||pw);o.value=`${e.bits} bits — ${e.level}`;log('[ENTROPIA] '+o.value)}
}catch(e){o.value='';log('[ERRO] '+(e.message||'falha (senha errada ou dado inválido)'))}}
// ---------- INTEGRIDADE ----------
async function integrity(){const f=$('file').files[0];if(!f)return log('[INTEGRIDADE] Selecione um arquivo.');
const h=await sha(await f.arrayBuffer()),db=st.get('sos_hashes',{}),k=f.name+':'+f.size;
if(!db[k]){db[k]=h;st.set('sos_hashes',db);log(`[INTEGRIDADE] Baseline salvo: ${f.name}\n  ${h}`)}
else if(db[k]===h)log(`[INTEGRIDADE] OK — ${f.name} inalterado.`);
else log(`[INTEGRIDADE] ALERTA — ${f.name} DIFERE do baseline!\n  atual: ${h}\n  base:  ${db[k]}`)}
// ---------- SISTEMA ----------
function sysinfo(){const n=navigator,c=n.connection||{};
return[`Núcleos: ${n.hardwareConcurrency||'?'}`,`Memória (GB aprox.): ${n.deviceMemory||'?'}`,`Plataforma: ${n.platform||'?'}`,`Idioma: ${n.language}`,
`Tela: ${screen.width}x${screen.height} @${devicePixelRatio}x`,`Rede: ${c.effectiveType||'?'} ↓${c.downlink||'?'}Mbps rtt ${c.rtt||'?'}ms`,
`Bateria/online: ${n.onLine?'online':'offline'}`,`Fuso: ${Intl.DateTimeFormat().resolvedOptions().timeZone}`].join('\n  ')}
function scanSys(){log('[HARDWARE] Informações do dispositivo:\n  '+sysinfo());addNodes(2)}
async function workers(){log('[WORKERS] 4 tarefas concorrentes (hash de 8 MB cada)...');
const job=async i=>{const t=performance.now(),b=new Uint8Array(8*1024*1024);for(let o=0;o<b.length;o+=65536)crypto.getRandomValues(b.subarray(o,o+65536));
const h=await sha(b);return`#${i+1} ${(performance.now()-t).toFixed(0)}ms ${h.slice(0,12)}…`};
const t=performance.now(),r=await Promise.all([0,1,2,3].map(job));log('[WORKERS] '+r.join(' | ')+`\n  total ${(performance.now()-t).toFixed(0)}ms`)}
async function audit(){const r=[];r.push(['Contexto seguro (HTTPS)',isSecureContext]);r.push(['WebCrypto',!!(crypto&&crypto.subtle)]);
let s=false;try{localStorage.setItem('_t','1');localStorage.removeItem('_t');s=true}catch(e){}r.push(['Armazenamento local',s]);
r.push(['Cookies habilitados',navigator.cookieEnabled]);r.push(['Do Not Track',navigator.doNotTrack==='1']);r.push(['Online',navigator.onLine]);
log('[AUDITORIA]\n'+r.map(([k,v])=>`  ${v?'[ OK ]':'[FALHA]'} ${k}`).join('\n'))}
function exportLog(){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([lines.join('\n')],{type:'text/plain'}));a.download='log_sistema.txt';a.click();log('[LOG] exportado.')}
function clearAll(){if(!confirm('Apagar log e baselines salvos?'))return;st.del('sos_log');st.del('sos_hashes');lines=['> [INIT] Dados limpos.'];render()}
// ---------- TERMINAL ----------
const hist=[];let hi=0;
const cmds={
help:()=>'Comandos: help clear sysinfo hash <txt> enc <senha> <txt> dec <senha> <b64> genpass [n] entropy <txt> b64 <txt> unb64 <b64> hexa <txt> rand [n] uptime audit nodes history export',
clear:()=>{lines=[];render();return null},
sysinfo:()=>sysinfo(),
hash:async a=>await sha(a.join(' ')),
enc:async a=>await encrypt(a.slice(1).join(' '),a[0]),
dec:async a=>await decrypt(a[1],a[0]),
genpass:a=>genpass(Math.min(128,+a[0]||20)),
entropy:a=>{const e=entropy(a.join(' '));return`${e.bits} bits (${e.level})`},
b64:a=>btoa(unescape(encodeURIComponent(a.join(' ')))),
unb64:a=>decodeURIComponent(escape(atob(a[0]))),
hexa:a=>hex(enc.encode(a.join(' '))),
rand:a=>{const n=Math.min(64,+a[0]||16);return hex(crypto.getRandomValues(new Uint8Array(n)))},
uptime:()=>fmt((Date.now()-T0)/1000),
audit:()=>{audit();return null},nodes:()=>{addNodes(3);return `${blips.length} nós no radar`},
history:()=>hist.join('\n'),export:()=>{exportLog();return null}};
$('cmd').addEventListener('keydown',async e=>{
if(e.key==='ArrowUp'&&hist.length){hi=Math.max(0,hi-1);e.target.value=hist[hi]||'';return}
if(e.key==='ArrowDown'){hi=Math.min(hist.length,hi+1);e.target.value=hist[hi]||'';return}
if(e.key!=='Enter')return;const v=e.target.value.trim();e.target.value='';if(!v)return;hist.push(v);hi=hist.length;
const [c,...a]=v.split(/\s+/);log('$ '+(c==='enc'||c==='dec'?c+' ***':v));
const f=cmds[c.toLowerCase()];if(!f)return log('Comando desconhecido. Digite help.');
try{const r=await f(a);if(r!=null)log(r)}catch(x){log('[ERRO] '+(x.message||'entrada inválida'))}});
// ---------- STATUS ----------
const fmt=s=>{s=Math.floor(s);return`${Math.floor(s/3600)}h ${Math.floor(s%3600/60)}m ${s%60}s`};
function net(){const o=navigator.onLine,c=navigator.connection;$('net').textContent=o?'ONLINE':'OFFLINE';$('net').className=o?'ok':'bad';
$('lnk').textContent=c?`${c.effectiveType} ${c.downlink}Mbps`:'n/d'}
addEventListener('online',()=>{net();log('[REDE] conexão restabelecida.')});addEventListener('offline',()=>{net();log('[REDE] conexão perdida.')});net();
setInterval(()=>$('up').textContent=fmt((Date.now()-T0)/1000),1000);
let last=performance.now();
setInterval(()=>{const n=performance.now(),lag=Math.max(0,n-last-500);last=n;const p=Math.min(100,lag/5*100/10).toFixed(1);
$('cpu').textContent=p+'%';$('cpub').style.width=p+'%'},500);
// ---------- MATRIX ----------
const mx=$('mx'),x=mx.getContext('2d'),chs="0123456789ABCDEF@#$%&*<>/[]{}=",fs=14;let dr=[];
function rs(){mx.width=innerWidth;mx.height=innerHeight;dr=Array(Math.floor(mx.width/fs)).fill(1)}rs();addEventListener('resize',rs);
setInterval(()=>{x.fillStyle='rgba(0,0,0,.05)';x.fillRect(0,0,mx.width,mx.height);x.fillStyle='#00ff41';x.font=fs+'px monospace';
dr.forEach((d,i)=>{x.fillText(chs[Math.random()*chs.length|0],i*fs,d*fs);if(d*fs>mx.height&&Math.random()>.975)dr[i]=0;dr[i]++})},50);
// ---------- RADAR ----------
const mc=$('map'),m=mc.getContext('2d');let ang=0;const blips=[];
function addNodes(n){for(let i=0;i<n;i++)blips.push({a:Math.random()*Math.PI*2,r:.2+Math.random()*.75,l:0})}addNodes(4);
setInterval(()=>{m.fillStyle='rgba(0,10,0,.3)';m.fillRect(0,0,mc.width,mc.height);
const cx=mc.width/2,cy=mc.height/2,R=Math.min(cx,cy)-8;m.strokeStyle='rgba(0,255,65,.3)';
[1,.6,.3].forEach(k=>{m.beginPath();m.arc(cx,cy,R*k,0,7);m.stroke()});
m.strokeStyle='#00ff41';m.beginPath();m.moveTo(cx,cy);m.lineTo(cx+Math.cos(ang)*R,cy+Math.sin(ang)*R);m.stroke();
blips.forEach(b=>{const d=Math.abs(((ang-b.a)%(Math.PI*2)+Math.PI*3)%(Math.PI*2)-Math.PI);if(d<.1)b.l=1;b.l=Math.max(0,b.l-.015);
m.fillStyle=`rgba(0,255,65,${.2+b.l*.8})`;m.fillRect(cx+Math.cos(b.a)*R*b.r-2,cy+Math.sin(b.a)*R*b.r-2,5,5)});
ang+=.05},50);
log('[SYSTEM READY] Digite help no terminal.');
</script></body></html>
