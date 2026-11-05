const express=require('express'),crypto=require('crypto'),fs=require('fs'),path=require('path'),webpush=require('web-push');
const PORT=process.env.PORT||3000,FILE=process.env.DATA_FILE||path.join(__dirname,'data','data.json');
const iso=d=>d.toISOString().slice(0,10),today=()=>iso(new Date()),addD=(s,n)=>{const d=new Date(s);d.setDate(d.getDate()+n);return iso(d)};
const E=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const hash=(p,salt)=>crypto.scryptSync(String(p),salt,32).toString('hex');
const mk=p=>{const salt=crypto.randomBytes(16).toString('hex');return{salt,hash:hash(p,salt)}};
const eq=(a,b)=>{a=Buffer.from(a);b=Buffer.from(b);return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const chk=(p,o)=>eq(hash(p,o.salt),o.hash);
let D;
try{D=JSON.parse(fs.readFileSync(FILE,'utf8'))}catch(e){
 D={seq:1,inv:1,nid:1,secret:crypto.randomBytes(32).toString('hex'),vapid:webpush.generateVAPIDKeys(),
 staff:[{u:process.env.ADMIN_USER||'Admin',role:'admin',...mk(process.env.ADMIN_PASS||'850964')}],
 plans:[{id:'p1',name:'جيم',services:'صالة الحديد',price:300,days:30}],members:[],att:[],invs:[],reqs:[],notes:[],seen:{},subs:{}}}
D.usedTxn=D.usedTxn||[];D.expenses=D.expenses||[];D.partners=D.partners||[{name:'الشريك 1',pct:0},{name:'الشريك 2',pct:0},{name:'الشريك 3',pct:0}];D.gateToken=D.gateToken||crypto.randomBytes(9).toString('base64url');D.settings=D.settings||{shamCode:'',shamName:''};
const PROOFS=path.resolve(path.dirname(FILE),'proofs'),EXT={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','application/pdf':'pdf'};
let wq=Promise.resolve();
const save=()=>{wq=wq.then(async()=>{await fs.promises.mkdir(path.dirname(FILE),{recursive:true});const t=FILE+'.tmp';await fs.promises.writeFile(t,JSON.stringify(D));await fs.promises.rename(t,FILE)}).catch(console.error)};
save();
webpush.setVapidDetails(process.env.VAPID_SUBJECT||'mailto:admin@example.com',D.vapid.publicKey,D.vapid.privateKey);
const sig=p=>crypto.createHmac('sha256',D.secret).update(p).digest('base64url');
const sign=(o,h)=>{const p=Buffer.from(JSON.stringify({...o,exp:Date.now()+h*36e5})).toString('base64url');return p+'.'+sig(p)};
const verify=t=>{try{const[p,s]=t.split('.');if(!eq(s,sig(p)))return null;const o=JSON.parse(Buffer.from(p,'base64url'));return o.exp>Date.now()?o:null}catch(e){return null}};
const tries={},blocked=ip=>(tries[ip]=(tries[ip]||[]).filter(t=>Date.now()-t<9e5)).length>=10,bad=ip=>tries[ip].push(Date.now());
const pubM=({salt,hash,...x})=>x,str=(v,n=100)=>String(v??'').trim().slice(0,n),nid=()=>++D.nid;
const planOf=id=>D.plans.find(p=>p.id===id),memOf=id=>D.members.find(m=>m.id===id);
const stState=u=>({plans:D.plans,members:D.members.map(pubM),att:D.att.slice(-3000),invs:D.invs,reqs:D.reqs,notes:D.notes.slice(-100),seen:{},settings:D.settings,gateToken:u.role==='admin'?D.gateToken:'',expenses:D.expenses,partners:u.role==='admin'?D.partners:[],staff:u.role==='admin'?D.staff.map(({u,role})=>({u,role})):[]});
const mState=id=>({plans:D.plans,members:[pubM(memOf(id))],att:D.att.filter(a=>!a.out).map(()=>({out:null})),invs:[],reqs:D.reqs.filter(x=>x.m===id),notes:D.notes.filter(n=>n.to==='all'||n.to===id).slice(-50),seen:{[id]:D.seen[id]||0},settings:D.settings,mine:(o=>({inside:!!o,since:o?o.in:null}))(D.att.find(a=>a.m===id&&!a.out)),staff:[]});
async function push(ids,title,body){let n=0;for(const id of ids)for(const s of [...(D.subs[id]||[])]){try{await webpush.sendNotification(s,JSON.stringify({title,body}));n++}catch(e){if(e.statusCode===404||e.statusCode===410)D.subs[id]=D.subs[id].filter(x=>x.endpoint!==s.endpoint)}}return n}
const note=(to,title,body)=>D.notes.push({id:nid(),t:new Date().toISOString(),title,body,to});
function renewM(m,p,txn){if(m.end<=today())m.start=today();const base=m.end>today()?m.end:today();m.plan=p.id;m.end=addD(base,p.days);D.invs.push({n:D.inv++,m:m.id,plan:p.name,amt:p.price,date:today(),kind:'تجديد',...(txn?{pay:'شام كاش'}:{})})}
async function renewNotify(m,p){const b='باقة '+p.name+' تنتهي في '+m.end;note(m.id,'تم تجديد اشتراكك',b);return{pushed:await push([m.id],'تم تجديد اشتراكك',b)}}
const A={
 memberSave(d){const name=str(d.name),p=planOf(d.plan);if(!name)throw Error('الاسم مطلوب');if(!p)throw Error('اختر باقة صحيحة');
  if(d.id){const m=memOf(d.id);if(!m)throw Error('العضو غير موجود');m.name=name;m.phone=str(d.phone,30);m.plan=p.id;const pw=str(d.pw,50);if(pw)Object.assign(m,mk(pw));return{id:m.id}}
  const id='TG-'+String(D.seq++).padStart(3,'0'),pw=str(d.pw,50)||String(crypto.randomInt(100000,999999)),st=today();
  D.members.push({id,name,phone:str(d.phone,30),plan:p.id,start:st,end:addD(st,p.days),...mk(pw)});
  D.invs.push({n:D.inv++,m:id,plan:p.name,amt:p.price,date:st,kind:'اشتراك'});return{id,pw}},
 memberDel(d){D.members=D.members.filter(m=>m.id!==d.id);D.reqs=D.reqs.filter(r=>r.m!==d.id);delete D.subs[d.id]},
 planSave(d){const name=str(d.name),price=+d.price,days=Math.round(+d.days);if(!name||!(price>=0)||!(days>=1&&days<=3650))throw Error('بيانات الباقة غير صحيحة');
  const o={name,services:str(d.services,200),price,days};if(d.id){const p=planOf(d.id);if(!p)throw Error('الباقة غير موجودة');Object.assign(p,o)}else D.plans.push({id:'p'+Date.now(),...o})},
 planDel(d){D.plans=D.plans.filter(p=>p.id!==d.id)},
 gate(d){const id=str(d.code,20).toUpperCase(),m=memOf(id);if(!m)return{msg:['كود غير معروف','bad']};
  const o=D.att.find(a=>a.m===id&&!a.out),n=new Date().toISOString(),left=Math.round((new Date(m.end)-new Date(today()))/864e5),nm=E(m.name);
  if(o){o.out=n;return{msg:['خروج: '+nm,'ok']}}
  if(left<0)return{msg:['اشتراك '+nm+' منتهي — لا يمكن تسجيل الدخول','bad']};
  D.att.push({m:id,in:n,out:null});return{msg:['دخول: '+nm+(left<=7?' (ينتهي اشتراكه خلال '+left+' أيام)':''),left<=7?'warn':'ok']}},
 async renew(d){const m=memOf(d.m),p=planOf(d.plan);if(!m||!p)throw Error('بيانات غير صحيحة');renewM(m,p);return renewNotify(m,p)},
 async approve(d){const r=D.reqs.find(x=>x.id===d.id);if(!r)throw Error('الطلب غير موجود');const m=memOf(r.m),p=planOf(r.plan);D.reqs=D.reqs.filter(x=>x!==r);if(!m||!p)throw Error('بيانات الطلب لم تعد صالحة');renewM(m,p,true);if(r.hx)D.usedTxn.push(r.hx);return renewNotify(m,p)},
 async reject(d){const r=D.reqs.find(x=>x.id===d.id);if(!r)return;D.reqs=D.reqs.filter(x=>x!==r);const b='تعذّر قبول طلب التجديد، يرجى التواصل مع النادي';note(r.m,'طلب التجديد',b);return{pushed:await push([r.m],'طلب التجديد',b)}},
 async noteSend(d){const title=str(d.title,80),body=str(d.body,500),to=d.to==='all'?'all':d.to;if(!title||!body)throw Error('العنوان والنص مطلوبان');if(to!=='all'&&!memOf(to))throw Error('المشترك غير موجود');
  note(to,title,body);return{pushed:await push(to==='all'?D.members.map(m=>m.id):[to],title,body)}},
 staffAdd(d){const u=str(d.u,30),p=str(d.p,50);if(!u||p.length<4)throw Error('اسم المستخدم أو كلمة السر غير صالحة');if(D.staff.some(x=>x.u.toLowerCase()===u.toLowerCase()))throw Error('اسم المستخدم مستخدم مسبقاً');
  if(D.staff.filter(x=>x.role==='acc').length>=2)throw Error('الحد الأقصى محاسبان');D.staff.push({u,role:'acc',...mk(p)})},
 staffDel(d){D.staff=D.staff.filter(x=>!(x.u===d.u&&x.role==='acc'))},
 settingsSave(d){D.settings={shamCode:str(d.shamCode,60),shamName:str(d.shamName,60)}},
 reqRenew(d,u){const p=planOf(d.plan);if(!p)throw Error('باقة غير صحيحة');if(D.reqs.some(r=>r.m===u.id))throw Error('لديك طلب قيد المراجعة');
  const mt=/^data:(image\/(?:jpeg|png|webp)|application\/pdf);base64,([A-Za-z0-9+/=]+)$/.exec(String(d.proof||''));if(!mt)throw Error('أرفق إشعار التحويل (صورة أو PDF)');
  const buf=Buffer.from(mt[2],'base64');if(buf.length>2.5e6||buf.length<300)throw Error('حجم الملف غير مقبول (الحد 2.5 ميغابايت)');
  const hx=crypto.createHash('sha256').update(buf).digest('hex');if(D.reqs.some(r=>r.hx===hx)||D.usedTxn.includes(hx))throw Error('هذا الإشعار أُرسل سابقاً، أرفق إشعار التحويل الجديد');
  const id=nid();fs.mkdirSync(PROOFS,{recursive:true});fs.writeFileSync(path.join(PROOFS,id+'.'+EXT[mt[1]]),buf);
  D.reqs.push({id,m:u.id,plan:p.id,t:new Date().toISOString(),hx})},
 pwChange(d,u){const m=memOf(u.id);if(!m||!chk(d.old,m))throw Error('كلمة السر الحالية غير صحيحة');const p=str(d.pw,50);if(p.length<6)throw Error('كلمة السر الجديدة 6 خانات على الأقل');Object.assign(m,mk(p))},
selfGate(d,u){if(!d.token||!eq(String(d.token),D.gateToken))throw Error('رمز النادي غير صحيح، امسح الرمز المعلّق عند المدخل');
  const m=memOf(u.id),o=D.att.find(a=>a.m===u.id&&!a.out),n=new Date().toISOString(),last=[...D.att].reverse().find(a=>a.m===u.id),lt=o?new Date(o.in).getTime():(last&&last.out?new Date(last.out).getTime():0);
  if(lt&&Date.now()-lt<20000)return{msg:['تم تسجيلك قبل لحظات','warn']};
  if(o){o.out=n;return{msg:['تم تسجيل خروجك. نراك قريباً','ok']}}
  const left=Math.round((new Date(m.end)-new Date(today()))/864e5);if(left<0)throw Error('اشتراكك منتهي، جدّد اشتراكك أولاً');
  D.att.push({m:u.id,in:n,out:null});return{msg:['تم تسجيل دخولك. تمرين موفق!'+(left<=7?' (ينتهي اشتراكك خلال '+left+' أيام)':''),'ok']}},
 gateRegen(){D.gateToken=crypto.randomBytes(9).toString('base64url')},
 expenseAdd(d,u){const amount=+d.amount,note=str(d.note,300),cat=CATS.includes(d.cat)?d.cat:'أخرى',date=/^\d{4}-\d{2}-\d{2}$/.test(String(d.date||''))?d.date:today();
  if(!(amount>0&&amount<1e12))throw Error('المبلغ غير صحيح');if(!note)throw Error('اكتب ملاحظة توضح ما تم صرفه');D.expenses.push({id:nid(),date,amount,cat,note,by:u.u})},
 expenseDel(d){D.expenses=D.expenses.filter(x=>x.id!==+d.id)},
 partnersSave(d){const L=Array.isArray(d.partners)?d.partners.slice(0,3):[];if(L.length!==3)throw Error('يجب تحديد 3 شركاء');
  const P=L.map((p,i)=>({name:str(p.name,40)||'الشريك '+(i+1),pct:Math.round((+p.pct||0)*100)/100}));
  if(P.some(p=>!(p.pct>=0&&p.pct<=100)))throw Error('النسبة يجب أن تكون بين 0 و100');if(P.reduce((a,p)=>a+p.pct,0)>100.001)throw Error('مجموع النسب يتجاوز 100%');D.partners=P},
 seen(d,u){D.seen[u.id]=Math.max(D.seen[u.id]||0,+d.id||0)}};
const CATS=['أجهزة','صيانة','إكسسوارات','إيجار','رواتب','أخرى'];
const M=['reqRenew','seen','pwChange','selfGate'],ACC=['renew','approve','reject','expenseAdd'];
const app=express();app.set('trust proxy',1);app.use((q,r,n)=>q.path==='/api/act'?n():express.json({limit:'100kb'})(q,r,n));
app.use((q,r,n)=>{r.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer'});n()});
const pub=path.join(__dirname,'public');
app.get('/',(q,r)=>r.redirect('/app'));app.get('/admin',(q,r)=>r.sendFile(pub+'/admin.html'));app.get('/app',(q,r)=>r.sendFile(pub+'/member.html'));
app.use(express.static(pub,{index:false}));
const auth=(q,r,n)=>{const o=verify((q.headers.authorization||'').slice(7));if(!o)return r.status(401).json({error:'انتهت الجلسة، سجّل الدخول من جديد'});q.u=o;n()};
app.post('/api/login/staff',(q,r)=>{const ip=q.ip,{u,p}=q.body||{};if(blocked(ip))return r.status(429).json({error:'محاولات كثيرة، حاول بعد 15 دقيقة'});
 const s=D.staff.find(x=>x.u.toLowerCase()===str(u,30).toLowerCase());if(!s||!chk(p,s)){bad(ip);return r.status(401).json({error:'اسم المستخدم أو كلمة السر غير صحيحة'})}r.json({token:sign({k:'s',u:s.u,role:s.role},12)})});
app.post('/api/login/member',(q,r)=>{const ip=q.ip,{code,pw}=q.body||{};if(blocked(ip))return r.status(429).json({error:'محاولات كثيرة، حاول بعد 15 دقيقة'});
 const m=memOf(str(code,20).toUpperCase());if(!m||!chk(pw,m)){bad(ip);return r.status(401).json({error:'الكود أو كلمة السر غير صحيحة'})}r.json({token:sign({k:'m',id:m.id},720)})});
app.get('/api/state',auth,(q,r)=>q.u.k==='s'?r.json({state:stState(q.u),me:{u:q.u.u,role:q.u.role}}):r.status(403).json({error:'ممنوع'}));
app.get('/api/me',auth,(q,r)=>q.u.k==='m'&&memOf(q.u.id)?r.json({state:mState(q.u.id)}):r.status(403).json({error:'ممنوع'}));
app.get('/api/vapid',(q,r)=>r.json({key:D.vapid.publicKey}));
app.get('/api/count',auth,(q,r)=>r.json({n:D.att.filter(a=>!a.out).length}));
app.post('/api/push',auth,(q,r)=>{if(q.u.k!=='m')return r.status(403).json({error:'ممنوع'});const s=q.body;if(!s||typeof s.endpoint!=='string'||!s.keys)return r.status(400).json({error:'اشتراك غير صالح'});
 const l=(D.subs[q.u.id]||[]).filter(x=>x.endpoint!==s.endpoint);l.push({endpoint:s.endpoint,keys:s.keys});D.subs[q.u.id]=l.slice(-5);save();r.json({ok:true})});
app.get('/api/proof/:id',auth,(q,r)=>{if(q.u.k!=='s')return r.status(403).end();const id=+q.params.id;if(!Number.isInteger(id))return r.status(400).end();
 for(const e of Object.values(EXT)){const f=path.join(PROOFS,id+'.'+e);if(fs.existsSync(f))return r.sendFile(f)}r.status(404).end()});
app.post('/api/act',auth,express.json({limit:'5mb'}),async(q,r)=>{const{type,data}=q.body||{},u=q.u,fn=Object.hasOwn(A,type)?A[type]:null;
 const ok=u.k==='m'?M:u.role==='admin'?Object.keys(A).filter(x=>!M.includes(x)):ACC;
 if(!fn||!ok.includes(type))return r.status(403).json({error:'غير مسموح'});
 try{const extra=(await fn(data||{},u))||{};save();r.json({ok:true,extra,state:u.k==='m'?mState(u.id):stState(u)})}catch(e){r.status(400).json({error:e.message})}});
app.listen(PORT,()=>console.log('TIGER GYM يعمل على المنفذ '+PORT));
