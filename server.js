const express = require('express'),
      crypto = require('crypto'),
      fs = require('fs'),
      path = require('path'),
      webpush = require('web-push'),
      mongoose = require('mongoose');

const PORT = process.env.PORT || 3000;

// الاتصال بقاعدة بيانات MongoDB Atlas السحابية
const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/tiger-gym';
mongoose.connect(mongoURI)
  .then(() => console.log('Connected to MongoDB Atlas successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// تعريف نماذج قاعدة البيانات (Schemas & Models)
const memberSchema = new mongoose.Schema({
  id: { type: String, unique: true, required: true },
  name: String,
  phone: String,
  plan: String,
  start: String,
  end: String,
  salt: String,
  hash: String
});
const Member = mongoose.model('Member', memberSchema);

const planSchema = new mongoose.Schema({
  id: { type: String, unique: true, required: true },
  name: String,
  services: String,
  price: Number,
  days: Number
});
const Plan = mongoose.model('Plan', planSchema);

const requestSchema = new mongoose.Schema({
  id: Number,
  m: String,
  plan: String,
  t: String,
  hx: String
});
const Request = mongoose.model('Request', requestSchema);

// متغيرات عامة وبنية البيانات في الذاكرة مؤقتاً للتوافق
let D = {
  seq: 1, inv: 1, nid: 1, 
  secret: crypto.randomBytes(32).toString('hex'),
  vapid: webpush.generateVAPIDKeys(),
  staff: [{ u: process.env.ADMIN_USER || 'Admin', role: 'admin', ...mk(process.env.ADMIN_PASS || '850964') }],
  plans: [{ id: 'p1', name: 'جيم', services: 'صالة الحديد', price: 300, days: 30 }],
  att: [], invs: [], notes: [], seen: {}, subs: {}
};

D.usedTxn = D.usedTxn || [];
D.expenses = D.expenses || [];
D.partners = D.partners || [{ name: 'الشريك 1', pct: 0 }, { name: 'الشريك 2', pct: 0 }, { name: 'الشريك 3', pct: 0 }];
D.gateToken = D.gateToken || crypto.randomBytes(9).toString('base64url');
D.settings = D.settings || { shamCode: '', shamName: '' };

const PROOFS = path.join(__dirname, 'proofs'),
      EXT = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'application/pdf': 'pdf' };

const iso = d => d.toISOString().slice(0, 10),
      today = () => iso(new Date()),
      addD = (s, n) => { const d = new Date(s); d.setDate(d.getDate() + n); return iso(d); };
const E = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const hash = (p, salt) => crypto.scryptSync(String(p), salt, 32).toString('hex');
const mk = p => { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: hash(p, salt) }; };
const eq = (a, b) => { a = Buffer.from(a); b = Buffer.from(b); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const chk = (p, o) => eq(hash(p, o.salt), o.hash);

webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@example.com', D.vapid.publicKey, D.vapid.privateKey);
const sig = p => crypto.createHmac('sha256', D.secret).update(p).digest('base64url');
const sign = (o, h) => { const p = Buffer.from(JSON.stringify({ ...o, exp: Date.now() + h * 36e5 })).toString('base64url'); return p + '.' + sig(p); };
const verify = t => { try { const [p, s] = t.split('.'); if (!eq(s, sig(p))) return null; const o = JSON.parse(Buffer.from(p, 'base64url')); return o.exp > Date.now() ? o : null; } catch (e) { return null; } };

const tries = {}, blocked = ip => (tries[ip] = (tries[ip] || []).filter(t => Date.now() - t < 9e5)).length >= 10, bad = ip => tries[ip].push(Date.now());
const pubM = ({ salt, hash, ...x }) => x, str = (v, n = 100) => String(v ?? '').trim().slice(0, n), nid = () => ++D.nid;
const planOf = id => D.plans.find(p => p.id === id);

// دالة مساعدة لحذف ملف الإيصال من المجلد
const removeProof = (id) => {
  for (const e of Object.values(EXT)) {
    const f = path.join(PROOFS, id + '.' + e);
    if (fs.existsSync(f)) {
      try { fs.unlinkSync(f); } catch (err) { console.error("خطأ في حذف ملف الإيصال:", err); }
    }
  }
};

const stState = u => ({ plans: D.plans, members: [], att: D.att.slice(-3000), invs: D.invs, reqs: [], notes: D.notes.slice(-100), seen: {}, settings: D.settings, gateToken: u.role === 'admin' ? D.gateToken : '', expenses: D.expenses, partners: u.role === 'admin' ? D.partners : [], staff: u.role === 'admin' ? D.staff.map(({ u, role }) => ({ u, role })) : [] });
const mState = id => ({ plans: D.plans, members: [], att: [], invs: [], reqs: [], notes: [], seen: {}, settings: D.settings, mine: { inside: false, since: null } });

async function push(ids, title, body) {
  let n = 0;
  for (const id of ids) for (const s of [...(D.subs[id] || [])]) {
    try { await webpush.sendNotification(s, JSON.stringify({ title, body })); n++; }
    catch (e) { if (e.statusCode === 404 || e.statusCode === 410) D.subs[id] = D.subs[id].filter(x => x.endpoint !== s.endpoint); }
  }
  return n;
}
const note = (to, title, body) => D.notes.push({ id: nid(), t: new Date().toISOString(), title, body, to });
function renewM(m, p, txn) {
  if (m.end <= today()) m.start = today();
  const base = m.end > today() ? m.end : today();
  m.plan = p.id;
  m.end = addD(base, p.days);
  D.invs.push({ n: D.inv++, m: m.id, plan: p.name, amt: p.price, date: today(), kind: 'تجديد', ...(txn ? { pay: 'شام كاش' } : {}) });
}

// كائنات العمليات (Actions)
const A = {
  async memberSave(d) {
    const name = str(d.name), p = planOf(d.plan);
    if (!name) throw Error('الاسم مطلوب');
    if (!p) throw Error('اختر باقة صحيحة');
    if (d.id) {
      const m = await Member.findOne({ id: d.id });
      if (!m) throw Error('العضو غير موجود');
      m.name = name; m.phone = str(d.phone, 30); m.plan = p.id;
      const pw = str(d.pw, 50);
      if (pw) Object.assign(m, mk(pw));
      await m.save();
      return { id: m.id };
    }
    const id = 'TG-' + String(D.seq++).padStart(3, '0'),
          pw = str(d.pw, 50) || String(crypto.randomInt(100000, 999999)),
          st = today();
    const newMem = new Member({
      id, name, phone: str(d.phone, 30), plan: p.id,
      start: st, end: addD(st, p.days), ...mk(pw)
    });
    await newMem.save();
    D.invs.push({ n: D.inv++, m: id, plan: p.name, amt: p.price, date: st, kind: 'اشتراك' });
    return { id, pw };
  },

  async memberDel(d) {
    await Member.deleteOne({ id: d.id });
    await Request.deleteMany({ m: d.id });
    delete D.subs[d.id];
  },

  planSave(d) {
    const name = str(d.name), price = +d.price, days = Math.round(+d.days);
    if (!name || !(price >= 0) || !(days >= 1 && days <= 3650)) throw Error('بيانات الباقة غير صحيحة');
    const o = { name, services: str(d.services, 200), price, days };
    if (d.id) {
      const p = planOf(d.id);
      if (!p) throw Error('الباقة غير موجودة');
      Object.assign(p, o);
    } else {
      D.plans.push({ id: 'p' + Date.now(), ...o });
    }
  },

  planDel(d) { D.plans = D.plans.filter(p => p.id !== d.id); },

  async gate(d) {
    const id = str(d.code, 20).toUpperCase(), m = await Member.findOne({ id });
    if (!m) return { msg: ['كود غير معروف', 'bad'] };
    const o = D.att.find(a => a.m === id && !a.out), n = new Date().toISOString(),
          left = Math.round((new Date(m.end) - new Date(today())) / 864e5), nm = E(m.name);
    if (o) { o.out = n; return { msg: ['خروج: ' + nm, 'ok'] }; }
    if (left < 0) return { msg: ['اشتراك ' + nm + ' منتهي — لا يمكن تسجيل الدخول', 'bad'] };
    D.att.push({ m: id, in: n, out: null });
    return { msg: ['دخول: ' + nm + (left <= 7 ? ' (ينتهي اشتراكه خلال ' + left + ' أيام)' : ''), left <= 7 ? 'warn' : 'ok'] };
  },

  async renew(d) {
    const m = await Member.findOne({ id: d.m }), p = planOf(d.plan);
    if (!m || !p) throw Error('بيانات غير صحيحة');
    renewM(m, p);
    await m.save();
    const b = 'باقة ' + p.name + ' تنتهي في ' + m.end;
    note(m.id, 'تم تجديد اشتراكك', b);
    return { pushed: await push([m.id], 'تم تجديد اشتراكك', b) };
  },

  async approve(d) {
    const r = await Request.findOne({ id: d.id });
    if (!r) throw Error('الطلب غير موجود');
    const m = await Member.findOne({ id: r.m }), p = planOf(r.plan);
    
    // حذف الطلب وإزالة ملف الإيصال من المجلد فوراً
    await Request.deleteOne({ id: d.id });
    removeProof(r.id);

    if (!m || !p) throw Error('بيانات الطلب لم تعد صالحة');
    renewM(m, p, true);
    await m.save();
    if (r.hx) D.usedTxn.push(r.hx);
    const b = 'باقة ' + p.name + ' تنتهي في ' + m.end;
    note(m.id, 'تم تجديد اشتراكك', b);
    return { pushed: await push([m.id], 'تم تجديد اشتراكك', b) };
  },

  async reject(d) {
    const r = await Request.findOne({ id: d.id });
    if (!r) return;
    
    // حذف الطلب وإزالة ملف الإيصال من المجلد فوراً
    await Request.deleteOne({ id: d.id });
    removeProof(r.id);

    const b = 'تعذّر قبول طلب التجديد، يرجى التواصل مع النادي';
    note(r.m, 'طلب التجديد', b);
    return { pushed: await push([r.m], 'طلب التجديد', b) };
  },

  async reqRenew(d, u) {
    const p = planOf(d.plan);
    if (!p) throw Error('باقة غير صحيحة');
    if (await Request.exists({ m: u.id })) throw Error('لديك طلب قيد المراجعة');
    const mt = /^data:(image\/(?:jpeg|png|webp)|application\/pdf);base64,([A-Za-z0-9+/=]+)$/.exec(String(d.proof || ''));
    if (!mt) throw Error('أرفق إشعار التحويل (صورة أو PDF)');
    const buf = Buffer.from(mt[2], 'base64');
    if (buf.length > 2.5e6 || buf.length < 300) throw Error('حجم الملف غير مقبول (الحد 2.5 ميغابايت)');
    const hx = crypto.createHash('sha256').update(buf).digest('hex');
    if (D.usedTxn.includes(hx)) throw Error('هذا الإشعار أُرسل سابقاً، أرفق إشعار التحويل الجديد');
    
    const id = nid();
    fs.mkdirSync(PROOFS, { recursive: true });
    fs.writeFileSync(path.join(PROOFS, id + '.' + EXT[mt[1]]), buf);
    
    const newReq = new Request({ id, m: u.id, plan: p.id, t: new Date().toISOString(), hx });
    await newReq.save();
  },

  async selfGate(d, u) {
    if (!d.token || !eq(String(d.token), D.gateToken)) throw Error('رمز النادي غير صحيح');
    const m = await Member.findOne({ id: u.id }), o = D.att.find(a => a.m === u.id && !a.out),
          n = new Date().toISOString(), last = [...D.att].reverse().find(a => a.m === u.id),
          lt = o ? new Date(o.in).getTime() : (last && last.out ? new Date(last.out).getTime() : 0);
    if (lt && Date.now() - lt < 20000) return { msg: ['تم تسجيلك قبل لحظات', 'warn'] };
    if (o) { o.out = n
