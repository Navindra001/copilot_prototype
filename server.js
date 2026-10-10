// Story Pilot prototype server. No dependencies. Needs Node 18 or newer.
// Run:  node server.js
// Env:  PORT (3000), CLINIC_CODE (clinic-invite) = invite code clinicians enter when they sign up.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const CLINIC_CODE = process.env.CLINIC_CODE || 'clinic-invite';
const FILE = path.join(__dirname, 'data.json');
const COLLS = ['families', 'status', 'clinical', 'claims', 'closed'];
const SESSION_MS = 30 * 864e5;

let db = {};
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
COLLS.concat(['users', 'sessions']).forEach(c => { db[c] = db[c] || {}; });
let saveT = null;
const save = () => { clearTimeout(saveT); saveT = setTimeout(() => fs.writeFile(FILE, JSON.stringify(db), () => {}), 150); };

/* ---------- accounts ---------- */
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const publicUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });
const findByEmail = em => Object.values(db.users).find(u => u.email === em);
const fails = {}; // login throttle per email
function tooMany(em) { const f = fails[em]; return f && f.n >= 5 && Date.now() - f.t < 5 * 60 * 1000; }
function noteFail(em) { const f = fails[em] && Date.now() - fails[em].t < 5 * 60 * 1000 ? fails[em] : { n: 0, t: Date.now() }; f.n++; f.t = Date.now(); fails[em] = f; }
function newSession(uid) {
  const token = crypto.randomBytes(24).toString('hex');
  db.sessions[token] = { uid, at: Date.now() }; save(); return token;
}
function auth(req, url) {
  const tok = String(req.headers['x-token'] || url.searchParams.get('token') || '');
  const s = db.sessions[tok];
  if (!s || Date.now() - s.at > SESSION_MS) return null;
  const u = db.users[s.uid]; return u ? { user: u, token: tok } : null;
}

/* ---------- live updates ---------- */
const clients = new Set();
function view(user) { // families see only their own record; clinical notes are clinic-only
  const admin = user.role === 'clinician', out = {};
  COLLS.forEach(c => { out[c] = db[c]; });
  if (!admin) { out.clinical = {}; out.families = db.families[user.id] ? { [user.id]: db.families[user.id] } : {}; }
  return out;
}
const push = () => clients.forEach(c => c.res.write('data: ' + JSON.stringify(view(c.user)) + '\n\n'));
function body(req) {
  return new Promise(resolve => {
    let b = ''; req.on('data', d => { b += d; if (b.length > 262144) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch (e) { resolve(null); } });
  });
}
const send = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj || {})); };
const fail = (res, code, error) => send(res, code, { error });

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'), p = url.pathname;

  if (p === '/api/ping') return send(res, 200, { ok: true });
  if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
    return fs.readFile(path.join(__dirname, 'index.html'), (e, d) => {
      if (e) return fail(res, 500, 'Page missing.');
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); res.end(d);
    });
  }

  if (p === '/api/signup' && req.method === 'POST') {
    const b = await body(req); if (!b) return fail(res, 400, 'Bad request.');
    const name = String(b.name || '').trim(), email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
    const role = b.role === 'clinician' ? 'clinician' : 'parent';
    if (name.length < 2 || name.length > 60) return fail(res, 400, 'Enter your name.');
    if (!/^\S+@\S+\.\S+$/.test(email)) return fail(res, 400, 'Enter a valid email address.');
    if (pw.length < 8) return fail(res, 400, 'Use at least 8 characters for your password.');
    if (role === 'clinician' && String(b.code || '') !== CLINIC_CODE) return fail(res, 403, 'That clinic invite code is not right.');
    if (findByEmail(email)) return fail(res, 409, 'An account with that email already exists. Log in instead.');
    const id = 'u' + crypto.randomBytes(8).toString('hex'), salt = crypto.randomBytes(16).toString('hex');
    db.users[id] = { id, name, email, role, salt, hash: hashPw(pw, salt), created: Date.now() };
    return send(res, 200, { user: publicUser(db.users[id]), token: newSession(id) });
  }
  if (p === '/api/login' && req.method === 'POST') {
    const b = await body(req); if (!b) return fail(res, 400, 'Bad request.');
    const email = String(b.email || '').trim().toLowerCase();
    if (tooMany(email)) return fail(res, 429, 'Too many attempts. Try again in a few minutes.');
    const u = findByEmail(email);
    let ok = false;
    if (u) { const a = Buffer.from(hashPw(String(b.password || ''), u.salt), 'hex'), h = Buffer.from(u.hash, 'hex'); ok = a.length === h.length && crypto.timingSafeEqual(a, h); }
    if (!ok) { noteFail(email); return fail(res, 401, 'Email or password is not right.'); }
    delete fails[email];
    return send(res, 200, { user: publicUser(u), token: newSession(u.id) });
  }

  const a = auth(req, url);
  if (!a) return fail(res, 401, 'Please log in.');
  const user = a.user, admin = user.role === 'clinician';

  if (p === '/api/me') return send(res, 200, { user: publicUser(user) });
  if (p === '/api/logout' && req.method === 'POST') { delete db.sessions[a.token]; save(); return send(res, 200); }

  if (p === '/api/events') {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
    const c = { res, user }; clients.add(c);
    res.write('data: ' + JSON.stringify(view(user)) + '\n\n');
    const ka = setInterval(() => res.write(': ping\n\n'), 25000);
    req.on('close', () => { clearInterval(ka); clients.delete(c); });
    return;
  }
  let m = p.match(/^\/api\/doc\/(\w+)\/([^/]+)$/);
  if (m) {
    const coll = m[1], id = decodeURIComponent(m[2]);
    if (!COLLS.includes(coll)) return fail(res, 404, 'Not found.');
    const ok = admin || (coll === 'families' && id === user.id) || coll === 'claims';
    if (!ok) return fail(res, 403, 'You do not have permission to change this.');
    if (req.method === 'PUT') {
      const b = await body(req); if (!b || typeof b !== 'object') return fail(res, 400, 'Bad request.');
      db[coll][id] = b;
    } else if (req.method === 'DELETE') delete db[coll][id];
    else return fail(res, 405, 'Not allowed.');
    save(); push(); return send(res, 200);
  }
  m = p.match(/^\/api\/claim\/([^/]+)$/);
  if (m && req.method === 'POST') {
    const id = decodeURIComponent(m[1]), b = await body(req);
    if (!b) return fail(res, 400, 'Bad request.');
    b.uid = user.id;
    const cur = db.claims[id];
    if (cur) { // a claim is stale if its booking was cancelled or declined
      const f = db.families[cur.uid], bk = f && f.bookings && f.bookings[cur.bid], st = db.status[cur.bid];
      if (bk && !bk.cancelled && !(st && st.status === 'declined')) return fail(res, 409, 'Taken.');
    }
    db.claims[id] = b; save(); push(); return send(res, 200);
  }
  fail(res, 404, 'Not found.');
}).listen(PORT, () => console.log('Story Pilot running on http://localhost:' + PORT + '\nClinician invite code: ' + CLINIC_CODE));
