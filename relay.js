// SMS relay: Customer app -> (ye server) -> Gateway phone khud yahan se SMS utha ke bhejta hai.
// Isme phone ka IP/port kabhi nahi lagta, aur API key app me nahi hoti.
const crypto = require('crypto');

const GATEWAY_TOKEN = process.env.GATEWAY_TOKEN || 'change-this-gateway-token';   // Render me set karo
if (GATEWAY_TOKEN === 'change-this-gateway-token') console.warn('WARNING: GATEWAY_TOKEN set nahi hai, default use ho raha hai!');

const SECRET = crypto.randomBytes(16).toString('hex');
const OTP_TTL = 5 * 60e3, JOB_TTL = 2 * 60e3, LEASE = 60e3, POLL_HOLD = 20e3, GATEWAY_ALIVE = 70e3;
const MAX_TRIES = 5, PHONE_GAP = 30e3, PHONE_HOURLY = 50, IP_HOURLY = 230;

const otps = new Map(), jobs = new Map(), hits = new Map();
let waiters = [], lastPoll = 0;

const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
const clientIp = req => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const hashOtp = (phone, code) => sha(SECRET + phone + code).toString('hex');
const gatewayAlive = () => waiters.length > 0 || Date.now() - lastPoll < GATEWAY_ALIVE;
const tokenOk = req => crypto.timingSafeEqual(sha(req.headers['x-gateway-token'] || ''), sha(GATEWAY_TOKEN));

function readJson(req) {
  return new Promise(ok => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > 2048) { req.destroy(); ok({}); } });
    req.on('end', () => { try { ok(JSON.parse(b || '{}')); } catch { ok({}); } });
    req.on('error', () => ok({}));
  });
}
function normPhone(p) {
  let d = String(p || '').replace(/[^0-9]/g, '');
  if (d.length === 12 && d.startsWith('91')) d = d.slice(2);
  return /^[6-9]\d{9}$/.test(d) ? '+91' + d : null;
}
function allow(key, max, windowMs) {
  const now = Date.now(), a = (hits.get(key) || []).filter(t => now - t < windowMs);
  if (a.length >= max) { hits.set(key, a); return false; }
  a.push(now); hits.set(key, a); return true;
}
function takeJobs() {
  const now = Date.now(), out = [];
  for (const j of jobs.values()) {
    if (now - j.created > JOB_TTL) { jobs.delete(j.id); continue; }
    if (j.lease > now || out.length >= 5) continue;
    j.lease = now + LEASE; out.push({ id: j.id, number: j.number, text: j.text });
  }
  return out;
}
function dispatch() {
  while (waiters.length) {
    const out = takeJobs();
    if (!out.length) return;
    const w = waiters.shift(); clearTimeout(w.timer); send(w.res, 200, { jobs: out });
  }
}

async function handle(req, res, url) {
  const p = url.pathname;
  if (!p.startsWith('/relay/')) return false;

  // ---- Customer app: OTP bhejo ----
  if (p === '/relay/otp/send' && req.method === 'POST') {
    const body = await readJson(req);
    const phone = normPhone(body.phone);
    // Driver app "app":"partner" bhejti hai -> SMS me "Apna Ride Partner". Customer app kuch nahi bhejti -> "Apna Ride".
    const appName = body.app === 'partner' ? 'Apna Ride Partner' : 'Apna Ride';
    if (!phone) return send(res, 400, { ok: false, error: 'invalid_phone' }), true;
    if (!gatewayAlive()) return send(res, 503, { ok: false, error: 'sms_service_down' }), true;
    const old = otps.get(phone);
    if (old && Date.now() - old.sent < PHONE_GAP) return send(res, 429, { ok: false, error: 'wait', retryAfter: Math.ceil((PHONE_GAP - (Date.now() - old.sent)) / 1000) }), true;
    if (!allow('ip:' + clientIp(req), IP_HOURLY, 3600e3) || !allow('ph:' + phone, PHONE_HOURLY, 3600e3)) return send(res, 429, { ok: false, error: 'too_many' }), true;

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    otps.set(phone, { h: hashOtp(phone, code), exp: Date.now() + OTP_TTL, tries: 0, sent: Date.now() });
    const id = crypto.randomBytes(8).toString('hex');
    // Text me "verification" shabd nahi likhna: operator use rok deta hai (test se pata chala)
    jobs.set(id, { id, number: phone, created: Date.now(), lease: 0,
      text: 'Your ' + appName + ' verify code is ' + code + '. Valid for 5 minutes. Do not share it with anyone.' });
    dispatch();
    return send(res, 200, { ok: true }), true;
  }

  // ---- Customer app: OTP check karo ----
  if (p === '/relay/otp/verify' && req.method === 'POST') {
    const b = await readJson(req), phone = normPhone(b.phone), code = String(b.code || '');
    const r = phone && otps.get(phone);
    if (!r) return send(res, 200, { ok: false, reason: 'not_found' }), true;
    if (Date.now() > r.exp) { otps.delete(phone); return send(res, 200, { ok: false, reason: 'expired' }), true; }
    if (r.tries >= MAX_TRIES) { otps.delete(phone); return send(res, 200, { ok: false, reason: 'too_many' }), true; }
    if (/^\d{6}$/.test(code) && crypto.timingSafeEqual(Buffer.from(hashOtp(phone, code)), Buffer.from(r.h))) {
      otps.delete(phone); return send(res, 200, { ok: true }), true;
    }
    r.tries++; return send(res, 200, { ok: false, reason: 'wrong' }), true;
  }

  // ---- Gateway phone: kaam maango (long-poll) ----
  if (p === '/relay/poll' && req.method === 'GET') {
    if (!tokenOk(req)) return send(res, 401, { error: 'bad_token' }), true;
    lastPoll = Date.now();
    const out = takeJobs();
    if (out.length) return send(res, 200, { jobs: out }), true;
    const w = { res };
    const drop = () => { clearTimeout(w.timer); waiters = waiters.filter(x => x !== w); };
    w.timer = setTimeout(() => { drop(); lastPoll = Date.now(); send(res, 200, { jobs: [] }); }, POLL_HOLD);
    res.on('close', drop);
    waiters.push(w);
    return true;
  }

  // ---- Gateway phone: kaam ho gaya ----
  if (p === '/relay/ack' && req.method === 'POST') {
    if (!tokenOk(req)) return send(res, 401, { error: 'bad_token' }), true;
    const b = await readJson(req);
    jobs.delete(String(b.id || ''));
    if (b.ok === false) console.warn('Gateway SMS fail:', String(b.error || '').slice(0, 100));
    return send(res, 200, { ok: true }), true;
  }
  return send(res, 404, { error: 'not_found' }), true;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of otps) if (now > v.exp) otps.delete(k);
  for (const [k, v] of hits) if (!v.some(t => now - t < 3600e3)) hits.delete(k);
}, 5 * 60e3).unref();

module.exports = { handle };
