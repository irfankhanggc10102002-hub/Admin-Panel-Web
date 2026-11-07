// Apna Ride download website: koi npm package nahi chahiye. Chalane ke liye: node server.js
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const relay = require('./relay');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me-now';   // <-- ISE BADAL DO
const MAX_APK = 500 * 1024 * 1024;                                        // 500 MB
// DATA_DIR: Render par persistent disk ka path (jaise /var/data). Na ho to isi folder me save hoga.
const STORE = process.env.DATA_DIR || __dirname;
const DIRS = { pub: path.join(__dirname, 'public'), dl: path.join(STORE, 'downloads'),
               data: path.join(STORE, 'data'), priv: path.join(__dirname, 'private') };
const FILES = { customer: 'apna-ride.apk', partner: 'apna-ride-partner.apk' };
const DB = path.join(DIRS.data, 'apps.json');
Object.values(DIRS).forEach(d => fs.mkdirSync(d, { recursive: true }));

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon', '.webp': 'image/webp' };
const sessions = new Map();   // token -> expiry
const tries = new Map();      // ip -> {n, t}

const SEED = path.join(__dirname, 'data', 'apps.json');   // repo ke saath aayi apps.json (GitHub wali)
const readFileJson = f => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };
// Pehle DB (DATA_DIR wali) padho; wo khaali/galat ho to repo wali apps.json padho
const readDb = () => { const d = readFileJson(DB); return (d && Object.keys(d).length) ? d : (readFileJson(SEED) || {}); };
const writeDb = d => fs.writeFileSync(DB, JSON.stringify(d, null, 2));
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
const clip = (s, n) => String(s || '').replace(/[\r\n]+/g, ' ').slice(0, n);

function isAdmin(req) {
  const m = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '');
  const exp = m && sessions.get(m[1]);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(m[1]); return false; }
  return true;
}
const sameOrigin = req => req.headers['x-requested-with'] === 'apnaride';   // CSRF se bachav

function readBody(req, limit = 4096) {
  return new Promise((ok, no) => { let b = ''; req.on('data', c => { b += c; if (b.length > limit) { req.destroy(); no(); } }); req.on('end', () => ok(b)); req.on('error', no); });
}

function serveFile(req, res, file, extra = {}) {
  fs.stat(file, (e, st) => {
    if (e || !st.isFile()) { res.writeHead(404); return res.end('Not found'); }
    // Range support: Chrome/Android download manager beech me ruke download ko "resume" karta hai.
    // Server Range na samjhe to download "failed" ho jaata hai.
    const etag = `"${st.size}-${Math.floor(st.mtimeMs)}"`;
    const h = { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Accept-Ranges': 'bytes',
                'ETag': etag, 'Last-Modified': st.mtime.toUTCString(), ...extra };
    let start = 0, end = st.size - 1, status = 200;
    const rg = req.headers.range, ifr = req.headers['if-range'];
    if (rg && (!ifr || ifr === etag || ifr === h['Last-Modified'])) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(rg.trim());
      if (m && (m[1] !== '' || m[2] !== '')) {
        if (m[1] === '') start = Math.max(0, st.size - parseInt(m[2], 10));
        else { start = parseInt(m[1], 10); if (m[2] !== '') end = Math.min(end, parseInt(m[2], 10)); }
      }
      if (!m || start > end || start >= st.size) {
        res.writeHead(416, { 'Content-Range': `bytes */${st.size}` }); return res.end();
      }
      status = 206; h['Content-Range'] = `bytes ${start}-${end}/${st.size}`;
    }
    h['Content-Length'] = end - start + 1;
    res.writeHead(status, h);
    if (req.method === 'HEAD') return res.end();
    const s = fs.createReadStream(file, { start, end });
    s.on('error', () => res.destroy());
    res.on('close', () => s.destroy());
    s.pipe(res);
  });
}

async function api(req, res, url) {
  if (url.pathname === '/api/apps' && req.method === 'GET') {
    const d = readDb(), out = {};
    for (const k of Object.keys(d)) { const { sha256, ...pub } = d[k]; out[k] = pub; }   // checksum bahar nahi dikhana
    return json(res, 200, out);
  }

  if (url.pathname === '/api/login' && req.method === 'POST') {
    const ip = req.socket.remoteAddress, t = tries.get(ip) || { n: 0, t: Date.now() };
    if (Date.now() - t.t > 600000) { t.n = 0; t.t = Date.now(); }
    if (t.n >= 5) return json(res, 429, { error: 'Bahut zyada try. 10 minute baad dobara koshish karo.' });
    let pw = ''; try { pw = JSON.parse(await readBody(req)).password || ''; } catch {}
    const a = crypto.createHash('sha256').update(pw).digest(), b = crypto.createHash('sha256').update(ADMIN_PASSWORD).digest();
    if (!crypto.timingSafeEqual(a, b)) { t.n++; tries.set(ip, t); return json(res, 401, { error: 'Password galat hai.' }); }
    const sid = crypto.randomBytes(24).toString('hex'); sessions.set(sid, Date.now() + 12 * 3600e3);
    res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`);
    return json(res, 200, { ok: true });
  }

  // Yahan se neeche sab kuch sirf admin ke liye
  if (!isAdmin(req)) return json(res, 401, { error: 'Login karo.' });
  if (url.pathname === '/api/me') return json(res, 200, { ok: true });
  if (req.method === 'POST' && !sameOrigin(req)) return json(res, 403, { error: 'Request allowed nahi.' });

  if (url.pathname === '/api/logout') { res.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/'); return json(res, 200, { ok: true }); }

  const app = url.searchParams.get('app');
  if (!FILES[app]) return json(res, 400, { error: 'app customer ya partner hona chahiye.' });

  if (url.pathname === '/api/delete' && req.method === 'POST') {
    fs.rmSync(path.join(DIRS.dl, FILES[app]), { force: true });
    const d = readDb(); delete d[app]; writeDb(d); return json(res, 200, { ok: true });
  }

  if (url.pathname === '/api/upload' && req.method === 'POST') {
    const tmp = path.join(DIRS.dl, FILES[app] + '.part'), hash = crypto.createHash('sha256');
    let size = 0, head = Buffer.alloc(0), bad = null;
    const out = fs.createWriteStream(tmp);
    req.on('data', c => {
      size += c.length;
      if (head.length < 4) head = Buffer.concat([head, c]).subarray(0, 4);
      if (size > MAX_APK) { bad = 'File 500 MB se badi hai.'; req.destroy(); return; }
      hash.update(c); out.write(c);
    });
    req.on('end', () => out.end(() => {
      if (!bad && (size < 1024 || head.toString('latin1') !== 'PK\x03\x04')) bad = 'Ye valid APK file nahi lag rahi.';
      if (bad) { fs.rmSync(tmp, { force: true }); return json(res, 400, { error: bad }); }
      fs.renameSync(tmp, path.join(DIRS.dl, FILES[app]));
      const d = readDb();
      d[app] = { file: '/downloads/' + FILES[app], version: clip(url.searchParams.get('version'), 30) || '1.0',
        notes: clip(url.searchParams.get('notes'), 200), size, sha256: hash.digest('hex'),
        date: new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) };
      writeDb(d); json(res, 200, { ok: true, app: d[app] });
    }));
    req.on('error', () => { out.destroy(); fs.rmSync(tmp, { force: true }); });
    return;
  }
  json(res, 404, { error: 'Not found' });
}

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname.startsWith('/relay/')) return relay.handle(req, res, url).catch(() => json(res, 500, { error: 'Server error' }));
  const p0 = decodeURIComponent(url.pathname);
  const p = p0.length > 1 ? p0.replace(/\/+$/, '') : p0;   // /admin/ aur /admin dono chalein
  if (p.startsWith('/api/')) return api(req, res, url).catch(() => json(res, 500, { error: 'Server error' }));
  if (p === '/admin' || p === '/admin.html') return serveFile(req, res, path.join(DIRS.priv, 'admin.html'), { 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' });
  if (p.startsWith('/downloads/')) {
    const name = path.basename(p);
    if (!Object.values(FILES).includes(name)) { res.writeHead(404); return res.end('Not found'); }
    return serveFile(req, res, path.join(DIRS.dl, name),
      { 'Content-Type': 'application/vnd.android.package-archive', 'Content-Disposition': `attachment; filename="${name}"`, 'Cache-Control': 'no-cache' });
  }
  const file = path.join(DIRS.pub, p === '/' ? 'index.html' : p);
  if (!file.startsWith(DIRS.pub + path.sep)) { res.writeHead(403); return res.end(); }
  serveFile(req, res, file);
}).listen(PORT, () => {
  const base = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;   // Render par asli https link aata hai
  console.log(`Site chal rahi hai: ${base}   Admin panel: ${base}/admin`);
  // Files sahi jagah hain ya nahi - Render ke Logs me dikhega
  const chk = f => console.log((fs.existsSync(f) ? 'OK      ' : 'MISSING ') + path.relative(__dirname, f));
  chk(path.join(DIRS.pub, 'index.html')); chk(path.join(DIRS.priv, 'admin.html'));
  const walk = (d, pre = '') => { try { fs.readdirSync(d, { withFileTypes: true }).forEach(e => {
    if (e.name === 'node_modules' || e.name === '.git') return;
    console.log('  ' + pre + e.name + (e.isDirectory() ? '/' : '')); if (e.isDirectory()) walk(path.join(d, e.name), pre + e.name + '/'); }); } catch {} };
  console.log('Project me ye files mili:'); walk(__dirname);
  console.log('apps.json DB path:', DB, '| DB keys:', Object.keys(readFileJson(DB) || {}).join(',') || '(khaali/galat)',
    '| repo seed keys:', Object.keys(readFileJson(SEED) || {}).join(',') || '(khaali/galat)', '| DATA_DIR:', process.env.DATA_DIR || '(set nahi)');
});
