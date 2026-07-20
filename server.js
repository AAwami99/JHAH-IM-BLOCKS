const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool } = require('pg');

const root = __dirname;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined });
const secret = process.env.APP_SECRET;
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(body)); };
const readBody = req => new Promise((resolve, reject) => { let body = ''; req.on('data', c => body += c); req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('Invalid JSON')); } }); });
const tokenFor = () => { const expiry = String(Date.now() + 8 * 60 * 60 * 1000); return `${expiry}.${crypto.createHmac('sha256', secret).update(expiry).digest('hex')}`; };
const validToken = token => { const [expiry, signature] = String(token || '').split('.'); return Number(expiry) > Date.now() && crypto.timingSafeEqual(Buffer.from(signature || ''), Buffer.from(crypto.createHmac('sha256', secret).update(expiry || '').digest('hex'))); };
const chief = req => validToken(req.headers['x-chief-token']);
async function init() { await pool.query('CREATE TABLE IF NOT EXISTS app_state (key text PRIMARY KEY, value jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())'); }
const server = http.createServer(async (req, res) => {
  try {
    if (req.url === '/api/health') return json(res, 200, { ok: true });
    if (req.url === '/api/schedule' && req.method === 'GET') { const r = await pool.query("SELECT value, updated_at FROM app_state WHERE key='schedule'"); return json(res, 200, r.rowCount ? { state: r.rows[0].value, savedAt: r.rows[0].updated_at } : { state: null }); }
    if (req.url === '/api/schedule' && req.method === 'PUT') { const { state } = await readBody(req); if (!state) return json(res, 400, { error: 'Missing schedule.' }); await pool.query("INSERT INTO app_state(key,value) VALUES('schedule',$1) ON CONFLICT(key) DO UPDATE SET value=$1, updated_at=now()", [state]); return json(res, 200, { ok: true }); }
    if (req.url === '/api/chief/login' && req.method === 'POST') { const { password } = await readBody(req); const saved = await pool.query("SELECT value FROM app_state WHERE key='chief_password'"); const current = saved.rowCount ? saved.rows[0].value.password : process.env.CHIEF_PASSWORD; if (!current || !secret || ![current, process.env.MASTER_KEY].includes(password)) return json(res, 401, { error: 'Incorrect password.' }); return json(res, 200, { token: tokenFor() }); }
    if (req.url === '/api/chief/password' && req.method === 'PUT') { if (!chief(req)) return json(res, 401, { error: 'Chief access required.' }); const { password } = await readBody(req); if (!password || password.length < 8) return json(res, 400, { error: 'Password must be at least 8 characters.' }); await pool.query("INSERT INTO app_state(key,value) VALUES('chief_password',$1) ON CONFLICT(key) DO UPDATE SET value=$1", [{ password }]); return json(res, 200, { ok: true }); }
    if (req.url === '/api/baseline/restore' && req.method === 'POST') { if (!chief(req)) return json(res, 401, { error: 'Chief access required.' }); await pool.query("DELETE FROM app_state WHERE key='schedule'"); return json(res, 200, { ok: true }); }
    const file = req.url === '/' ? 'index.html' : req.url.slice(1); const target = path.resolve(root, file); if (!target.startsWith(root) || !fs.existsSync(target)) return json(res, 404, { error: 'Not found' }); res.writeHead(200, { 'content-type': target.endsWith('.html') ? 'text/html; charset=utf-8' : 'application/octet-stream' }); fs.createReadStream(target).pipe(res);
  } catch (error) { console.error(error); json(res, 500, { error: 'Server error.' }); }
});
init().then(() => server.listen(process.env.PORT || 10000, '0.0.0.0'));
