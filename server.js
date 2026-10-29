'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { scan, ScanError, MAX_BYTES, VERSION, RULES } = require('./scanner');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');
const MAX_BODY = Math.ceil(MAX_BYTES * 1.2) + 4096; // JSON escaping overhead
const HISTORY_PER_CLIENT = 50;
const RATE_LIMIT = 30; // scans per minute per IP

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json; charset=utf-8' };
const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store'
};
if (process.env.NODE_ENV === 'production') SECURITY_HEADERS['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';

/* ---------- history store (scan results only; submitted code is never stored) ---------- */
function loadHistory() {
  try { return JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')); } catch { return []; }
}
function saveHistory(items) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = HISTORY_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(items));
  fs.renameSync(tmp, HISTORY_FILE);
}
const validClient = (id) => typeof id === 'string' && /^[a-f0-9-]{16,64}$/.test(id);

/* ---------- tiny rate limiter ---------- */
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > RATE_LIMIT;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some((t) => now - t < 60000)) hits.delete(k); }, 60000).unref();

/* ---------- helpers ---------- */
function send(res, status, body, headers = {}) {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8', ...headers });
  res.end(isObj ? JSON.stringify(body) : body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0, tooBig = false; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY * 4) { req.destroy(); return; } // hard stop for abusive uploads
      if (size > MAX_BODY) { tooBig = true; chunks.length = 0; return; } // drain, then answer with 413
      if (!tooBig) chunks.push(c);
    });
    req.on('end', () => {
      if (tooBig) return reject(new ScanError(413, `Upload is larger than the ${MAX_BYTES / 1024} KB limit.`));
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch { reject(new ScanError(400, 'Request body must be valid JSON.')); }
    });
    req.on('error', reject);
  });
}

async function handleApi(req, res, url) {
  const client = req.headers['x-client-id'];
  if (req.method === 'GET' && url.pathname === '/api/health') return send(res, 200, { ok: true, version: VERSION, rules: RULES.length });

  if (req.method === 'POST' && url.pathname === '/api/scan') {
    if (limited(req.socket.remoteAddress || 'x')) return send(res, 429, { error: 'Too many scans. Wait a minute and try again.' });
    if (!/^application\/json/i.test(req.headers['content-type'] || '')) return send(res, 415, { error: 'Send the scan request as application/json.' });
    const body = await readBody(req);
    const result = scan(body); // static analysis only; code is never executed
    if (body.save === true && validClient(client)) {
      const all = loadHistory();
      const mine = all.filter((h) => h.clientId === client);
      const others = all.filter((h) => h.clientId !== client);
      mine.unshift({ clientId: client, savedAt: result.createdAt, result });
      saveHistory(others.concat(mine.slice(0, HISTORY_PER_CLIENT)));
      result.saved = true;
    }
    return send(res, 200, result);
  }

  if (url.pathname.startsWith('/api/history')) {
    if (!validClient(client)) return send(res, 400, { error: 'Missing or invalid X-Client-Id header.' });
    const id = decodeURIComponent(url.pathname.slice('/api/history'.length).replace(/^\//, ''));
    const all = loadHistory();
    if (req.method === 'GET' && !id) {
      return send(res, 200, all.filter((h) => h.clientId === client).map((h) => ({ scanId: h.result.scanId, savedAt: h.savedAt, file: h.result.file, language: h.result.language, summary: h.result.summary })));
    }
    if (req.method === 'GET') {
      const item = all.find((h) => h.clientId === client && h.result.scanId === id);
      return item ? send(res, 200, item.result) : send(res, 404, { error: 'Saved scan not found.' });
    }
    if (req.method === 'DELETE') {
      const keep = all.filter((h) => !(h.clientId === client && (!id || h.result.scanId === id)));
      saveHistory(keep);
      return send(res, 200, { deleted: all.length - keep.length });
    }
  }
  return send(res, 404, { error: 'Not found.' });
}

function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
  let rel = decodeURIComponent(url.pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, 'Forbidden');
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, 'Not found');
    send(res, 200, data, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
    else serveStatic(req, res, url);
  } catch (e) {
    // Log only the error type/message, never submitted code.
    if (!(e instanceof ScanError)) console.error('Unexpected error:', e && e.message);
    if (!res.headersSent) send(res, e instanceof ScanError ? e.status : 500, { error: e instanceof ScanError ? e.message : 'Something went wrong on the server. Please try again.' });
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => console.log(`CodeCook running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`));
}
module.exports = server;
