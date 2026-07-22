import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(process.env.TNUA_DATA_DIR || path.join(root, 'server-data'));
const versionsDir = path.join(dataDir, 'versions');
const statePath = path.join(dataDir, 'state.json');
const host = process.env.TNUA_HOST || '127.0.0.1';
const port = Number(process.env.TNUA_PORT || 4178);
const sessionHours = Math.max(1, Number(process.env.TNUA_SESSION_HOURS || 8));
const generatedPassword = crypto.randomBytes(12).toString('base64url');
const sessionSecret = process.env.TNUA_SESSION_SECRET || crypto.randomBytes(32).toString('hex');

function configuredUsers() {
  if (process.env.TNUA_USERS_JSON) {
    const raw = JSON.parse(process.env.TNUA_USERS_JSON);
    return Object.fromEntries(Object.entries(raw).map(([username, user]) => [username, {
      username,
      name: String(user.name || username),
      password: String(user.password || ''),
      role: ['viewer', 'editor', 'admin'].includes(user.role) ? user.role : 'viewer',
    }]));
  }
  const username = process.env.TNUA_ADMIN_USER || 'admin';
  return { [username]: { username, name: '招生資料管理者', password: process.env.TNUA_ADMIN_PASSWORD || generatedPassword, role: 'admin' } };
}

const users = configuredUsers();
const loginAttempts = new Map();
let mutationQueue = Promise.resolve();

function emptyState() {
  return { format: 'tnua-central-store', version: 1, revision: 0, draft: null, published: null, versions: [], audit: [] };
}

async function ensureStorage() {
  await fs.mkdir(versionsDir, { recursive: true });
  try { await fs.access(statePath); } catch { await atomicWrite(statePath, emptyState()); }
}

async function atomicWrite(target, value) {
  await fs.mkdir(path.dirname(target), { recursive: true });
  const temporary = target + '.' + process.pid + '.' + Date.now() + '.tmp';
  await fs.writeFile(temporary, JSON.stringify(value, null, 2), 'utf8');
  await fs.rename(temporary, target);
}

async function readState() {
  try {
    const value = JSON.parse(await fs.readFile(statePath, 'utf8'));
    return value?.format === 'tnua-central-store' ? value : emptyState();
  } catch { return emptyState(); }
}

function queueMutation(action) {
  const result = mutationQueue.then(action, action);
  mutationQueue = result.catch(() => {});
  return result;
}

function base64url(value) { return Buffer.from(value).toString('base64url'); }
function sign(value) { return crypto.createHmac('sha256', sessionSecret).update(value).digest('base64url'); }
function safeEqual(left, right) {
  const a = Buffer.from(String(left)); const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function issueSession(username) {
  const payload = base64url(JSON.stringify({ username, expires: Date.now() + sessionHours * 3600_000 }));
  return payload + '.' + sign(payload);
}

function sessionUser(request) {
  const cookies = Object.fromEntries(String(request.headers.cookie || '').split(';').map(part => part.trim().split('=').map(decodeURIComponent)).filter(pair => pair.length === 2));
  const token = cookies.tnua_session;
  if (!token) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature || !safeEqual(signature, sign(payload))) return null;
  try {
    const value = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (Number(value.expires) < Date.now()) return null;
    const user = users[value.username];
    return user ? { username: user.username, name: user.name, role: user.role } : null;
  } catch { return null; }
}

function sendJson(response, status, body, extraHeaders = {}) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders });
  response.end(JSON.stringify(body));
}

function cookieHeader(request, token, maxAge) {
  const forwardedHttps = String(request.headers['x-forwarded-proto'] || '').toLowerCase() === 'https';
  return `tnua_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${forwardedHttps ? '; Secure' : ''}`;
}

async function readJson(request, limit = 20 * 1024 * 1024) {
  const chunks = []; let size = 0;
  for await (const chunk of request) { size += chunk.length; if (size > limit) throw Object.assign(new Error('請求資料超過大小限制'), { status: 413 }); chunks.push(chunk); }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw Object.assign(new Error('JSON 格式錯誤'), { status: 400 }); }
}

function sameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === request.headers.host; } catch { return false; }
}

function requireUser(request, roles = ['viewer', 'editor', 'admin']) {
  const user = sessionUser(request);
  if (!user) throw Object.assign(new Error('請先登入'), { status: 401 });
  if (!roles.includes(user.role)) throw Object.assign(new Error('此帳號沒有執行權限'), { status: 403 });
  return user;
}

function validatePayload(payload) {
  if (!payload || payload.format !== 'tnua-central-payload' || Number(payload.version) !== 1) throw Object.assign(new Error('中央資料格式不正確'), { status: 400 });
  if (!Array.isArray(payload.customRows) || payload.customRows.length > 10_000) throw Object.assign(new Error('招生資料筆數異常'), { status: 400 });
  if (!payload.inlineEdits || Array.isArray(payload.inlineEdits) || typeof payload.inlineEdits !== 'object') throw Object.assign(new Error('編輯資料格式不正確'), { status: 400 });
  return payload;
}

function payloadSummary(payload) {
  return { customRows: payload?.customRows?.length || 0, inlineEdits: Object.keys(payload?.inlineEdits || {}).length, hasSystemData: !!payload?.systemData };
}

async function addVersion(state, stage, payload, user, note) {
  const id = crypto.randomUUID();
  const metadata = { id, revision: state.revision, stage, createdAt: new Date().toISOString(), user: user.username, name: user.name, note: String(note || '').slice(0, 300), summary: payloadSummary(payload) };
  await atomicWrite(path.join(versionsDir, id + '.json'), { ...metadata, payload });
  state.versions.unshift(metadata);
  const removed = state.versions.splice(50);
  await Promise.all(removed.map(item => fs.unlink(path.join(versionsDir, item.id + '.json')).catch(() => {})));
  return metadata;
}

function audit(state, user, action, detail = '') {
  state.audit.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), user: user.username, name: user.name, role: user.role, action, detail: String(detail).slice(0, 500), revision: state.revision });
  state.audit = state.audit.slice(0, 500);
}

async function handleApi(request, response, pathname, url) {
  if (request.method !== 'GET' && !sameOrigin(request)) return sendJson(response, 403, { error: '來源驗證失敗' });
  if (pathname === '/api/session' && request.method === 'GET') {
    return sendJson(response, 200, { central: true, authenticated: !!sessionUser(request), user: sessionUser(request) });
  }
  if (pathname === '/api/login' && request.method === 'POST') {
    const ip = request.socket.remoteAddress || 'unknown'; const attempt = loginAttempts.get(ip) || { count: 0, resetAt: 0 };
    if (attempt.resetAt > Date.now() && attempt.count >= 8) return sendJson(response, 429, { error: '登入失敗次數過多，請稍後再試' });
    const body = await readJson(request, 32 * 1024); const user = users[String(body.username || '')];
    if (!user || !safeEqual(body.password || '', user.password)) { loginAttempts.set(ip, { count: attempt.resetAt > Date.now() ? attempt.count + 1 : 1, resetAt: Date.now() + 15 * 60_000 }); return sendJson(response, 401, { error: '帳號或密碼錯誤' }); }
    loginAttempts.delete(ip); const publicUser = { username: user.username, name: user.name, role: user.role };
    return sendJson(response, 200, { central: true, authenticated: true, user: publicUser }, { 'Set-Cookie': cookieHeader(request, issueSession(user.username), sessionHours * 3600) });
  }
  if (pathname === '/api/logout' && request.method === 'POST') return sendJson(response, 200, { ok: true }, { 'Set-Cookie': cookieHeader(request, '', 0) });
  if (pathname === '/api/data' && request.method === 'GET') {
    const user = requireUser(request); const state = await readState(); let stage = url.searchParams.get('stage') === 'draft' ? 'draft' : 'published';
    if (user.role === 'viewer') stage = 'published';
    let payload = state[stage]; if (!payload && stage === 'draft') { payload = state.published; stage = payload ? 'published' : 'draft'; }
    return sendJson(response, 200, { revision: state.revision, stage, payload });
  }
  if (pathname === '/api/versions' && request.method === 'GET') { requireUser(request); const state = await readState(); return sendJson(response, 200, { revision: state.revision, versions: state.versions }); }
  if (pathname === '/api/audit' && request.method === 'GET') { requireUser(request, ['admin']); const state = await readState(); return sendJson(response, 200, { revision: state.revision, audit: state.audit }); }
  if (pathname === '/api/draft' && request.method === 'POST') {
    const user = requireUser(request, ['editor', 'admin']); const body = await readJson(request); const payload = validatePayload(body.payload);
    return queueMutation(async () => { const state = await readState(); if (Number(body.baseRevision) !== state.revision) return sendJson(response, 409, { error: '中央資料已由其他使用者更新', revision: state.revision }); state.revision += 1; state.draft = payload; await addVersion(state, 'draft', payload, user, body.note); audit(state, user, 'save-draft', body.note); await atomicWrite(statePath, state); return sendJson(response, 200, { ok: true, revision: state.revision, stage: 'draft' }); });
  }
  if (pathname === '/api/publish' && request.method === 'POST') {
    const user = requireUser(request, ['admin']); const body = await readJson(request, 64 * 1024);
    return queueMutation(async () => { const state = await readState(); if (Number(body.baseRevision) !== state.revision) return sendJson(response, 409, { error: '中央資料已變更，請重新載入', revision: state.revision }); if (!state.draft) return sendJson(response, 400, { error: '目前沒有可發布的共用草稿' }); state.revision += 1; state.published = structuredClone(state.draft); await addVersion(state, 'published', state.published, user, body.note); audit(state, user, 'publish', body.note); await atomicWrite(statePath, state); return sendJson(response, 200, { ok: true, revision: state.revision, stage: 'published' }); });
  }
  if (pathname === '/api/restore' && request.method === 'POST') {
    const user = requireUser(request, ['admin']); const body = await readJson(request, 64 * 1024);
    return queueMutation(async () => { const state = await readState(); if (Number(body.baseRevision) !== state.revision) return sendJson(response, 409, { error: '中央資料已變更，請重新載入', revision: state.revision }); const metadata = state.versions.find(item => item.id === body.versionId); if (!metadata) return sendJson(response, 404, { error: '找不到指定版本' }); const snapshot = JSON.parse(await fs.readFile(path.join(versionsDir, metadata.id + '.json'), 'utf8')); state.revision += 1; state.draft = validatePayload(snapshot.payload); await addVersion(state, 'draft', state.draft, user, '由第 ' + metadata.revision + ' 版還原'); audit(state, user, 'restore-to-draft', metadata.id); await atomicWrite(statePath, state); return sendJson(response, 200, { ok: true, revision: state.revision, stage: 'draft' }); });
  }
  return sendJson(response, 404, { error: '找不到 API' });
}

const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.webmanifest': 'application/manifest+json; charset=utf-8', '.png': 'image/png', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' };

async function serveStatic(response, pathname) {
  const requested = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
  const target = path.resolve(root, requested);
  if (target !== root && !target.startsWith(root + path.sep)) return sendJson(response, 403, { error: '禁止存取' });
  if (target.startsWith(dataDir + path.sep) || target === dataDir) return sendJson(response, 403, { error: '禁止存取' });
  try {
    const content = await fs.readFile(target); const extension = path.extname(target).toLowerCase();
    response.writeHead(200, { 'Content-Type': mime[extension] || 'application/octet-stream', 'Cache-Control': extension === '.html' ? 'no-store' : 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'" });
    response.end(content);
  } catch (error) { sendJson(response, error.code === 'ENOENT' ? 404 : 500, { error: error.code === 'ENOENT' ? '找不到檔案' : '讀取檔案失敗' }); }
}

await ensureStorage();
const server = http.createServer(async (request, response) => {
  try { const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`); if (url.pathname.startsWith('/api/')) await handleApi(request, response, url.pathname, url); else if (request.method === 'GET' || request.method === 'HEAD') await serveStatic(response, url.pathname); else sendJson(response, 405, { error: '不允許的方法' }); }
  catch (error) { sendJson(response, error.status || 500, { error: error.status ? error.message : '伺服器處理失敗' }); }
});

server.listen(port, host, () => {
  console.log(`北藝大招生中央資料平台：http://${host}:${port}`);
  console.log(`資料目錄：${dataDir}`);
  if (!process.env.TNUA_USERS_JSON && !process.env.TNUA_ADMIN_PASSWORD) console.log(`首次啟動管理者：admin / ${generatedPassword}`);
  if (!process.env.TNUA_SESSION_SECRET) console.log('提醒：本次使用暫時工作階段金鑰；重新啟動後需要重新登入。');
});

