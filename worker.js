/**
 * BELUGA RU — secure admin API for Cloudflare Workers.
 * Secrets expected: ADMIN_PASSWORD, SESSION_SECRET, JSONBIN_MASTER_KEY.
 * Variables expected: JSONBIN_BIN_ID, ALLOWED_ORIGIN.
 * KV binding expected: AUTH_KV.
 */
const encoder = new TextEncoder();
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const PASSWORD_ITERATIONS = 310000;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers }
  });
}
function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function fromBase64url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(normalized);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
function constantTimeEqual(a, b) {
  const aa = encoder.encode(String(a));
  const bb = encoder.encode(String(b));
  let diff = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);
  for (let i = 0; i < length; i++) diff |= (aa[i % (aa.length || 1)] || 0) ^ (bb[i % (bb.length || 1)] || 0);
  return diff === 0;
}
async function hmac(message, secret) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(message)));
}
async function makeToken(secret) {
  const payload = base64url(encoder.encode(JSON.stringify({ sub: 'beluga-admin', exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS })));
  const signature = base64url(await hmac(payload, secret));
  return `${payload}.${signature}`;
}
async function verifyToken(request, env) {
  const header = request.headers.get('Authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const parts = token.split('.');
  if (parts.length !== 2 || !env.SESSION_SECRET) return false;
  const expected = base64url(await hmac(parts[0], env.SESSION_SECRET));
  if (!constantTimeEqual(expected, parts[1])) return false;
  try {
    const payload = JSON.parse(new TextDecoder().decode(fromBase64url(parts[0])));
    return payload.sub === 'beluga-admin' && Number(payload.exp) > Math.floor(Date.now() / 1000);
  } catch { return false; }
}
async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PASSWORD_ITERATIONS, hash: 'SHA-256' }, key, 256);
  return base64url(new Uint8Array(bits));
}
async function verifyPassword(password, env) {
  if (env.AUTH_KV) {
    const saved = await env.AUTH_KV.get('admin-password-v1', 'json');
    if (saved?.salt && saved?.hash) {
      const candidate = await hashPassword(password, fromBase64url(saved.salt));
      return constantTimeEqual(candidate, saved.hash);
    }
  }
  if (!env.ADMIN_PASSWORD) return false;
  const [a, b] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(password)),
    crypto.subtle.digest('SHA-256', encoder.encode(env.ADMIN_PASSWORD))
  ]);
  return constantTimeEqual(base64url(new Uint8Array(a)), base64url(new Uint8Array(b)));
}
async function savePassword(password, env) {
  if (!env.AUTH_KV) throw new Error('На сервере не подключено хранилище AUTH_KV. Создай KV namespace по инструкции.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);
  await env.AUTH_KV.put('admin-password-v1', JSON.stringify({ salt: base64url(salt), hash, iterations: PASSWORD_ITERATIONS }));
}
function corsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = env.ALLOWED_ORIGIN || '*';
  const allowOrigin = allowed === '*' ? '*' : (origin === allowed ? origin : 'null');
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
async function checkLoginLimit(request, env) {
  if (!env.AUTH_KV) return { allowed: true };
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const key = `login-attempts:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const state = await env.AUTH_KV.get(key, 'json') || { count: 0, resetAt: now + 600 };
  if (state.resetAt <= now) return { allowed: true, key };
  return { allowed: state.count < 6, key, retryAfter: Math.max(1, state.resetAt - now), state };
}
async function recordLoginFailure(env, limit) {
  if (!env.AUTH_KV || !limit.key) return;
  const now = Math.floor(Date.now() / 1000);
  const state = limit.state && limit.state.resetAt > now ? limit.state : { count: 0, resetAt: now + 600 };
  state.count += 1;
  await env.AUTH_KV.put(limit.key, JSON.stringify(state), { expirationTtl: Math.max(60, state.resetAt - now) });
}
async function clearLoginFailures(env, limit) {
  if (env.AUTH_KV && limit.key) await env.AUTH_KV.delete(limit.key);
}
function stripPrivateFields(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  const safe = { ...record };
  for (const key of ['adminPass', 'password', 'passwordHash', 'apiKey', 'masterKey', 'token', 'secret', 'sessionToken']) delete safe[key];
  return safe;
}
async function jsonbinRequest(env, method, body) {
  if (!env.JSONBIN_MASTER_KEY || !env.JSONBIN_BIN_ID) throw new Error('Не настроены JSONBIN_MASTER_KEY или JSONBIN_BIN_ID.');
  const url = `https://api.jsonbin.io/v3/b/${encodeURIComponent(env.JSONBIN_BIN_ID)}${method === 'GET' ? '/latest' : ''}`;
  const response = await fetch(url, {
    method,
    headers: { 'X-Master-Key': env.JSONBIN_MASTER_KEY, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
  const result = await response.json().catch(() => ({}));
  if (response.status === 404 && method === 'GET') return { record: null };
  if (!response.ok) throw new Error(result.message || `JSONBin вернул ошибку ${response.status}.`);
  return result;
}
export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    const url = new URL(request.url);
    if (env.ALLOWED_ORIGIN && env.ALLOWED_ORIGIN !== '*' && request.headers.get('Origin') && request.headers.get('Origin') !== env.ALLOWED_ORIGIN) {
      return json({ error: 'Origin не разрешён.' }, 403, cors);
    }
    try {
      if (url.pathname === '/api/health' && request.method === 'GET') return json({ ok: true, service: 'beluga-ru-admin-api' }, 200, cors);

      if (url.pathname === '/api/login' && request.method === 'POST') {
        if (!env.SESSION_SECRET || !env.ADMIN_PASSWORD && !env.AUTH_KV) return json({ error: 'Администратор ещё не настроен на сервере.' }, 503, cors);
        const body = await request.json();
        const password = typeof body.password === 'string' ? body.password : '';
        const limit = await checkLoginLimit(request, env);
        if (!limit.allowed) return json({ error: 'Слишком много попыток. Попробуй позже.' }, 429, { ...cors, 'Retry-After': String(limit.retryAfter || 600) });
        if (password.length > 256 || !(await verifyPassword(password, env))) {
          await recordLoginFailure(env, limit);
          return json({ error: 'Неверный пароль.' }, 401, cors);
        }
        await clearLoginFailures(env, limit);
        return json({ token: await makeToken(env.SESSION_SECRET), expiresIn: SESSION_TTL_SECONDS }, 200, cors);
      }

      if (url.pathname === '/api/config' && request.method === 'GET') {
        const result = await jsonbinRequest(env, 'GET');
        return json({ record: stripPrivateFields(result.record) }, 200, cors);
      }

      if (!(await verifyToken(request, env))) return json({ error: 'Сеанс истёк или нет доступа. Войди в админ-панель заново.' }, 401, cors);

      if (url.pathname === '/api/config' && request.method === 'PUT') {
        const body = await request.json();
        const record = body.record;
        if (!record || typeof record !== 'object' || Array.isArray(record)) return json({ error: 'Некорректные настройки.' }, 400, cors);
        const serialized = JSON.stringify(record);
        if (serialized.length > 250000) return json({ error: 'Настройки слишком большие (максимум 250 КБ).' }, 413, cors);
        const result = await jsonbinRequest(env, 'PUT', record);
        return json({ ok: true, version: result.metadata?.version ?? null }, 200, cors);
      }

      if (url.pathname === '/api/change-password' && request.method === 'POST') {
        const body = await request.json();
        const currentPassword = typeof body.currentPassword === 'string' ? body.currentPassword : '';
        const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';
        if (!(await verifyPassword(currentPassword, env))) return json({ error: 'Текущий пароль указан неверно.' }, 401, cors);
        if (newPassword.length < 12 || newPassword.length > 256) return json({ error: 'Новый пароль должен содержать от 12 до 256 символов.' }, 400, cors);
        await savePassword(newPassword, env);
        return json({ ok: true }, 200, cors);
      }

      return json({ error: 'Маршрут не найден.' }, 404, cors);
    } catch (error) {
      return json({ error: error.message || 'Внутренняя ошибка сервера.' }, 500, cors);
    }
  }
};
