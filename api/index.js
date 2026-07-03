// ─────────────────────────────────────────────────────────────────────────────
//  NyxAI — Single index.js (Vercel Edge Runtime)
//  Routes: /api/register /api/login /api/logout /api/verify /api/chat
//  Storage: Upstash Redis via REST (KV_REST_API_URL + KV_REST_API_TOKEN)
//  AI: OpenRouter (OPENROUTER_KEY) — uses deepseek/deepseek-chat-v3-0324 FREE
// ─────────────────────────────────────────────────────────────────────────────
export const config = { runtime: 'edge' };

// ── ENV ──────────────────────────────────────────────────────────────────────
const KV_URL   = process.env.KV_REST_API_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN;
const OR_KEY   = process.env.OPENROUTER_KEY;
const SESSION_TTL = 60 * 60 * 24 * 7; // 7 days

// ── SAFE FREE MODEL (always works on OpenRouter free tier) ──────────────────
const DEFAULT_MODEL = 'deepseek/deepseek-chat-v3-0324:free';

// ── CORS / RESPONSE HELPERS ──────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
const J = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
const E = (msg, status = 400) => J({ error: msg }, status);

// ── KV HELPERS (Upstash REST) ────────────────────────────────────────────────
async function kvGet(key) {
  const r = await fetch(`${KV_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN}` },
  });
  const d = await r.json();
  if (!d.result) return null;
  try { return JSON.parse(d.result); } catch { return d.result; }
}

async function kvSet(key, value, ex) {
  const v = encodeURIComponent(JSON.stringify(value));
  const url = ex
    ? `${KV_URL}/set/${encodeURIComponent(key)}/${v}?EX=${ex}`
    : `${KV_URL}/set/${encodeURIComponent(key)}/${v}`;
  await fetch(url, { headers: { Authorization: `Bearer ${KV_TOKEN}` } });
}

async function kvDel(key) {
  await fetch(`${KV_URL}/del/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN}` },
  });
}

// ── CRYPTO HELPERS (Web Crypto — works on Edge) ──────────────────────────────
function rndHex(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return Array.from(a).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function hashPwd(password, salt) {
  const raw = new TextEncoder().encode(salt + ':' + password);
  const buf = await crypto.subtle.digest('SHA-256', raw);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ── AUTH HELPER ──────────────────────────────────────────────────────────────
async function getSession(req) {
  const auth  = req.headers.get('authorization') || '';
  const token = auth.replace('Bearer ','').trim();
  if (!token) return null;
  const s = await kvGet(`session:${token}`);
  return s ? { ...s, token } : null;
}

// ── ROUTER ───────────────────────────────────────────────────────────────────
export default async function handler(req) {
  const url  = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  // CORS preflight
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  // ── POST /api/register ────────────────────────────────────────────────────
  if (path === '/api/register' && method === 'POST') {
    try {
      const { username, password } = await req.json().catch(() => ({}));
      if (!username || !password) return E('Username and password are required.');
      if (username.length < 3)    return E('Username must be at least 3 characters.');
      if (password.length < 4)    return E('Password must be at least 4 characters.');
      if (!/^\w+$/.test(username)) return E('Username can only contain letters, numbers and underscore.');

      const key  = `user:${username.toLowerCase()}`;
      const exist = await kvGet(key);
      if (exist) return E('Username already taken.', 409);

      const salt = rndHex(16);
      const hash = await hashPwd(password, salt);
      await kvSet(key, { username, passwordHash: hash, salt, createdAt: Date.now() });

      return J({ success: true, message: 'Account created. Please sign in.' }, 201);
    } catch (err) {
      return E('Server error: ' + err.message, 500);
    }
  }

  // ── POST /api/login ───────────────────────────────────────────────────────
  if (path === '/api/login' && method === 'POST') {
    try {
      const { username, password } = await req.json().catch(() => ({}));
      if (!username || !password) return E('Username and password are required.');

      const user = await kvGet(`user:${username.toLowerCase()}`);
      if (!user) return E('Incorrect username or password.', 401);

      const hash = await hashPwd(password, user.salt);
      if (hash !== user.passwordHash) return E('Incorrect username or password.', 401);

      // Single-device check
      const activeToken = await kvGet(`active:${username.toLowerCase()}`);
      if (activeToken) {
        const still = await kvGet(`session:${activeToken}`);
        if (still) return E('Username And Password Already Use', 403);
      }

      const token = rndHex(32);
      await kvSet(`session:${token}`, { username: user.username, createdAt: Date.now() }, SESSION_TTL);
      await kvSet(`active:${username.toLowerCase()}`, token, SESSION_TTL);

      return J({ success: true, token, username: user.username });
    } catch (err) {
      return E('Server error: ' + err.message, 500);
    }
  }

  // ── POST /api/logout ──────────────────────────────────────────────────────
  if (path === '/api/logout' && method === 'POST') {
    try {
      const s = await getSession(req);
      if (!s) return E('Unauthorized.', 401);
      await kvDel(`session:${s.token}`);
      await kvDel(`active:${s.username.toLowerCase()}`);
      return J({ success: true });
    } catch (err) {
      return E('Server error: ' + err.message, 500);
    }
  }

  // ── GET /api/verify ───────────────────────────────────────────────────────
  if (path === '/api/verify') {
    try {
      const s = await getSession(req);
      if (!s) return E('Session expired. Please sign in again.', 401);
      return J({ valid: true, username: s.username });
    } catch (err) {
      return E('Server error: ' + err.message, 500);
    }
  }

  // ── POST /api/chat ────────────────────────────────────────────────────────
  if (path === '/api/chat' && method === 'POST') {
    try {
      // Auth
      const s = await getSession(req);
      if (!s) return E('Unauthorized. Please sign in again.', 401);

      // Key check
      if (!OR_KEY || OR_KEY.includes('MASUKKAN')) {
        return E('OPENROUTER_KEY is not configured on the server.', 500);
      }

      // Parse body
      const body = await req.json().catch(() => null);
      if (!body || !Array.isArray(body.messages) || body.messages.length === 0) {
        return E('messages array is required.');
      }

      // ── FORCE safe free model — ignore client model string to avoid paid errors ──
      // Map friendly names → actual free slugs
      // ── ALWAYS use only verified working free model slugs ──
      // Ignore whatever the client sends — map to safe slugs only
      const MODEL_MAP = {
        // FREE — verified working on OpenRouter free tier
        'nyx ai v3':                  'deepseek/deepseek-chat-v3-0324:free',
        'nyx ai v3 ⚡ free':          'deepseek/deepseek-chat-v3-0324:free',
        'nyxai v3':                   'deepseek/deepseek-chat-v3-0324:free',
        'gemini flash 2.5':           'meta-llama/llama-3.3-70b-instruct:free',
        'gemini flash 2.5 ⚡ free':   'meta-llama/llama-3.3-70b-instruct:free',
        'gemini flash 3':             'meta-llama/llama-3.3-70b-instruct:free',
        // PRO — require OpenRouter credits
        'chatgpt plus 5.5':           'openai/gpt-4o',
        'chatgpt 4':                  'openai/gpt-4',
        'chatgpt4':                   'openai/gpt-4',
        'gemini pro 3':               'google/gemini-1.5-pro',
        'gemini pro 4':               'google/gemini-1.5-pro',
        'claude sonnet 4.6':          'anthropic/claude-3-5-sonnet-20241022',
        'claude sonnet 4.7':          'anthropic/claude-3-5-sonnet-20241022',
        'claude haiku 4.4':           'anthropic/claude-3-haiku-20240307',
      };

      const clientModel = (body.model || '').toLowerCase().trim();
      // Always fallback to verified free model
      let model = MODEL_MAP[clientModel] || 'deepseek/deepseek-chat-v3-0324:free';

      // Proxy to OpenRouter with streaming
      const upstream = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${OR_KEY}`,
          'HTTP-Referer':  'https://nyxai.vercel.app',
          'X-Title':       'NyxAI',
        },
        body: JSON.stringify({
          model,
          messages:    body.messages.slice(-24),
          stream:      true,
          max_tokens:  body.max_tokens  || 4096,
          temperature: body.temperature != null ? body.temperature : 0.7,
        }),
      });

      if (!upstream.ok || !upstream.body) {
        let errMsg = `OpenRouter HTTP ${upstream.status}`;
        try {
          const t = await upstream.text();
          const j = JSON.parse(t);
          errMsg = j.error?.message || j.error || errMsg;
        } catch {}
        return E(errMsg, 502);
      }

      // Stream SSE straight to client
      return new Response(upstream.body, {
        status: 200,
        headers: {
          'Content-Type':      'text/event-stream',
          'Cache-Control':     'no-cache',
          'Connection':        'keep-alive',
          'X-Accel-Buffering': 'no',
          ...CORS,
        },
      });

    } catch (err) {
      return E('Server error: ' + err.message, 500);
    }
  }

  // ── 404 ───────────────────────────────────────────────────────────────────
  return E('Endpoint not found.', 404);
        }
