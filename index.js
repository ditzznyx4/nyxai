export const config = { runtime: 'edge' };

const KV_URL          = process.env.KV_REST_API_URL;
const KV_TOKEN        = process.env.KV_REST_API_TOKEN;
const OPENROUTER_KEY  = process.env.OPENROUTER_KEY;
const SESSION_TTL     = 60 * 60 * 24 * 7; // 7 hari (detik)

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const JSON_HEADERS = { 'Content-Type': 'application/json', ...CORS };
const SSE_HEADERS  = {
  'Content-Type':      'text/event-stream',
  'Cache-Control':     'no-cache',
  'Connection':        'keep-alive',
  'X-Accel-Buffering': 'no',
  ...CORS,
};

const ok   = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
const fail = (msg,  status = 400) => new Response(JSON.stringify({ error: msg }), { status, headers: JSON_HEADERS });

async function kvGet(key) {
  const res  = await fetch(`${KV_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN}` },
  });
  const data = await res.json();
  if (!data.result) return null;
  try { return JSON.parse(data.result); } catch { return data.result; }
}

async function kvSet(key, value, exSeconds) {
  const encoded = encodeURIComponent(JSON.stringify(value));
  const url     = exSeconds
    ? `${KV_URL}/set/${encodeURIComponent(key)}/${encoded}?EX=${exSeconds}`
    : `${KV_URL}/set/${encodeURIComponent(key)}/${encoded}`;
  await fetch(url, { headers: { Authorization: `Bearer ${KV_TOKEN}` } });
}

async function kvDel(key) {
  await fetch(`${KV_URL}/del/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN}` },
  });
}

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password, salt) {
  const raw    = new TextEncoder().encode(salt + ':' + password);
  const buf    = await crypto.subtle.digest('SHA-256', raw);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getSession(req) {
  const auth  = req.headers.get('authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  const session = await kvGet(`session:${token}`);
  if (!session) return null;
  return { ...session, token };
}

export default async function handler(req) {
  const url      = new URL(req.url);
  const pathname = url.pathname;
  const method   = req.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  if (pathname === '/api/register' && method === 'POST') {
    try {
      const { username, password } = await req.json();

      if (!username || !password)     return fail('Username dan password wajib diisi.');
      if (username.length < 3)        return fail('Username minimal 3 karakter.');
      if (password.length < 4)        return fail('Password minimal 4 karakter.');
      if (!/^\w+$/.test(username))    return fail('Username hanya boleh huruf, angka, dan underscore.');

      const key      = `user:${username.toLowerCase()}`;
      const existing = await kvGet(key);
      if (existing)  return fail('Username sudah digunakan.', 409);

      const salt         = randomHex(16);
      const passwordHash = await hashPassword(password, salt);

      await kvSet(key, { username, passwordHash, salt, createdAt: Date.now() });

      return ok({ success: true, message: 'Akun berhasil dibuat. Silakan login.' }, 201);
    } catch (err) {
      return fail('Kesalahan server: ' + err.message, 500);
    }
  }

  if (pathname === '/api/login' && method === 'POST') {
    try {
      const { username, password } = await req.json();

      if (!username || !password) return fail('Username dan password wajib diisi.');

      const user = await kvGet(`user:${username.toLowerCase()}`);
      if (!user)  return fail('Username atau password salah.', 401);

      const hash = await hashPassword(password, user.salt);
      if (hash !== user.passwordHash) return fail('Username atau password salah.', 401);

      // Cek session aktif (1 device per akun)
      const activeToken = await kvGet(`active:${username.toLowerCase()}`);
      if (activeToken) {
        const stillValid = await kvGet(`session:${activeToken}`);
        if (stillValid) {
          return fail('Username And Password Already Use', 403);
        }
        // Session lama sudah expired — lanjut login
      }

      const token = randomHex(32);
      await kvSet(`session:${token}`, { username: user.username, createdAt: Date.now() }, SESSION_TTL);
      await kvSet(`active:${username.toLowerCase()}`, token, SESSION_TTL);

      return ok({ success: true, token, username: user.username });
    } catch (err) {
      return fail('Kesalahan server: ' + err.message, 500);
    }
  }

  if (pathname === '/api/logout' && method === 'POST') {
    try {
      const session = await getSession(req);
      if (!session) return fail('Unauthorized.', 401);

      await kvDel(`session:${session.token}`);
      await kvDel(`active:${session.username.toLowerCase()}`);

      return ok({ success: true });
    } catch (err) {
      return fail('Kesalahan server: ' + err.message, 500);
    }
  }

  if (pathname === '/api/verify' && method === 'GET') {
    try {
      const session = await getSession(req);
      if (!session) return fail('Sesi tidak valid. Silakan login ulang.', 401);

      return ok({ valid: true, username: session.username });
    } catch (err) {
      return fail('Kesalahan server: ' + err.message, 500);
    }
  }

  if (pathname === '/api/chat' && method === 'POST') {
    try {
      // Auth
      const session = await getSession(req);
      if (!session) return fail('Unauthorized. Silakan login ulang.', 401);

      // Validate OpenRouter key
      if (!OPENROUTER_KEY || OPENROUTER_KEY.includes('MASUKKAN')) {
        return fail('OPENROUTER_KEY belum diset di Environment Variables Vercel.', 500);
      }

      // Parse body
      const { model, messages, temperature, max_tokens } = await req.json();
      if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return fail('Field messages wajib berupa array dan tidak boleh kosong.');
      }

      // Proxy stream ke OpenRouter
      const upstream = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${OPENROUTER_KEY}`,
          'HTTP-Referer':  'https://nyxai.vercel.app',
          'X-Title':       'NyxAI',
        },
        body: JSON.stringify({
          model:       model       || 'deepseek/deepseek-chat-v3-0324:free',
          messages:    messages.slice(-20),
          stream:      true,
          max_tokens:  max_tokens  || 4096,
          temperature: temperature != null ? temperature : 0.7,
        }),
      });

      if (!upstream.ok || !upstream.body) {
        const errText = await upstream.text().catch(() => '');
        let errMsg = `OpenRouter error HTTP ${upstream.status}`;
        try { errMsg = JSON.parse(errText).error?.message || errMsg; } catch {}
        return fail(errMsg, 502);
      }

      // Forward stream langsung ke client
      return new Response(upstream.body, { status: 200, headers: SSE_HEADERS });

    } catch (err) {
      return fail('Kesalahan server: ' + err.message, 500);
    }
  }

  // ── 404 ───────────────────────────────────────────────────────────────────
  return fail('Endpoint tidak ditemukan.', 404);
}
