// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/chat
//  Edge Runtime — supaya streaming SSE jalan mulus di Vercel
// ─────────────────────────────────────────────────────────────────────────────
export const config = { runtime: 'edge' };

export default async function handler(req) {
  const corsHeaders = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405, headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // ── AUTH CHECK (via Upstash REST API, karena Edge Runtime tidak bisa pakai TCP client biasa) ──
  const authHeader = req.headers.get('authorization') || '';
  const token = authHeader.replace('Bearer ', '').trim();

  if (!token) {
    return new Response(JSON.stringify({ error: 'Unauthorized. Silakan login ulang.' }), {
      status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const KV_URL   = process.env.KV_REST_API_URL;
  const KV_TOKEN = process.env.KV_REST_API_TOKEN;

  try {
    const sessionRes = await fetch(`${KV_URL}/get/${encodeURIComponent('session:' + token)}`, {
      headers: { Authorization: `Bearer ${KV_TOKEN}` },
    });
    const sessionData = await sessionRes.json();

    if (!sessionData.result) {
      return new Response(JSON.stringify({ error: 'Sesi tidak valid. Silakan login ulang.' }), {
        status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  } catch (err) {
    return new Response(JSON.stringify({ error: 'Gagal verifikasi sesi: ' + err.message }), {
      status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // ── PARSE BODY ──
  let body;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Body request tidak valid.' }), {
      status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const { model, messages, temperature, max_tokens } = body;

  if (!messages || !Array.isArray(messages)) {
    return new Response(JSON.stringify({ error: 'Field messages wajib berupa array.' }), {
      status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  const OPENROUTER_KEY = process.env.OPENROUTER_KEY;

  if (!OPENROUTER_KEY) {
    return new Response(JSON.stringify({ error: 'OPENROUTER_KEY belum diset di Environment Variables Vercel.' }), {
      status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }

  // ── PROXY KE OPENROUTER (streaming) ──
  try {
    const upstream = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${OPENROUTER_KEY}`,
        'HTTP-Referer':  'https://nyxai.vercel.app',
        'X-Title':       'NyxAI',
      },
      body: JSON.stringify({
        model:       model || 'deepseek/deepseek-chat-v3-0324:free',
        messages,
        stream:      true,
        max_tokens:  max_tokens  || 4096,
        temperature: temperature != null ? temperature : 0.7,
      }),
    });

    if (!upstream.ok || !upstream.body) {
      const errText = await upstream.text().catch(() => 'Unknown error');
      let errMsg = `HTTP ${upstream.status}`;
      try { errMsg = JSON.parse(errText).error?.message || errMsg; } catch {}
      return new Response(JSON.stringify({ error: errMsg }), {
        status: upstream.status || 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    // Forward stream langsung ke client (Edge Runtime support ReadableStream native)
    return new Response(upstream.body, {
      status: 200,
      headers: {
        'Content-Type':      'text/event-stream',
        'Cache-Control':     'no-cache',
        'Connection':        'keep-alive',
        'X-Accel-Buffering': 'no',
        ...corsHeaders,
      },
    });

  } catch (err) {
    return new Response(JSON.stringify({ error: 'Gagal terhubung ke OpenRouter: ' + err.message }), {
      status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
    }
