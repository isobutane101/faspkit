import { FaspConfig } from "./config.js";

/**
 * The dashboard markup.
 *
 * Kept as template strings rather than a framework and a build step: the whole
 * point of this file is that `npx faspkit` needs no install beyond itself.
 * There are no external assets, so it works offline and behind a firewall.
 */

const escape = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

const STYLE = `
:root {
  color-scheme: light dark;
  --bg: #fbfbfd; --panel: #fff; --ink: #16161a; --muted: #6b6b76;
  --line: #e4e4ea; --accent: #4c4ddc; --ok: #157f4a; --warn: #9a6700; --bad: #b42318;
  --okbg: #e7f6ee; --warnbg: #fdf5e2; --badbg: #fdeceb;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #131317; --panel: #1b1b21; --ink: #ececf1; --muted: #9a9aa6;
    --line: #2c2c35; --accent: #9c9dfb; --ok: #6ee7a8; --warn: #f0c674; --bad: #ff9b91;
    --okbg: #14301f; --warnbg: #322a12; --badbg: #35191a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
a { color: var(--accent); }
header {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  padding: 18px 24px; border-bottom: 1px solid var(--line); background: var(--panel);
}
header h1 { font-size: 17px; margin: 0; font-weight: 650; }
header .url { color: var(--muted); font-size: 13px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
header .spacer { flex: 1; }
main { max-width: 1000px; margin: 0 auto; padding: 24px; }
.tabs { display: flex; gap: 4px; margin-bottom: 20px; flex-wrap: wrap; }
.tabs button {
  padding: 7px 14px; border: 1px solid var(--line); background: var(--panel); color: var(--ink);
  border-radius: 999px; cursor: pointer; font-size: 14px;
}
.tabs button[aria-selected="true"] { background: var(--accent); border-color: var(--accent); color: #fff; }
.panel {
  background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: 20px; margin-bottom: 16px;
}
.panel h2 { margin: 0 0 4px; font-size: 15px; font-weight: 650; }
.panel p.hint { margin: 0 0 16px; color: var(--muted); font-size: 13px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
.stat { border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.stat .n { font-size: 24px; font-weight: 650; font-variant-numeric: tabular-nums; }
.stat .k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; }
input[type=text], input[type=password], select {
  width: 100%; padding: 9px 11px; border: 1px solid var(--line); border-radius: 8px;
  background: var(--bg); color: var(--ink); font-size: 14px;
}
button.action {
  padding: 9px 16px; border-radius: 8px; border: 1px solid var(--accent);
  background: var(--accent); color: #fff; font-size: 14px; cursor: pointer; font-weight: 600;
}
button.action.ghost { background: transparent; color: var(--accent); }
button.action:disabled { opacity: .55; cursor: progress; }
.row { display: flex; gap: 10px; align-items: flex-end; flex-wrap: wrap; }
.row > div { flex: 1; min-width: 220px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 9px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; }
.pill { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px; font-weight: 600; }
.pill.ok { background: var(--okbg); color: var(--ok); }
.pill.warn { background: var(--warnbg); color: var(--warn); }
.note { border-radius: 10px; padding: 14px 16px; font-size: 14px; margin-top: 14px; }
.note.ok { background: var(--okbg); color: var(--ok); }
.note.bad { background: var(--badbg); color: var(--bad); }
.note.warn { background: var(--warnbg); color: var(--warn); }
.note ol { margin: 8px 0 0; padding-left: 20px; }
.fingerprint {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 15px; font-weight: 700;
  word-break: break-all; display: block; margin: 8px 0; padding: 10px 12px;
  background: var(--bg); border: 1px solid var(--line); border-radius: 8px;
}
.empty { color: var(--muted); font-size: 14px; padding: 8px 0; }
ul.plain { list-style: none; padding: 0; margin: 0; }
ul.plain li { padding: 7px 0; border-bottom: 1px solid var(--line); }
ul.plain li:last-child { border-bottom: 0; }
.hidden { display: none; }
.login { max-width: 380px; margin: 12vh auto; }
`;

export function loginPage(name: string, error?: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(name)} — sign in</title><style>${STYLE}</style></head><body>
<main class="login">
  <div class="panel">
    <h2>${escape(name)}</h2>
    <p class="hint">Enter the admin token. It was printed to the console when this FASP started.</p>
    <form method="post" action="/admin/login">
      <label for="token">Admin token</label>
      <input id="token" name="token" type="password" autocomplete="current-password" autofocus>
      <div style="margin-top:14px"><button class="action" type="submit">Sign in</button></div>
    </form>
    ${error ? `<div class="note bad">${escape(error)}</div>` : ""}
  </div>
</main></body></html>`;
}

export function adminPage(config: FaspConfig): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(config.name)} — FASP admin</title><style>${STYLE}</style></head><body>
<header>
  <h1>${escape(config.name)}</h1>
  <span class="url">${escape(config.baseUrl)}</span>
  <span class="spacer"></span>
  <form method="post" action="/admin/logout"><button class="action ghost" type="submit">Sign out</button></form>
</header>
<main>
  <div class="tabs" role="tablist">
    <button role="tab" data-tab="overview" aria-selected="true">Overview</button>
    <button role="tab" data-tab="connect" aria-selected="false">Connect a server</button>
    <button role="tab" data-tab="explore" aria-selected="false">Explore</button>
  </div>

  <section id="tab-overview">
    <div class="panel">
      <h2>Status</h2>
      <p class="hint">What this FASP has collected so far.</p>
      <div class="stats" id="stats"></div>
    </div>
    <div class="panel">
      <h2>Connected servers</h2>
      <p class="hint">A server stays <em>pending</em> until its admin approves the registration.</p>
      <div id="servers"></div>
    </div>
    <div class="panel">
      <h2>Capabilities offered</h2>
      <p class="hint">Servers read these from <code>/provider_info</code> and choose which to enable.</p>
      <div id="capabilities"></div>
    </div>
  </section>

  <section id="tab-connect" class="hidden">
    <div class="panel">
      <h2>Connect to a fediverse server</h2>
      <p class="hint">
        Enter the server's address. This FASP will introduce itself and give you a fingerprint
        to compare in that server's admin interface.
      </p>
      <div class="row">
        <div>
          <label for="serverUrl">Server address</label>
          <input id="serverUrl" type="text" placeholder="mastodon.example.com" autocomplete="off">
        </div>
        <button class="action" id="connectBtn">Connect</button>
      </div>
      <div id="connectResult"></div>
    </div>
  </section>

  <section id="tab-explore" class="hidden">
    <div class="panel">
      <h2>Try a search</h2>
      <p class="hint">Exactly what a fediverse server would get from <code>account_search</code>.</p>
      <div class="row">
        <div>
          <label for="searchTerm">Search term</label>
          <input id="searchTerm" type="text" placeholder="alice" autocomplete="off">
        </div>
        <button class="action" id="searchBtn">Search</button>
      </div>
      <div id="searchResult"></div>
    </div>
    <div class="panel">
      <h2>Current trends</h2>
      <p class="hint">What this FASP would answer for <code>trends</code> right now.</p>
      <div id="trends"></div>
    </div>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function api(path, options) {
  const res = await fetch(path, { headers: { 'content-type': 'application/json' }, ...options });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
  return body;
}

document.querySelectorAll('[role=tab]').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('[role=tab]').forEach((b) => b.setAttribute('aria-selected', String(b === btn)));
    ['overview', 'connect', 'explore'].forEach((t) => $('tab-' + t).classList.toggle('hidden', t !== btn.dataset.tab));
    if (btn.dataset.tab === 'explore') loadTrends();
  });
});

const STAT_LABELS = {
  servers: 'Servers', active: 'Active', indexed: 'Indexed', seen: 'URIs seen',
  content: 'Posts', accounts: 'Accounts',
};

async function refresh() {
  let status;
  try {
    status = await api('/admin/api/status');
  } catch (err) {
    $('stats').innerHTML = '<div class="note bad">' + esc(err.message) + '</div>';
    return;
  }

  $('stats').innerHTML = Object.entries(STAT_LABELS)
    .filter(([k]) => status.counts[k] !== undefined)
    .map(([k, label]) => '<div class="stat"><div class="n">' + status.counts[k] + '</div><div class="k">' + label + '</div></div>')
    .join('');

  $('capabilities').innerHTML = '<ul class="plain">' + status.capabilities
    .map((c) => '<li><code>' + esc(c.id) + '</code> <span class="pill ok">v' + esc(c.version) + '</span></li>').join('') + '</ul>';

  $('servers').innerHTML = status.servers.length === 0
    ? '<p class="empty">No servers yet. Use <strong>Connect a server</strong> to add one.</p>'
    : '<table><thead><tr><th>Server</th><th>Status</th><th>Fingerprint</th><th></th></tr></thead><tbody>' +
      status.servers.map((s) =>
        '<tr><td>' + esc(s.serverUrl) + '</td>' +
        '<td><span class="pill ' + (s.status === 'active' ? 'ok' : 'warn') + '">' + esc(s.status) + '</span></td>' +
        '<td class="mono">' + esc(s.fingerprint.slice(0, 16)) + '…</td>' +
        '<td><button class="action ghost" data-backfill="' + esc(s.serverId) + '">Backfill</button> ' +
        '<button class="action ghost" data-subscribe="' + esc(s.serverId) + '">Subscribe</button></td></tr>').join('') +
      '</tbody></table><div id="serverAction"></div>';

  document.querySelectorAll('[data-backfill]').forEach((b) => b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      const r = await api('/admin/api/servers/' + b.dataset.backfill + '/backfill', {
        method: 'POST', body: JSON.stringify({ category: 'content', maxCount: 100 }) });
      $('serverAction').innerHTML = '<div class="note ok">Backfill requested (id ' + esc(r.backfillRequestId) +
        '). Content arrives in the background.</div>';
    } catch (err) { $('serverAction').innerHTML = '<div class="note bad">' + esc(err.message) + '</div>'; }
    b.disabled = false;
  }));

  document.querySelectorAll('[data-subscribe]').forEach((b) => b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      const r = await api('/admin/api/servers/' + b.dataset.subscribe + '/subscribe', {
        method: 'POST', body: JSON.stringify({ category: 'content', subscriptionType: 'lifecycle' }) });
      $('serverAction').innerHTML = '<div class="note ok">Subscribed (id ' + esc(r.subscriptionId) +
        '). New posts will be announced to this FASP.</div>';
    } catch (err) { $('serverAction').innerHTML = '<div class="note bad">' + esc(err.message) + '</div>'; }
    b.disabled = false;
  }));
}

$('connectBtn').addEventListener('click', async () => {
  const btn = $('connectBtn');
  const url = $('serverUrl').value.trim();
  if (!url) return;
  btn.disabled = true;
  $('connectResult').innerHTML = '<p class="empty">Contacting ' + esc(url) + '…</p>';
  try {
    const r = await api('/admin/api/connect', { method: 'POST', body: JSON.stringify({ serverUrl: url }) });
    $('connectResult').innerHTML =
      '<div class="note ok"><strong>Introduced.</strong> Now approve it on the other side.' +
      '<ol><li>Open <a href="' + esc(r.registrationCompletionUri) + '" target="_blank" rel="noreferrer">' +
      esc(r.registrationCompletionUri) + '</a></li>' +
      '<li>Check that the fingerprint shown there matches this one exactly:' +
      '<code class="fingerprint">' + esc(r.fingerprint) + '</code></li>' +
      '<li>Approve the registration, then choose which capabilities to enable.</li></ol></div>';
    refresh();
  } catch (err) {
    $('connectResult').innerHTML = '<div class="note bad"><strong>Could not connect.</strong> ' + esc(err.message) +
      '<br><br>Check that the address is right and that the server runs Mastodon 4.4+ with FASP enabled.</div>';
  }
  btn.disabled = false;
});

$('searchBtn').addEventListener('click', async () => {
  const term = $('searchTerm').value.trim();
  if (!term) return;
  try {
    const r = await api('/admin/api/preview/search?term=' + encodeURIComponent(term));
    $('searchResult').innerHTML = r.uris.length
      ? '<ul class="plain">' + r.uris.map((u) => '<li class="mono">' + esc(u) + '</li>').join('') + '</ul>'
      : '<p class="empty">No matches. This FASP only knows about content servers have shared with it.</p>';
  } catch (err) { $('searchResult').innerHTML = '<div class="note bad">' + esc(err.message) + '</div>'; }
});

async function loadTrends() {
  try {
    const r = await api('/admin/api/preview/trends');
    const section = (title, items, render) => '<h2 style="margin-top:18px">' + title + '</h2>' + (items.length
      ? '<ul class="plain">' + items.map(render).join('') + '</ul>'
      : '<p class="empty">Nothing yet.</p>');
    $('trends').innerHTML =
      section('Hashtags', r.hashtags, (h) => '<li><strong>' + esc(h.name) + '</strong> <span class="pill ok">rank ' + h.rank + '</span></li>') +
      section('Links', r.links, (l) => '<li class="mono">' + esc(l.url) + ' <span class="pill ok">rank ' + l.rank + '</span></li>') +
      section('Posts', r.content, (c) => '<li class="mono">' + esc(c.uri) + '</li>');
  } catch (err) { $('trends').innerHTML = '<div class="note bad">' + esc(err.message) + '</div>'; }
}

refresh();
setInterval(refresh, 10000);
</script>
</body></html>`;
}
