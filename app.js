// Tiny Nostr client for relay.testls.bit. No deps.
//
// Connects to wss://<this-host>/, subscribes to recent kind:0/1/30023,
// renders a feed.

const RELAY_URL = `wss://${location.host}/`;
const FEED_LIMIT = 200;
const PROFILE_LIMIT = 200;

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const status = $('#status');
const feed = $('#feed');

function setStatus(text, cls = '') {
  status.textContent = text;
  status.className = 'status' + (cls ? ' ' + cls : '');
}

// ─── state ─────────────────────────────────────────────────────────────────
const events = new Map();      // id -> event
const profiles = new Map();    // pubkey -> parsed kind:0 metadata
let activeKindFilter = 'all';
let renderQueued = false;

function queueRender() {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => { renderQueued = false; render(); });
}

// ─── utilities ─────────────────────────────────────────────────────────────
function shortId(s, n = 8) { return s.slice(0, n) + '…'; }

const URL_RE = /https?:\/\/[^\s<>"']+/g;
const IMG_EXT = /\.(png|jpe?g|gif|webp|avif)(\?|#|$)/i;
const VID_EXT = /\.(mp4|webm|mov)(\?|#|$)/i;

function escape(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function linkify(text) {
  return escape(text).replace(URL_RE, (u) => {
    if (IMG_EXT.test(u)) return `<img src="${u}" loading="lazy" alt="">`;
    if (VID_EXT.test(u)) return `<video src="${u}" controls preload="metadata"></video>`;
    return `<a href="${u}" target="_blank" rel="noopener nofollow">${u}</a>`;
  });
}

function fmtDate(ts) {
  const d = new Date(ts * 1000);
  const diff = Date.now() / 1000 - ts;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 7 * 86400) return `${Math.floor(diff / 86400)}d ago`;
  return d.toISOString().slice(0, 10);
}

// crockford-free, just-enough bech32 encoder for npub/nevent/naddr links via njump
function npubFromHex(hex) {
  return bech32Encode('npub', hexToBytes(hex));
}
function neventFromHex(hex) {
  return bech32Encode('nevent', tlv([[0, hexToBytes(hex)]]));
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function tlv(entries) {
  // Build TLV: [type, length, value...]
  let total = 0;
  for (const [, v] of entries) total += 2 + v.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const [t, v] of entries) {
    out[off++] = t; out[off++] = v.length;
    out.set(v, off); off += v.length;
  }
  return out;
}
function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk;
}
function bech32HrpExpand(hrp) {
  const out = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}
function bech32CreateChecksum(hrp, data) {
  const values = bech32HrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0]);
  const polymod = bech32Polymod(values) ^ 1;
  const out = [];
  for (let i = 0; i < 6; i++) out.push((polymod >> (5 * (5 - i))) & 31);
  return out;
}
function convertBits(data, fromBits, toBits, pad) {
  let acc = 0, bits = 0;
  const out = [];
  const maxv = (1 << toBits) - 1;
  for (const v of data) {
    if (v < 0 || (v >> fromBits) !== 0) return null;
    acc = (acc << fromBits) | v;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    return null;
  }
  return out;
}
function bech32Encode(hrp, bytes) {
  const data = convertBits(bytes, 8, 5, true);
  const checksum = bech32CreateChecksum(hrp, data);
  return hrp + '1' + [...data, ...checksum].map(d => BECH32_CHARSET[d]).join('');
}

// ─── relay connection ──────────────────────────────────────────────────────
let ws;
function connect() {
  setStatus('connecting…');
  ws = new WebSocket(RELAY_URL);
  ws.onopen = () => {
    setStatus('connected', 'ok');
    // Profile sub: all kind:0
    ws.send(JSON.stringify(['REQ', 'profiles', { kinds: [0], limit: PROFILE_LIMIT }]));
    // Feed sub: kind:1 + kind:30023, recent
    ws.send(JSON.stringify(['REQ', 'feed', { kinds: [1, 30023], limit: FEED_LIMIT }]));
  };
  ws.onmessage = (m) => {
    let msg;
    try { msg = JSON.parse(m.data); } catch { return; }
    if (msg[0] === 'EVENT') {
      const ev = msg[2];
      if (msg[1] === 'profiles' && ev.kind === 0) {
        try {
          const meta = JSON.parse(ev.content);
          // keep newest kind:0 per pubkey
          const prev = profiles.get(ev.pubkey);
          if (!prev || prev.created_at < ev.created_at) {
            profiles.set(ev.pubkey, { ...meta, created_at: ev.created_at });
          }
        } catch {}
        // also include in events if user picks "profiles" tab
        events.set(ev.id, ev);
      } else {
        events.set(ev.id, ev);
      }
      queueRender();
    } else if (msg[0] === 'EOSE') {
      // End of stored events for this sub. After feed EOSE, hold a live sub.
      if (msg[1] === 'feed') queueRender();
    } else if (msg[0] === 'NOTICE') {
      console.log('NOTICE:', msg[1]);
    } else if (msg[0] === 'CLOSED') {
      console.log('CLOSED:', msg);
    }
  };
  ws.onerror = (e) => {
    console.warn('ws error', e);
    setStatus('connection error', 'err');
  };
  ws.onclose = () => {
    setStatus('disconnected — retrying…', 'err');
    setTimeout(connect, 3000);
  };
}

// ─── render ────────────────────────────────────────────────────────────────
function render() {
  let list = [...events.values()].sort((a, b) => b.created_at - a.created_at);
  if (activeKindFilter !== 'all') {
    if (activeKindFilter === 'other') {
      list = list.filter(e => ![0, 1, 30023].includes(e.kind));
    } else {
      const k = parseInt(activeKindFilter, 10);
      list = list.filter(e => e.kind === k);
    }
  }
  if (list.length === 0) {
    feed.innerHTML = `<div class="empty">No events yet.</div>`;
    return;
  }
  feed.innerHTML = list.slice(0, 300).map(renderEvent).join('');
}

function renderEvent(ev) {
  const profile = profiles.get(ev.pubkey) || {};
  const npub = npubFromHex(ev.pubkey);
  const nevent = neventFromHex(ev.id);
  const name = profile.display_name || profile.name || shortId(npub, 14);
  const nip05 = profile.nip05 ? `<span class="nip05">@${escape(profile.nip05)}</span>` : '';
  const avatar = profile.picture
    ? `<img src="${escape(profile.picture)}" alt="" loading="lazy" referrerpolicy="no-referrer">`
    : '';

  let body;
  if (ev.kind === 0) {
    let m = {};
    try { m = JSON.parse(ev.content); } catch {}
    body = `
      <div class="evt-content">
        <div><strong>${escape(m.display_name || m.name || '')}</strong></div>
        ${m.about ? `<div>${linkify(m.about)}</div>` : ''}
        ${m.nip05 ? `<div>NIP-05: <code>${escape(m.nip05)}</code></div>` : ''}
        ${m.website ? `<div><a href="${escape(m.website)}" target="_blank" rel="noopener">${escape(m.website)}</a></div>` : ''}
      </div>`;
  } else if (ev.kind === 30023) {
    const tag = (k) => (ev.tags.find(t => t[0] === k) || [])[1] || '';
    const title = tag('title');
    const summary = tag('summary');
    const image = tag('image');
    body = `
      ${title ? `<h2 class="evt-title">${escape(title)}</h2>` : ''}
      ${summary ? `<div class="evt-summary">${escape(summary)}</div>` : ''}
      ${image ? `<img src="${escape(image)}" alt="" loading="lazy" referrerpolicy="no-referrer" style="max-height:280px;object-fit:cover;width:100%;border-radius:8px;">` : ''}
      <div class="evt-content">${linkify((ev.content || '').slice(0, 1200))}${ev.content.length > 1200 ? '…' : ''}</div>
    `;
  } else if (ev.kind === 1) {
    body = `<div class="evt-content">${linkify(ev.content || '')}</div>`;
  } else {
    body = `<div class="evt-content"><code>${escape((ev.content || '').slice(0, 600))}</code></div>`;
  }

  return `
    <article class="evt">
      <div class="evt-head">
        <span class="who">${avatar}${escape(name)}</span>
        ${nip05}
        <span class="kind">kind&nbsp;${ev.kind}</span>
        <span>· ${fmtDate(ev.created_at)}</span>
      </div>
      ${body}
      <div class="evt-foot">
        <a href="https://njump.me/${nevent}" target="_blank" rel="noopener">njump</a>
        <a href="https://nostr.com/${npub}" target="_blank" rel="noopener">author</a>
        <span class="id">${shortId(ev.id, 12)}</span>
      </div>
    </article>
  `;
}

// ─── tabs ──────────────────────────────────────────────────────────────────
$$('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    $$('.tab').forEach(b => b.classList.toggle('active', b === btn));
    activeKindFilter = btn.dataset.kind;
    render();
  });
});

// ─── nip-11 link ───────────────────────────────────────────────────────────
$('#nip11-link').addEventListener('click', async (e) => {
  e.preventDefault();
  try {
    const r = await fetch('/', { headers: { Accept: 'application/nostr+json' } });
    const j = await r.json();
    alert(JSON.stringify(j, null, 2));
  } catch (err) {
    alert('Failed: ' + err.message);
  }
});

// ─── start ─────────────────────────────────────────────────────────────────
feed.innerHTML = `<div class="loading">Connecting to ${RELAY_URL} …</div>`;
connect();
