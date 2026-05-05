// Tiny Nostr client for relay.testls.bit. No deps.
//
// Connects to wss://<this-host>/, subscribes to recent kind:0/1/30023,
// renders a feed. Click a profile to open a profile view that subscribes
// to all events from that pubkey. Search bar resolves a `.bit` NIP-05
// (or npub/hex) to a profile.

const RELAY_URL = `wss://${location.host}/`;
const FEED_LIMIT = 200;
const PROFILE_LIMIT = 200;
const AUTHOR_LIMIT = 500;
const SEARCH_FETCH_MS = 4000;
const EVENT_FETCH_MS = 4000;

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const status = $('#status');
const feed = $('#feed');
const profileView = $('#profile-view');
const tabsEl = $('#tabs');
const searchForm = $('#search-form');
const searchInput = $('#search-input');

function setStatus(text, cls = '') {
  status.textContent = text;
  status.className = 'status' + (cls ? ' ' + cls : '');
}

// ─── state ─────────────────────────────────────────────────────────────────
const events = new Map();         // id -> event (global feed events)
const profiles = new Map();       // pubkey -> parsed kind:0 metadata (+ created_at)
const authorEvents = new Map();   // id -> event (currently-viewed author's events)
const eventCache = new Map();     // id -> event (anything we've ever seen)
let activeKindFilter = 'all';
let renderQueued = false;
let view = { kind: 'feed', pubkey: null, eventId: null }; // 'feed' | 'profile' | 'event'
let activeAuthorSubId = null;
let authorReqCounter = 0;
let activeEventSubId = null;
let eventReqCounter = 0;

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
const HEX64 = /^[0-9a-f]{64}$/i;

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text).then(() => true, () => fallbackCopy(text));
  }
  return Promise.resolve(fallbackCopy(text));
}
function fallbackCopy(text) {
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand && document.execCommand('copy');
    document.body.removeChild(ta);
    return !!ok;
  } catch { return false; }
}
function flashCopied(el, label = 'copied!') {
  if (!el) return;
  const prev = el.dataset.flashPrev || el.textContent;
  el.dataset.flashPrev = prev;
  el.textContent = label;
  el.classList.add('copied');
  clearTimeout(el._flashTimer);
  el._flashTimer = setTimeout(() => {
    el.textContent = el.dataset.flashPrev;
    el.classList.remove('copied');
  }, 1100);
}

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

// ─── bech32 (encode + decode) ──────────────────────────────────────────────
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_INV = (() => {
  const m = new Map();
  for (let i = 0; i < BECH32_CHARSET.length; i++) m.set(BECH32_CHARSET[i], i);
  return m;
})();

function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(b) {
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}

function tlv(entries) {
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
function bech32VerifyChecksum(hrp, data) {
  return bech32Polymod(bech32HrpExpand(hrp).concat(data)) === 1;
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
function bech32Decode(str) {
  if (!str || typeof str !== 'string') return null;
  const s = str.toLowerCase();
  // basic format checks
  if (/[A-Z]/.test(str) && /[a-z]/.test(str)) return null;
  const sep = s.lastIndexOf('1');
  if (sep < 1 || sep + 7 > s.length) return null;
  const hrp = s.slice(0, sep);
  const data = [];
  for (let i = sep + 1; i < s.length; i++) {
    const v = BECH32_INV.get(s[i]);
    if (v === undefined) return null;
    data.push(v);
  }
  if (!bech32VerifyChecksum(hrp, data)) return null;
  const payload = data.slice(0, -6);
  const bytes = convertBits(payload, 5, 8, false);
  if (!bytes) return null;
  return { hrp, bytes: new Uint8Array(bytes) };
}

function npubFromHex(hex) {
  return bech32Encode('npub', hexToBytes(hex));
}
function neventFromHex(hex) {
  return bech32Encode('nevent', tlv([[0, hexToBytes(hex)]]));
}
function noteFromHex(hex) {
  return bech32Encode('note', hexToBytes(hex));
}
function eventIdFromAny(input) {
  // Accepts: 64-char hex, note1..., nevent1...
  const s = (input || '').trim();
  if (HEX64.test(s)) return s.toLowerCase();
  const dec = bech32Decode(s);
  if (!dec) return null;
  if (dec.hrp === 'note') {
    return dec.bytes.length === 32 ? bytesToHex(dec.bytes) : null;
  }
  if (dec.hrp === 'nevent') {
    const b = dec.bytes;
    let off = 0;
    while (off + 2 <= b.length) {
      const t = b[off++], len = b[off++];
      if (off + len > b.length) return null;
      const val = b.slice(off, off + len);
      off += len;
      if (t === 0 && val.length === 32) return bytesToHex(val);
    }
    return null;
  }
  return null;
}
function pubkeyFromAny(input) {
  // Accepts: hex pubkey, npub1..., nprofile1...
  const s = input.trim();
  if (HEX64.test(s)) return s.toLowerCase();
  const dec = bech32Decode(s);
  if (!dec) return null;
  if (dec.hrp === 'npub') {
    return dec.bytes.length === 32 ? bytesToHex(dec.bytes) : null;
  }
  if (dec.hrp === 'nprofile') {
    // TLV; type 0 = pubkey
    const b = dec.bytes;
    let off = 0;
    while (off + 2 <= b.length) {
      const t = b[off++], len = b[off++];
      if (off + len > b.length) return null;
      const val = b.slice(off, off + len);
      off += len;
      if (t === 0 && val.length === 32) return bytesToHex(val);
    }
    return null;
  }
  return null;
}

// ─── relay connection ──────────────────────────────────────────────────────
let ws;
let wsReady = false;
const pendingSends = [];

function wsSend(payload) {
  const msg = JSON.stringify(payload);
  if (wsReady && ws.readyState === WebSocket.OPEN) ws.send(msg);
  else pendingSends.push(msg);
}

function connect() {
  setStatus('connecting…');
  ws = new WebSocket(RELAY_URL);
  ws.onopen = () => {
    wsReady = true;
    setStatus('connected', 'ok');
    // Profile sub: all kind:0
    ws.send(JSON.stringify(['REQ', 'profiles', { kinds: [0], limit: PROFILE_LIMIT }]));
    // Feed sub: kind:1 + kind:30023, recent
    ws.send(JSON.stringify(['REQ', 'feed', { kinds: [1, 30023], limit: FEED_LIMIT }]));
    // flush queued sends (e.g. author sub from a deep link)
    while (pendingSends.length) ws.send(pendingSends.shift());
  };
  ws.onmessage = (m) => {
    let msg;
    try { msg = JSON.parse(m.data); } catch { return; }
    if (msg[0] === 'EVENT') {
      const subId = msg[1];
      const ev = msg[2];
      // Always cache by id so /e/<id> can find it without refetching.
      eventCache.set(ev.id, ev);
      if (subId === 'profiles' && ev.kind === 0) {
        try {
          const meta = JSON.parse(ev.content);
          const prev = profiles.get(ev.pubkey);
          if (!prev || prev.created_at < ev.created_at) {
            profiles.set(ev.pubkey, { ...meta, created_at: ev.created_at });
          }
        } catch {}
        events.set(ev.id, ev);
      } else if (subId && subId.startsWith('author:')) {
        if (ev.kind === 0) {
          try {
            const meta = JSON.parse(ev.content);
            const prev = profiles.get(ev.pubkey);
            if (!prev || prev.created_at < ev.created_at) {
              profiles.set(ev.pubkey, { ...meta, created_at: ev.created_at });
            }
          } catch {}
        }
        if (subId === activeAuthorSubId) authorEvents.set(ev.id, ev);
      } else if (subId && subId.startsWith('event:')) {
        // single-event lookup; also harvest kind:0 if it's the author profile
        if (ev.kind === 0) {
          try {
            const meta = JSON.parse(ev.content);
            const prev = profiles.get(ev.pubkey);
            if (!prev || prev.created_at < ev.created_at) {
              profiles.set(ev.pubkey, { ...meta, created_at: ev.created_at });
            }
          } catch {}
        }
      } else {
        events.set(ev.id, ev);
      }
      queueRender();
    } else if (msg[0] === 'EOSE') {
      if (msg[1] === 'feed') queueRender();
      if (msg[1] === activeAuthorSubId) queueRender();
      if (msg[1] === activeEventSubId) queueRender();
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
    wsReady = false;
    setStatus('disconnected — retrying…', 'err');
    setTimeout(connect, 3000);
  };
}

// ─── routing ───────────────────────────────────────────────────────────────
function parseHash() {
  const h = location.hash || '';
  let m;
  // #/p/<npub-or-hex>
  if ((m = h.match(/^#\/p\/([a-z0-9]+)$/i))) {
    const pk = pubkeyFromAny(m[1]);
    if (pk) return { kind: 'profile', pubkey: pk, eventId: null };
  }
  // #/e/<nevent-note-or-hex>
  if ((m = h.match(/^#\/e\/([a-z0-9]+)$/i))) {
    const id = eventIdFromAny(m[1]);
    if (id) return { kind: 'event', pubkey: null, eventId: id };
  }
  return { kind: 'feed', pubkey: null, eventId: null };
}

function gotoProfileByPubkey(pk) {
  const npub = npubFromHex(pk);
  location.hash = `#/p/${npub}`;
}
function gotoEventById(id) {
  const nevent = neventFromHex(id);
  location.hash = `#/e/${nevent}`;
}
function gotoFeed() {
  if (location.hash && location.hash !== '#/') location.hash = '#/';
  else applyRoute();
}

function tearDownAuthorSub() {
  if (activeAuthorSubId) {
    try { wsSend(['CLOSE', activeAuthorSubId]); } catch {}
    activeAuthorSubId = null;
  }
  authorEvents.clear();
}
function tearDownEventSub() {
  if (activeEventSubId) {
    try { wsSend(['CLOSE', activeEventSubId]); } catch {}
    activeEventSubId = null;
  }
}

function applyRoute() {
  const next = parseHash();
  // Tear down stale subs when leaving or switching
  if (view.kind === 'profile' && (next.kind !== 'profile' || next.pubkey !== view.pubkey)) {
    tearDownAuthorSub();
  }
  if (view.kind === 'event' && (next.kind !== 'event' || next.eventId !== view.eventId)) {
    tearDownEventSub();
  }
  view = next;
  if (view.kind === 'profile') {
    profileView.hidden = false;
    feed.style.display = '';
    activeAuthorSubId = `author:${++authorReqCounter}`;
    wsSend(['REQ', activeAuthorSubId, { authors: [view.pubkey], limit: AUTHOR_LIMIT }]);
  } else if (view.kind === 'event') {
    profileView.hidden = true;
    profileView.innerHTML = '';
    if (!eventCache.has(view.eventId)) {
      activeEventSubId = `event:${++eventReqCounter}`;
      wsSend(['REQ', activeEventSubId, { ids: [view.eventId] }]);
    }
  } else {
    profileView.hidden = true;
    profileView.innerHTML = '';
  }
  render();
}

window.addEventListener('hashchange', applyRoute);

// ─── render ────────────────────────────────────────────────────────────────
function render() {
  if (view.kind === 'profile') renderProfileView();
  else if (view.kind === 'event') renderEventView();
  else renderFeed();
}

function applyKindFilter(list) {
  if (activeKindFilter === 'all') return list;
  if (activeKindFilter === 'other') return list.filter(e => ![0, 1, 30023].includes(e.kind));
  const k = parseInt(activeKindFilter, 10);
  return list.filter(e => e.kind === k);
}

function renderFeed() {
  let list = [...events.values()].sort((a, b) => b.created_at - a.created_at);
  list = applyKindFilter(list);
  if (list.length === 0) {
    feed.innerHTML = `<div class="empty">No events yet.</div>`;
    return;
  }
  feed.innerHTML = list.slice(0, 300).map(renderEvent).join('');
}

function renderProfileView() {
  const pk = view.pubkey;
  const npub = npubFromHex(pk);
  const profile = profiles.get(pk) || {};
  const name = profile.display_name || profile.name || shortId(npub, 14);
  const avatar = profile.picture
    ? `<img class="pic" src="${escape(profile.picture)}" alt="" loading="lazy" referrerpolicy="no-referrer">`
    : `<div class="pic" aria-hidden="true"></div>`;
  const nip05 = profile.nip05 ? `<div class="nip05">${escape(profile.nip05)}</div>` : '';
  const about = profile.about ? `<div class="about">${linkify(profile.about)}</div>` : '';
  const website = profile.website
    ? `<a href="${escape(profile.website)}" target="_blank" rel="noopener">${escape(profile.website)}</a>` : '';

  profileView.innerHTML = `
    <div class="profile-card">
      ${avatar}
      <div class="meta">
        <h2>${escape(name)}</h2>
        ${nip05}
        ${about}
        <div class="links">
          ${website}
          <a href="https://njump.me/${npub}" target="_blank" rel="noopener">njump</a>
          <a href="https://nostr.com/${npub}" target="_blank" rel="noopener">nostr.com</a>
        </div>
        <div class="ids">
          <div class="id-row">
            <span class="id-label">npub</span>
            <code class="id-val">${npub}</code>
            <button class="copy" type="button" data-copy="${npub}" title="copy npub">copy</button>
          </div>
          <div class="id-row">
            <span class="id-label">hex</span>
            <code class="id-val">${pk}</code>
            <button class="copy" type="button" data-copy="${pk}" title="copy hex pubkey">copy</button>
          </div>
        </div>
      </div>
      <button class="back" type="button" data-action="back">← back</button>
    </div>
  `;
  profileView.querySelector('[data-action="back"]').addEventListener('click', gotoFeed);

  let list = [...authorEvents.values()].sort((a, b) => b.created_at - a.created_at);
  list = applyKindFilter(list);
  if (list.length === 0) {
    feed.innerHTML = `<div class="empty">No events from this profile yet.</div>`;
    return;
  }
  feed.innerHTML = list.slice(0, 500).map(renderEvent).join('');
}

function renderEventView() {
  const id = view.eventId;
  const ev = eventCache.get(id);
  profileView.hidden = true;
  profileView.innerHTML = '';
  if (!ev) {
    const nevent = neventFromHex(id);
    const note = noteFromHex(id);
    feed.innerHTML = `
      <div class="event-detail-head">
        <button class="back" type="button" data-action="back">← back</button>
        <span class="detail-title">single event</span>
      </div>
      <div class="loading">Looking up event …<br><code>${shortId(id, 16)}</code></div>
      <div class="ids">
        <div class="id-row"><span class="id-label">nevent</span><code class="id-val">${nevent}</code><button class="copy" type="button" data-copy="${nevent}">copy</button></div>
        <div class="id-row"><span class="id-label">note</span><code class="id-val">${note}</code><button class="copy" type="button" data-copy="${note}">copy</button></div>
        <div class="id-row"><span class="id-label">hex</span><code class="id-val">${id}</code><button class="copy" type="button" data-copy="${id}">copy</button></div>
      </div>`;
    feed.querySelector('[data-action="back"]').addEventListener('click', gotoFeed);
    return;
  }
  feed.innerHTML = `
    <div class="event-detail-head">
      <button class="back" type="button" data-action="back">← back</button>
      <span class="detail-title">single event</span>
    </div>
    ${renderEvent(ev, { detail: true })}
  `;
  feed.querySelector('[data-action="back"]').addEventListener('click', gotoFeed);
}

function renderEvent(ev, opts = {}) {
  const detail = !!opts.detail;
  const profile = profiles.get(ev.pubkey) || {};
  const npub = npubFromHex(ev.pubkey);
  const nevent = neventFromHex(ev.id);
  const note = noteFromHex(ev.id);
  const name = profile.display_name || profile.name || shortId(npub, 14);
  const nip05 = profile.nip05
    ? `<button class="nip05" type="button" data-pubkey="${ev.pubkey}" title="open profile">@${escape(profile.nip05)}</button>`
    : '';
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

  const dateLink = detail
    ? `<span class="when">· ${fmtDate(ev.created_at)}</span>`
    : `<button class="when" type="button" data-event="${ev.id}" title="open event">· ${fmtDate(ev.created_at)}</button>`;
  const kindBadge = detail
    ? `<span class="kind">kind&nbsp;${ev.kind}</span>`
    : `<button class="kind kind-btn" type="button" data-event="${ev.id}" title="open event">kind&nbsp;${ev.kind}</button>`;

  return `
    <article class="evt${detail ? ' evt-detail' : ''}">
      <div class="evt-head">
        <button class="who" type="button" data-pubkey="${ev.pubkey}" title="open profile">${avatar}${escape(name)}</button>
        ${nip05}
        ${kindBadge}
        ${dateLink}
      </div>
      ${body}
      <div class="evt-foot">
        <a href="https://njump.me/${nevent}" target="_blank" rel="noopener">njump</a>
        <a href="https://nostr.com/${npub}" target="_blank" rel="noopener">author</a>
        ${detail ? '' : `<button class="open-event" type="button" data-event="${ev.id}" title="open event">open</button>`}
      </div>
      <div class="ids">
        <div class="id-row"><span class="id-label">nevent</span><code class="id-val">${nevent}</code><button class="copy" type="button" data-copy="${nevent}" title="copy nevent">copy</button></div>
        <div class="id-row"><span class="id-label">note</span><code class="id-val">${note}</code><button class="copy" type="button" data-copy="${note}" title="copy note id">copy</button></div>
        <div class="id-row"><span class="id-label">hex</span><code class="id-val">${ev.id}</code><button class="copy" type="button" data-copy="${ev.id}" title="copy hex id">copy</button></div>
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

// ─── delegated profile click handler ───────────────────────────────────────
document.addEventListener('click', (e) => {
  // copy buttons
  const cb = e.target.closest('[data-copy]');
  if (cb) {
    e.preventDefault();
    const val = cb.dataset.copy;
    if (val) copyToClipboard(val).then(() => flashCopied(cb));
    return;
  }
  // event-detail navigation
  const ev = e.target.closest('[data-event]');
  if (ev) {
    const id = ev.dataset.event;
    if (id && HEX64.test(id)) {
      e.preventDefault();
      gotoEventById(id);
      return;
    }
  }
  // profile navigation
  const pf = e.target.closest('[data-pubkey]');
  if (pf) {
    const pk = pf.dataset.pubkey;
    if (pk && HEX64.test(pk)) {
      e.preventDefault();
      gotoProfileByPubkey(pk);
    }
  }
});

// ─── search ────────────────────────────────────────────────────────────────
function findPubkeyByNip05(query) {
  // case-insensitive substring match on profile.nip05
  // exact match wins over partial; newest profile wins on ties
  const q = query.toLowerCase();
  let exact = null;
  let partial = null;
  for (const [pk, p] of profiles.entries()) {
    if (!p || !p.nip05) continue;
    const n = String(p.nip05).toLowerCase();
    if (n === q || n === '_@' + q) {
      if (!exact || (profiles.get(exact)?.created_at || 0) < p.created_at) exact = pk;
    } else if (n.includes(q)) {
      if (!partial || (profiles.get(partial)?.created_at || 0) < p.created_at) partial = pk;
    }
  }
  return exact || partial;
}

function findPubkeyByName(query) {
  const q = query.toLowerCase();
  let best = null;
  for (const [pk, p] of profiles.entries()) {
    const names = [p?.name, p?.display_name].filter(Boolean).map(s => String(s).toLowerCase());
    if (names.some(n => n === q)) {
      if (!best || (profiles.get(best)?.created_at || 0) < p.created_at) best = pk;
    }
  }
  return best;
}

function setSearchError(msg) {
  let el = document.querySelector('.search-error');
  if (!el) {
    el = document.createElement('div');
    el.className = 'search-error';
    searchForm.insertAdjacentElement('afterend', el);
  }
  el.textContent = msg || '';
}

async function resolveAndGo(raw) {
  setSearchError('');
  let q = (raw || '').trim();
  if (!q) return;

  // Strip leading @ if user typed "@alice@host.bit"
  if (q.startsWith('@')) q = q.slice(1);

  // 1. hex pubkey or npub/nprofile
  const direct = pubkeyFromAny(q);
  if (direct) { gotoProfileByPubkey(direct); return; }

  // 2. NIP-05-ish: name@host.bit or just host.bit
  const looksLikeNip05 = q.includes('.') || q.includes('@');
  if (looksLikeNip05) {
    // Normalize: bare "host.bit" is treated as "_@host.bit" in NIP-05 land
    const candidates = [q.toLowerCase()];
    if (!q.includes('@')) candidates.push('_@' + q.toLowerCase());

    // Try local cache first
    for (const cand of candidates) {
      const pk = findPubkeyByNip05(cand);
      if (pk) { gotoProfileByPubkey(pk); return; }
    }

    // Not in cache yet — refetch all kind:0 once and wait briefly
    setSearchError('searching relay for ' + q + '…');
    const before = profiles.size;
    const subId = 'search:' + Date.now();
    wsSend(['REQ', subId, { kinds: [0], limit: PROFILE_LIMIT }]);

    const found = await new Promise((resolve) => {
      const start = Date.now();
      const tick = () => {
        for (const cand of candidates) {
          const pk = findPubkeyByNip05(cand);
          if (pk) return resolve(pk);
        }
        if (Date.now() - start > SEARCH_FETCH_MS) return resolve(null);
        setTimeout(tick, 150);
      };
      tick();
    });
    try { wsSend(['CLOSE', subId]); } catch {}

    if (found) { setSearchError(''); gotoProfileByPubkey(found); return; }
    setSearchError('No profile found for "' + q + '" on this relay. Only profiles whose kind:0 declares a verified .bit NIP-05 are stored here.');
    return;
  }

  // 3. last resort: try name match
  const byName = findPubkeyByName(q);
  if (byName) { gotoProfileByPubkey(byName); return; }

  setSearchError('Type a .bit NIP-05 (e.g. alice@testls.bit), an npub1…, or a 64-char hex pubkey.');
}

searchForm.addEventListener('submit', (e) => {
  e.preventDefault();
  resolveAndGo(searchInput.value);
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
applyRoute();
