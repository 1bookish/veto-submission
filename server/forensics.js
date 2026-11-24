// Veto forensics: the evidence the X-ray collects for investigators, and the keys that link scam sites
// into campaigns.
//
//   copied logo   perceptual hashes of the page's icon and logos against the REAL institutions' own icons
//                 (data/logos.js, built by tools/logo-refs.js). Kits copy the brand's files byte for byte.
//   cloaking      the same link fetched as a phone, a computer and a search-engine crawler. Kits show the
//                 trap only to phones and send everyone else (and every scanner) somewhere harmless
//                 (Oest et al., "PhishFarm", IEEE S&P 2019).
//   kit print     a SimHash of the page's skeleton (tags, classes, field names, script files), not its
//                 words: the same kit re-skinned for another bank on another domain lands within a few bits.
//   campaign keys analytics / pixel IDs, Telegram bots, WhatsApp numbers, wallets: criminals reuse them
//                 across hundreds of domains (Forescout 2025: 28 % of phishing bot tokens reused).
//   infra         registrar + its abuse contact (RDAP), hosting network + ASN (Team Cymru DNS), the people
//                 a takedown request goes to.
// Only the suspicious SITE is examined; nothing about the user is stored or sent.

import dns from 'node:dns/promises';
import crypto from 'node:crypto';
import net from 'node:net';
import { fetchBytes } from './netguard.js';
import { LOGOS } from '../data/logos.js';
import { INSTITUTIONS } from '../data/institutions.js';
import { splitDomain } from '../engine/url.js';

const sig = (id, w, en, ar) => ({ id, w, en, ar });
const INST = new Map(INSTITUTIONS.map(i => [i.id, i]));

// ---------------------------------------------------------------------------------------------
// hashing helpers
export const sha256hex = buf => crypto.createHash('sha256').update(buf).digest('hex');

/** MurmurHash3 x86_32, signed, as Python's mmh3.hash() returns it. */
export function mmh3(key, seed = 0) {
  const c1 = 0xcc9e2d51, c2 = 0x1b873593, len = key.length, nb = len >> 2;
  let h = seed >>> 0, k;
  for (let i = 0; i < nb; i++) {
    k = key.readUInt32LE(i * 4);
    k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2);
    h ^= k; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  k = 0;
  const t = nb * 4;
  switch (len & 3) {
    case 3: k ^= key[t + 2] << 16; // fall through
    case 2: k ^= key[t + 1] << 8; // fall through
    case 1: k ^= key[t]; k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k;
  }
  h ^= len; h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return h | 0;
}
/** The favicon hash Shodan, Censys and FOFA index (http.favicon.hash): investigators pivot on it to find every server of a kit. */
export const shodanFaviconHash = buf => mmh3(Buffer.from(buf.toString('base64').match(/.{1,76}/g).map(l => l + '\n').join(''), 'latin1'));

export function sniffImage(buf, declared = '') {
  if (!buf || buf.length < 4) return null;
  if (buf.length > 8 && buf.readUInt32BE(0) === 0x89504e47) return 'image/png';
  if (buf.readUInt32LE(0) === 0x00010000) return 'image/x-icon';
  if (buf[0] === 0xff && buf[1] === 0xd8) return 'image/jpeg';
  if (buf.slice(0, 3).toString('latin1') === 'GIF') return 'image/gif';
  if (buf.length > 12 && buf.slice(0, 4).toString('latin1') === 'RIFF' && buf.slice(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
  if (/<svg[\s>]/i.test(buf.slice(0, 4000).toString('utf8'))) return 'image/svg+xml';
  return /^image\/(png|jpeg|gif|webp|x-icon|vnd\.microsoft\.icon|svg\+xml)/i.test(declared) ? declared.split(';')[0].trim() : null;
}

// Runs INSIDE a sealed page with no network: the browser's own decoders (PNG, ICO, SVG, WebP …) read
// each image from a data: URL and we keep three tiny fingerprints: dHash (gradients), aHash (light/dark
// pattern) and the mean colour. Images are composited on white so transparent icons hash the same way.
export const PHASH_IN_PAGE = async items => {
  const gray = (d, i) => 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
  const grid = (img, w, h) => {
    const c = document.createElement('canvas'); c.width = w; c.height = h;
    const x = c.getContext('2d', { willReadFrequently: true });
    x.fillStyle = '#fff'; x.fillRect(0, 0, w, h); x.imageSmoothingEnabled = true; x.imageSmoothingQuality = 'high';
    x.drawImage(img, 0, 0, w, h);
    return x.getImageData(0, 0, w, h).data;
  };
  const hex = bits => { let s = ''; for (let i = 0; i < 64; i += 4) s += ((bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3]).toString(16); return s; };
  const out = [];
  for (const it of items) {
    try {
      const img = new Image();
      img.src = `data:${it.type};base64,${it.b64}`;
      await img.decode();
      if (!img.naturalWidth || !img.naturalHeight) { out.push(null); continue; }
      // shrink in two steps (big logo -> 64 px -> grid) so thin strokes are averaged, not skipped
      const mid = document.createElement('canvas'); mid.width = 64; mid.height = 64;
      const mx = mid.getContext('2d'); mx.fillStyle = '#fff'; mx.fillRect(0, 0, 64, 64); mx.imageSmoothingQuality = 'high'; mx.drawImage(img, 0, 0, 64, 64);
      const d9 = grid(mid, 9, 8), dh = [];
      for (let y = 0; y < 8; y++) for (let x = 0; x < 8; x++) dh.push(gray(d9, (y * 9 + x) * 4) < gray(d9, (y * 9 + x + 1) * 4) ? 1 : 0);
      const d8 = grid(mid, 8, 8), g = [];
      let r = 0, gg = 0, b = 0;
      for (let i = 0; i < 64; i++) { g.push(gray(d8, i * 4)); r += d8[i * 4]; gg += d8[i * 4 + 1]; b += d8[i * 4 + 2]; }
      const mean = g.reduce((a, v) => a + v, 0) / 64;
      const sd = Math.sqrt(g.reduce((a, v) => a + (v - mean) ** 2, 0) / 64);
      out.push({ dh: hex(dh), ah: hex(g.map(v => (v > mean ? 1 : 0))), rgb: [Math.round(r / 64), Math.round(gg / 64), Math.round(b / 64)], sd: Math.round(sd), w: img.naturalWidth, h: img.naturalHeight });
    } catch { out.push(null); }
  }
  return out;
};

/** Perceptual hashes for [{bytes, type}] using the chamber's browser, in a context with no network at all. */
export async function hashImages(browser, imgs) {
  if (!imgs.length) return [];
  const ctx = await browser.newContext({ serviceWorkers: 'block', acceptDownloads: false, javaScriptEnabled: true });
  try {
    await ctx.route('**/*', r => r.abort());
    const page = await ctx.newPage();
    await page.setContent('<!doctype html><title>veto-hash</title>');
    return await page.evaluate(PHASH_IN_PAGE, imgs.map(i => ({ b64: i.bytes.toString('base64'), type: i.type })));
  } finally { await ctx.close().catch(() => {}); }
}

export function hamming64(a, b) {
  if (!a || !b || a.length !== 16 || b.length !== 16) return 64;
  let d = 0;
  for (let i = 0; i < 16; i += 8) { let x = (parseInt(a.slice(i, i + 8), 16) ^ parseInt(b.slice(i, i + 8), 16)) >>> 0; while (x) { x &= x - 1; d++; } }
  return d;
}

/** Same picture? exact bytes, or all three perceptual fingerprints close (plain one-colour images never match). */
export function sameImage(a, b) {
  if (a.sha256 && a.sha256 === b.sha256) return { exact: true, d: 0 };
  if (!a.ph || !b.ph || a.ph.sd < 12 || b.ph.sd < 12) return null;
  const d1 = hamming64(a.ph.dh, b.ph.dh), d2 = hamming64(a.ph.ah, b.ph.ah);
  const dc = Math.hypot(a.ph.rgb[0] - b.ph.rgb[0], a.ph.rgb[1] - b.ph.rgb[1], a.ph.rgb[2] - b.ph.rgb[2]);
  return d1 <= 6 && d2 <= 8 && dc <= 48 ? { exact: false, d: d1 } : null;
}

/** Page images (favicon, logos) that are the REAL institution's own pictures, on a site that is not theirs. */
// the brand's own country sites (google.nl, amazon.ae, careem.co.uk …) carry the same icon legitimately
export function brandSibling(inst, registrable) {
  const [label, ...rest] = String(registrable || '').split('.');
  return inst.domains.some(d => d.split('.')[0] === label) && /^[a-z]{2}$|^(co|com|org|net)\.[a-z]{2}$/.test(rest.join('.'));
}
export function matchLogos(images, finalReg) {
  const best = new Map();
  for (const im of images) {
    for (const ref of LOGOS) {
      const inst = INST.get(ref.inst);
      if (!inst || inst.domains.includes(finalReg) || brandSibling(inst, finalReg)) continue;
      const m = sameImage(im, ref);
      if (!m) continue;
      const cur = best.get(ref.inst);
      const score = (m.exact ? 2 : 1) + (im.kind === 'favicon' ? 1 : 0);
      if (!cur || score > cur.score) best.set(ref.inst, { inst: ref.inst, name: inst.name, domain: ref.domain, exact: m.exact, kind: im.kind, url: im.url, score });
    }
  }
  return [...best.values()].sort((a, b) => b.score - a.score).map(({ score, ...x }) => x);
}

// ---------------------------------------------------------------------------------------------
// cloaking: the same link fetched as a phone, a computer and a search-engine crawler (raw HTML, no JS,
// same server, same moment). Only a DIFFERENCE between them counts; one-time links that die after the
// first visit fail for all three and say nothing.
const UA = {
  phone: 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36',
  computer: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  crawler: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
};
function digest(r) {
  if (!r.ok) return { ok: false, status: /HTTP (\d+)/.exec(r.error || '')?.[1] ? Number(/HTTP (\d+)/.exec(r.error)[1]) : null, error: r.error };
  const html = r.bytes.toString('utf8').slice(0, 600_000);
  const text = html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&\w+;/g, ' ').toLowerCase();
  const words = new Set((text.match(/[a-z؀-ۿ]{3,}/g) || []).slice(0, 4000));
  let host = '';
  try { host = new URL(r.finalUrl).hostname; } catch { /* keep empty */ }
  return {
    ok: true, status: 200, finalHost: host, finalReg: host ? splitDomain(host).registrable : '', size: html.length,
    title: ((/<title[^>]*>([^<]{0,200})/i.exec(html) || [])[1] || '').trim(),
    secrets: (html.match(/type\s*=\s*["']?(password|tel|number)|name\s*=\s*["'][^"']*(pass|pin|otp|card|cvv)/gi) || []).length,
    inputs: (html.match(/<input\b/gi) || []).length, words
  };
}
const jaccard = (a, b) => { if (!a.size && !b.size) return 1; let i = 0; for (const w of a) if (b.has(w)) i++; return i / (a.size + b.size - i); };

export async function cloakProbe(url, { demoHosts = false } = {}) {
  const get = ua => fetchBytes(url, { demoHosts, maxBytes: 1_500_000, timeout: 6000, userAgent: ua }).then(digest, e => ({ ok: false, error: String(e.message || e) }));
  const phone = await get(UA.phone);
  const [computer, crawler] = await Promise.all([get(UA.computer), get(UA.crawler)]);
  const view = { phone, computer, crawler };
  const strip = v => v && { ok: v.ok, status: v.status, finalHost: v.finalHost, title: v.title, inputs: v.inputs, secrets: v.secrets, size: v.size, error: v.error };
  const out = { phone: strip(phone), computer: strip(computer), crawler: strip(crawler), verdict: 'none', who: [] };
  if (!phone.ok) { out.verdict = 'inconclusive'; return out; }
  for (const [who, v] of Object.entries({ computer, crawler })) {
    // 403/429/503 to a crawler is ordinary bot protection (Cloudflare & co.), not cloaking
    if (!v.ok && who === 'crawler' && [401, 403, 429, 503].includes(v.status)) continue;
    if (!v.ok && v.status && v.status >= 400) { out.who.push({ who, how: 'error', status: v.status }); continue; }
    if (!v.ok) continue;
    if (v.finalReg && phone.finalReg && v.finalReg !== phone.finalReg) { out.who.push({ who, how: 'elsewhere', to: v.finalHost }); continue; }
    const sim = jaccard(phone.words, v.words);
    if (phone.secrets > 0 && v.secrets === 0 && sim < 0.5) out.who.push({ who, how: 'no_form', sim: +sim.toFixed(2) });
    else if (sim < 0.15 && Math.min(phone.size, v.size) / Math.max(phone.size, v.size, 1) < 0.35) out.who.push({ who, how: 'different', sim: +sim.toFixed(2) });
  }
  if (out.who.length) out.verdict = 'cloaked';
  return out;
}
const WHO = { computer: ['a computer', 'جهاز كمبيوتر'], crawler: ['Google’s search crawler', 'زاحف بحث Google'] };
export function cloakSignal(c) {
  if (!c || c.verdict !== 'cloaked') return null;
  const x = c.who[0];
  const what = x.how === 'elsewhere' ? [`sends ${WHO[x.who][0]} to a different site (${x.to})`, `ترسل ${WHO[x.who][1]} إلى موقع آخر (${x.to})`]
    : x.how === 'error' ? [`shows ${WHO[x.who][0]} an error page (HTTP ${x.status})`, `تعرض على ${WHO[x.who][1]} صفحة خطأ (HTTP ${x.status})`]
      : x.how === 'no_form' ? [`shows ${WHO[x.who][0]} a page with no form`, `تعرض على ${WHO[x.who][1]} صفحة بلا نموذج`]
        : [`shows ${WHO[x.who][0]} a completely different page`, `تعرض على ${WHO[x.who][1]} صفحة مختلفة تماماً`];
  const both = c.who.length > 1 ? [' (and hides from the other check too)', ' (وتختبئ من الفحص الآخر أيضاً)'] : ['', ''];
  return sig('cloaking', x.how === 'elsewhere' || x.how === 'no_form' ? 0.7 : 0.55,
    `Cloaking: the page shows its real face only to phones. It ${what[0]}${both[0]}. Scam kits do this to hide from scanners and search engines.`,
    `تمويه: الصفحة تُظهر وجهها الحقيقي للهواتف فقط، و${what[1]}${both[1]}. تفعل أدوات الاحتيال ذلك للاختباء من الفاحصات ومحركات البحث.`);
}

// ---------------------------------------------------------------------------------------------
// kit fingerprint: SimHash over the page's skeleton, not its words
function fnv32(s, seed = 0x811c9dc5) { let h = seed >>> 0; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return h >>> 0; }
export function simhash64(features) {
  const v = new Float64Array(64);
  for (const [f, w] of features) {
    const hi = fnv32(f), lo = fnv32(f, 0x9747b28c);
    for (let i = 0; i < 32; i++) { v[i] += (hi >>> i) & 1 ? w : -w; v[32 + i] += (lo >>> i) & 1 ? w : -w; }
  }
  let hi = 0, lo = 0;
  for (let i = 0; i < 32; i++) { if (v[i] > 0) hi |= 1 << i; if (v[32 + i] > 0) lo |= 1 << i; }
  return (hi >>> 0).toString(16).padStart(8, '0') + (lo >>> 0).toString(16).padStart(8, '0');
}
/** skel = {tags: 'div.card form input …', fields: ['input:password:pass::', …], assets: ['jquery.min.js', …], forms: ['post /next.php']} */
export function kitPrint(skel) {
  if (!skel) return null;
  const toks = String(skel.tags || '').split(' ').filter(Boolean);
  if (toks.length < 25) return { simhash: null, tokens: toks.length };
  const f = new Map();
  const add = (k, w) => f.set(k, (f.get(k) || 0) + w);
  for (let i = 0; i + 4 <= toks.length; i++) add('s:' + toks.slice(i, i + 4).join(' '), 1);
  for (const x of skel.fields || []) add('f:' + x, 4);
  for (const x of skel.assets || []) add('a:' + x, 3);
  for (const x of skel.forms || []) add('m:' + x, 3);
  const exact = sha256hex([...(skel.fields || []), '|', ...(skel.assets || []), '|', ...(skel.forms || [])].join('\n')).slice(0, 16);
  return { simhash: simhash64(f), exact, tokens: toks.length, fields: (skel.fields || []).length };
}

// ---------------------------------------------------------------------------------------------
// campaign keys: identifiers the criminals reuse across sites
const ID_RX = [
  ['analytics', /\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{5,8}|AW-\d{9,11})\b/g],
  ['pixel', /fbq\(\s*['"]init['"]\s*,\s*['"](\d{12,17})['"]/g],
  ['pixel', /ttq\.load\(\s*['"]([A-Z0-9]{18,22})['"]/g],
  ['metrika', /\bym\(\s*(\d{6,10})\s*,\s*['"]init['"]/g],
  ['telegram_bot', /api\.telegram\.org\/bot(\d{6,12}):/g],
  ['telegram', /\bt(?:elegram)?\.me\/(?:s\/)?(?!share\b|joinchat\b)([A-Za-z][A-Za-z0-9_]{4,31})/g],
  ['whatsapp', /(?:wa\.me\/|api\.whatsapp\.com\/send\?phone=|whatsapp:\/\/send\?phone=)\+?(\d{8,15})/g],
  ['wallet', /\b(bc1[ac-hj-np-z02-9]{25,60}|0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33})\b/g],
  ['email', /\b([a-z0-9._%+-]{2,40}@(?:gmail|outlook|hotmail|yahoo|proton|protonmail|yandex|mail)\.[a-z.]{2,6})\b/gi]
];
export function campaignKeys({ html = '', text = '', links = [] } = {}) {
  const out = {};
  const hay = `${html}\n${links.join('\n')}`;
  for (const [kind, rx] of ID_RX) {
    for (const m of hay.matchAll(rx)) {
      const v = kind === 'email' ? m[1].toLowerCase() : m[1];
      (out[kind] ||= new Set()).add(v);
    }
  }
  // UAE phone numbers written on the page ("call our agent on 05x …")
  for (const m of String(text).matchAll(/(?:\+|00)?971[\s-]?5\d[\s-]?\d{3}[\s-]?\d{4}|\b05\d[\s-]?\d{3}[\s-]?\d{4}\b/g)) {
    (out.phone ||= new Set()).add('+9715' + m[0].replace(/\D/g, '').replace(/^(00)?971|^0/, '').slice(1));
  }
  return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, [...v].slice(0, 12)]));
}

// ---------------------------------------------------------------------------------------------
// infrastructure: who registered the name, who hosts the server, where to send the takedown
const vcard = (e, field) => {
  const row = (e?.vcardArray?.[1] || []).find(r => r[0] === field);
  return row ? String(Array.isArray(row[3]) ? row[3].join(' ') : row[3]).replace(/^mailto:/, '') : null;
};
const findEntity = (ents, role) => {
  for (const e of ents || []) {
    if ((e.roles || []).includes(role)) return e;
    const inner = findEntity(e.entities, role);
    if (inner) return inner;
  }
  return null;
};
async function rdap(kind, q) {
  try {
    const r = await fetch(`https://rdap.org/${kind}/${encodeURIComponent(q)}`, { signal: AbortSignal.timeout(6000), headers: { accept: 'application/rdap+json' }, redirect: 'follow' });
    return r.ok ? await r.json() : null;
  } catch { return null; }
}
export async function rdapDomain(registrable) {
  if (!registrable || !registrable.includes('.') || /\.localhost$/.test(registrable)) return null;
  const j = await rdap('domain', registrable);
  if (!j) return null;
  const ev = a => (j.events || []).find(e => new RegExp(a, 'i').test(e.eventAction))?.eventDate || null;
  const registrar = findEntity(j.entities, 'registrar');
  const abuse = findEntity(registrar?.entities || j.entities, 'abuse');
  const created = ev('registration');
  return {
    registrar: vcard(registrar, 'fn') || registrar?.handle || null,
    registrarIana: (registrar?.publicIds || []).find(p => /iana/i.test(p.type))?.identifier || null,
    abuseEmail: vcard(abuse, 'email'), abusePhone: vcard(abuse, 'tel'),
    created, expires: ev('expiration'), updated: ev('last changed'),
    ageDays: created ? Math.floor((Date.now() - Date.parse(created)) / 86400000) : null,
    status: j.status || [], nameservers: (j.nameservers || []).map(n => String(n.ldhName || '').toLowerCase()).filter(Boolean).slice(0, 6)
  };
}
export async function ipInfo(ip) {
  if (!ip || !net.isIPv4(ip)) return ip ? { ip } : null;
  const rev = ip.split('.').reverse().join('.');
  const txt = async name => { try { return (await dns.resolveTxt(name)).map(r => r.join('')); } catch { return []; } };
  const [origin, j] = await Promise.all([txt(`${rev}.origin.asn.cymru.com`), rdap('ip', ip)]);
  let asn = null, prefix = null, country = null, asName = null;
  if (origin[0]) {
    [asn, prefix, country] = origin[0].split('|').map(s => s.trim());
    asn = asn?.split(' ')[0] || null;
    const as = asn ? await txt(`AS${asn}.asn.cymru.com`) : [];
    asName = as[0] ? as[0].split('|').pop().trim() : null;
  }
  const abuse = findEntity(j?.entities, 'abuse');
  return { ip, asn: asn ? Number(asn) : null, asName, prefix, country: country || j?.country || null, network: j?.name || null, abuseEmail: vcard(abuse, 'email') };
}

/** Where takedown requests go, from the infra facts (and well-known abuse channels). */
export function takedownTargets({ infra, keys, url }) {
  const t = [];
  if (infra?.domain?.registrar) t.push({ to: 'registrar', name: infra.domain.registrar, email: infra.domain.abuseEmail, why: 'suspend the domain name' });
  if (infra?.host?.asName) {
    const cf = /cloudflare/i.test(infra.host.asName);
    t.push({ to: 'host', name: infra.host.asName, email: cf ? null : infra.host.abuseEmail, url: cf ? 'https://abuse.cloudflare.com/phishing' : null,
      why: cf ? 'Cloudflare hides the real server; its abuse form forwards the report to the real host' : 'take the server offline' });
  }
  if (keys?.telegram_bot?.length || keys?.telegram?.length) t.push({ to: 'telegram', name: 'Telegram', email: 'abuse@telegram.org', why: `ban the bot/account that receives the stolen data (${[...(keys.telegram_bot || []).map(b => 'bot ' + b), ...(keys.telegram || [])].slice(0, 3).join(', ')})` });
  if (keys?.whatsapp?.length) t.push({ to: 'whatsapp', name: 'WhatsApp', url: 'https://www.whatsapp.com/contact/forms/1534459096974129', why: `ban ${keys.whatsapp.slice(0, 3).map(n => '+' + n).join(', ')}` });
  t.push({ to: 'blocklists', name: 'Google Safe Browsing', url: `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url || '')}`, why: 'red warning in Chrome, Android, Safari and Firefox within hours' });
  t.push({ to: 'blocklists', name: 'Microsoft SmartScreen', url: 'https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest', why: 'warning in Edge and Windows' });
  t.push({ to: 'blocklists', name: 'Netcraft', url: 'https://report.netcraft.com/report', why: 'feeds many browsers, hosts and registrars' });
  return t;
}
