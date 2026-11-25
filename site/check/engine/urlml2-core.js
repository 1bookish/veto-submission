// Veto full-URL model (v2): "is this whole address a phishing URL?"
//
// v1 (engine/urlml.js, on the phone) reads only the site NAME. v2 reads everything an analyst reads: the host
// (character patterns, brand misuse, ending, shape), the PATH and QUERY (kit folders, login/verify words,
// e-mail addresses and tokens in the query, file types, depth, random strings), the scheme and port, and how
// popular the registrable domain is (Tranco rank bucket, with a separate bucket for hosting platforms where
// anyone can publish, so popularity never vouches for a stranger's sub-site).
// Logistic regression on 2^20 hashed features, trained by tools/train-url-model2.js on dated public data
// (OpenPhish history, Phishing.Database, PhiUSIIL) and crawled legitimate deep links.
//
// This file has no Node-only code, so the same scorer runs on the server and in the browser extension. The weights
// and the Tranco list come from a source set with setUrlml2Source(): engine/urlml2.js reads them from disk on the
// server; the extension loads them from its own package.

import { featurize as hostFeatures } from './urlml.js';
import { splitDomain, FREE_HOSTING } from './url.js';

export const BITS2 = 20;
const MASK = (1 << BITS2) - 1;
const fnv = s => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return h >>> 0; };
const SHORT = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rebrand.ly', 'ow.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'bit.do', 't.ly', 's.id', 'shorturl.asia', 'qrco.de', 'linktr.ee', 'lnkd.in']);

// ---- where the weights and the Tranco list come from ---------------------------------------------
// { model: () => parsed model JSON, tranco: () => the list as text, one registrable domain per line, most visited first }
const SOURCE = { model: null, tranco: null };
let RANK = null;
let MODEL2 = null, W2 = null;
export function setUrlml2Source({ model, tranco } = {}) {
  if (model) { SOURCE.model = model; MODEL2 = null; W2 = null; }
  if (tranco) { SOURCE.tranco = tranco; RANK = null; }
}

// ---- Tranco popularity (registrable domain -> rank), loaded once ----------------------------------
export function trancoRank(reg) {
  if (!RANK) {
    RANK = new Map();
    try {
      const txt = SOURCE.tranco ? SOURCE.tranco() : '';
      if (txt) txt.split('\n').forEach((d, i) => { if (d) RANK.set(d, i + 1); });
    } catch { /* list missing: popularity feature off */ }
  }
  return RANK.get(reg) || 0;
}
// big sites where ANYONE can publish a page: their popularity must never vouch for a stranger's page on them
const USER_CONTENT = ['sites.google.com', 'docs.google.com', 'drive.google.com', 'forms.gle', 'storage.googleapis.com', 'firebasestorage.googleapis.com',
  'blob.core.windows.net', 'dropbox.com', 'dropboxusercontent.com', 'onedrive.live.com', '1drv.ms', 'sharepoint.com', 'notion.site', 'canva.site', 'my.canva.site',
  'wordpress.com', 'telegra.ph', 'ipfs.io', 'dweb.link', 'gitbook.io', 'typeform.com', 'jotform.com', 'mailchi.mp', 'linktr.ee', 'wixsite.com', 'yolasite.com',
  'jimdosite.com', 'ucoz.net', 'tilda.ws', 'hpage.com', 'website2.me', 'tiiny.site', 'codeberg.page', 'pages.github.com'];
export function isPlatform(host, reg) {
  if (FREE_HOSTING.has(reg)) return true;
  for (const p of FREE_HOSTING) if (host.endsWith('.' + p)) return true;
  return USER_CONTENT.some(p => host === p || host.endsWith('.' + p));
}
const rankBucket = r => (!r ? 'none' : r <= 1000 ? '1k' : r <= 10000 ? '10k' : r <= 50000 ? '50k' : '100k');

const ent = s => { const c = {}; for (const ch of s) c[ch] = (c[ch] || 0) + 1; let e = 0; for (const k in c) { const p = c[k] / s.length; e -= p * Math.log2(p); } return e; };

/**
 * Undo "defanging", the way threat reports and police lists write dangerous links so nobody clicks them:
 * hxxp(s)://, h**p://, [.], (.), {.}, [dot], (dot), [:], [/]. Also strips wrapping quotes or <angle brackets>.
 * A real URL keeps its meaning: these bracketed tokens do not occur in ordinary addresses.
 */
export function refang(input) {
  let s = String(input || '').trim();
  for (let i = 0; i < 2; i++) {
    const m = /^(["'`<])([\s\S]*)(["'`>])$/.exec(s);
    if (!m || !((m[1] === '<' && m[3] === '>') || (m[1] !== '<' && m[1] === m[3]))) break;
    s = m[2].trim();
  }
  s = s.replace(/^h(?:xx|XX|\*\*|tt)p(s?)(?:\[:\]|\(:\)|:)\/\//i, 'http$1://');
  s = s.replace(/^(https?|ftp)(?:\[:\]|\(:\))\/\//i, '$1://');
  s = s.replace(/\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}/gi, '.');
  s = s.replace(/\[:\]/g, ':').replace(/\[\/\]/g, '/');
  return s;
}

/** Parse leniently: bare hosts, missing schemes, odd spacing, defanged links. */
export function parseUrl(input) {
  let s = refang(input);
  if (!/^[a-z][a-z0-9+.\-]*:\/\//i.test(s)) s = 'http://' + s;
  try { const u = new URL(s); if (u.hostname.endsWith('.')) u.hostname = u.hostname.replace(/[.]+$/, ''); return u; } catch { return null; }
}

/** Hashed sparse features of a full URL: Map(index -> value); keys kept when explain=true. */
export function featurizeUrl(input, explain = false) {
  const feats = new Map();
  const keys = explain ? new Map() : null;
  const add = (k, v = 1) => { const i = fnv(k) & MASK; feats.set(i, (feats.get(i) || 0) + v); if (keys && !keys.has(i)) keys.set(i, k); };
  const u = parseUrl(input);
  if (!u) { add('bad_url'); return { feats, keys, host: '' }; }
  const host = u.hostname.toLowerCase().replace(/^www\d?\./, '');
  // host side: reuse the v1 host features (n-grams, tokens, ending, shape, brand misuse), mapped into this space by a
  // cheap integer mix (no string work: this runs half a million times per training pass)
  const hf = hostFeatures(host, explain);
  for (const [i1, v] of hf.feats) {
    const i = (Math.imul(i1 + 0x9e3779b9, 0x85ebca6b) >>> 7) & MASK;
    feats.set(i, (feats.get(i) || 0) + v);
    if (keys && !keys.has(i)) keys.set(i, 'h|' + (hf.keys.get(i1) || ''));
  }
  const reg = splitDomain(host).registrable;
  const platform = isPlatform(host, reg);
  const rank = trancoRank(reg);
  add(`pop:${rankBucket(rank)}${platform ? ':platform' : ''}`);
  if (platform) add('platform');
  if (SHORT.has(reg) || SHORT.has(host)) add('shortener');
  add('scheme:' + u.protocol.replace(':', ''));
  if (u.port && !['80', '443'].includes(u.port)) add('port');
  if (u.username || u.password) add('userinfo');
  const sub = host.slice(0, Math.max(0, host.length - reg.length - 1));
  if (sub) add('subdepth:' + Math.min(4, sub.split('.').length));
  // path + query
  const p = decodeURIComponentSafe(u.pathname).toLowerCase();
  const q = u.search.toLowerCase();
  const pq = (p + q).slice(0, 240);
  const segs = p.split('/').filter(Boolean);
  add('depth:' + Math.min(8, segs.length));
  add('plen:' + Math.min(10, Math.floor(p.length / 12)));
  add('qlen:' + Math.min(8, Math.floor(q.length / 20)));
  const params = [...u.searchParams.keys()];
  add('nparams:' + Math.min(6, params.length));
  for (const k of params.slice(0, 8)) add('q:' + k.toLowerCase().slice(0, 20));
  const last = segs[segs.length - 1] || '';
  const ext = /\.([a-z0-9]{1,5})$/.exec(last)?.[1];
  add('ext:' + (ext || (p.endsWith('/') ? 'slash' : last ? 'none' : 'root')));
  if (/@/.test(p + q)) add('at_in_path');
  if (/[\w.+-]+@[\w-]+\.[\w.]+/.test(decodeURIComponentSafe(q))) add('email_in_query');
  if (p.includes('//')) add('double_slash');
  if (/~/.test(p)) add('tilde');
  add('pct:' + Math.min(4, (u.pathname.match(/%[0-9a-f]{2}/gi) || []).length));
  if (/https?%3a|https?:\/\//i.test(u.pathname + u.search)) add('url_in_url');
  if (/wp-(content|includes|admin)/.test(p)) add('wordpress_path');
  if (/\b(index|default)\.(php|html?)$/.test(p)) add('index_file');
  for (const tok of pq.split(/[\/._\-?=&+:;,!$()*'"]+/)) {
    if (!tok) continue;
    if (/^\d+$/.test(tok)) { add('pt:#' + Math.min(4, Math.ceil(tok.length / 3))); continue; }
    if (tok.length >= 14 && ent(tok) > 3.6) { add('pt:<rand>'); continue; }
    if (tok.length >= 3 && tok.length <= 24) add('pt:' + tok, 0.7);
  }
  const s = '^' + pq.slice(0, 120) + '$';
  const norm = 1 / Math.sqrt(Math.max(4, s.length));
  for (let i = 0; i + 4 <= s.length; i++) add('pg4:' + s.slice(i, i + 4), norm);
  return { feats, keys, host, reg, rank, platform };
}
function decodeURIComponentSafe(s) { try { return decodeURIComponent(s); } catch { return s; } }

// ---- weights ----------------------------------------------------------------------------------------
function b64bytes(s) {
  const b = atob(s);
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}
function load() {
  if (W2) return W2;
  W2 = new Map();
  try {
    MODEL2 = SOURCE.model ? SOURCE.model() : null;
    if (!MODEL2) return W2;
    const idx = b64bytes(MODEL2.idx), val = b64bytes(MODEL2.val);
    let cur = 0, v = 0, shift = 0, k = 0;
    for (const b of idx) {
      v |= (b & 0x7f) << shift;
      if (b & 0x80) { shift += 7; continue; }
      cur += v >>> 0; v = 0; shift = 0;
      const q = val[k] > 127 ? val[k] - 256 : val[k];
      W2.set(cur, q * MODEL2.scale);
      k++;
    }
  } catch { MODEL2 = null; W2 = new Map(); /* model not trained yet */ }
  return W2;
}
export const model2Info = () => (load(), MODEL2 ? { version: MODEL2.version, threshold: MODEL2.threshold, weights: MODEL2.weights, report: MODEL2.report } : null);

const READ = k => {
  if (!k) return null;
  const h = k.startsWith('h|') ? k.slice(2) : null;
  if (h?.startsWith('brand:typo')) return { en: 'a famous brand name with one letter changed', ar: 'اسم علامة مشهورة مع تغيير حرف' };
  if (h?.startsWith('brand:glued')) return { en: 'a famous brand glued to other words', ar: 'اسم علامة مشهورة ملصق بكلمات أخرى' };
  if (h?.startsWith('brand:sub')) return { en: 'a famous brand placed in front of another site', ar: 'اسم علامة مشهورة أمام موقع آخر' };
  if (h?.startsWith('tld:')) return { en: `the ending “.${h.slice(4)}”`, ar: `النهاية «.${h.slice(4)}»` };
  if (h?.startsWith('tok:')) return { en: `“${h.slice(4)}” in the site name`, ar: `«${h.slice(4)}» في اسم الموقع` };
  if (k.startsWith('pt:') && !k.startsWith('pt:#') && k !== 'pt:<rand>') return { en: `“${k.slice(3)}” in the path`, ar: `«${k.slice(3)}» في المسار` };
  if (k === 'pt:<rand>') return { en: 'random-looking strings in the path', ar: 'نصوص عشوائية في المسار' };
  if (k.startsWith('pop:none')) return { en: 'a site that is not among the 100,000 most visited', ar: 'موقع ليس من أكثر 100 ألف موقع زيارة' };
  if (k === 'platform' || k.endsWith(':platform')) return { en: 'a free hosting platform where anyone can publish', ar: 'منصة استضافة مجانية ينشر فيها أي شخص' };
  if (k === 'email_in_query') return { en: 'an e-mail address inside the link (pre-filled victim)', ar: 'بريد إلكتروني داخل الرابط' };
  if (k === 'url_in_url') return { en: 'another web address hidden inside the link', ar: 'عنوان آخر مخفي داخل الرابط' };
  if (k === 'wordpress_path') return { en: 'a hacked-website folder (wp-content)', ar: 'مجلد موقع مخترق (wp-content)' };
  if (k === 'scheme:http') return { en: 'no encryption (http)', ar: 'بدون تشفير (http)' };
  if (k === 'at_in_path' || k === 'userinfo') return { en: 'an “@” trick in the address', ar: 'خدعة «@» في العنوان' };
  if (k.startsWith('ext:php')) return { en: 'a .php script page', ar: 'صفحة برمجية .php' };
  if (k.startsWith('subdepth:')) return { en: 'many sub-domains', ar: 'نطاقات فرعية كثيرة' };
  if (k === 'shortener') return { en: 'a link shortener that hides the destination', ar: 'مختصِر روابط يخفي الوجهة' };
  return null;
};

/** p = probability that the full URL is phishing, with the 3 strongest reasons. */
export function mlUrlScore2(input) {
  const w = load();
  if (!w.size) return null;
  const { feats, keys, host, reg, rank, platform } = featurizeUrl(input, true);
  let z = MODEL2.bias;
  const contrib = [];
  for (const [i, v] of feats) { const wi = w.get(i); if (wi) { z += wi * v; contrib.push([i, wi * v]); } }
  const p = 1 / (1 + Math.exp(-z));
  const why = [], seen = new Set();
  for (const [i, c] of contrib.sort((a, b) => b[1] - a[1])) {
    if (c <= 0.2 || why.length >= 3) break;
    const r = READ(keys.get(i));
    if (r && !seen.has(r.en)) { seen.add(r.en); why.push(r); }
  }
  return { p: +p.toFixed(4), host, reg, rank, platform, why, threshold: MODEL2.threshold, version: MODEL2.version };
}
