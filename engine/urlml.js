// Veto ML link model: "does this domain NAME look like a phishing domain?"
//
// A logistic-regression model over hashed features of the host name only (never the path: public
// datasets list legitimate sites as bare homepages, so path features teach a model "has a path =
// phishing", which is wrong). Features: character 3- to 5-grams, words between dots and hyphens, the
// ending (.top, .xyz …), and bucketed shape counts (length, digits, hyphens, labels, randomness).
// Trained by tools/train-url-model.js on PhiUSIIL (UCI, 2024), split by domain, tested on fresh
// OpenPhish URLs and on Tranco top sites. Runs on the device in well under a millisecond and says
// WHY: the pieces of the name that pushed the score up.
//
// It is one signal among many: an official domain from the rulebook always wins, and a high score
// alone only says "looks machine-made", never "this is a scam".

import { MODEL } from '../data/urlml-model.js';
import { BRANDS } from '../data/brands.js';

// one edit (insert, delete, substitute) or one swap of neighbours apart; cheap early exits
function oneEdit(a, b) {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  if (a.length === b.length) {
    if (a.slice(i + 1) === b.slice(i + 1)) return true;
    return a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2);
  }
  return a.length > b.length ? a.slice(i + 1) === b.slice(i) : a.slice(i) === b.slice(i + 1);
}
const BRAND_SET = new Set(BRANDS);

export const BITS = 18;
const MASK = (1 << BITS) - 1;

function fnv(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return h >>> 0;
}

const TWO_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'sch', 'mil', 'ltd', 'plc']);

/** Lower-case host without scheme, port, "www." or a trailing dot. Accepts a full URL or a bare host. */
export function normHost(input) {
  let s = String(input || '').trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.\-]*:\/\//, '').replace(/^[^@/]*@/, '');
  s = s.split(/[/?#]/)[0].replace(/:\d+$/, '').replace(/\.$/, '');
  return s.replace(/^www\d?\./, '');
}

/** Registrable-ish part (last two labels, three for co.uk-style endings). Used for the domain split. */
export function regPart(host) {
  const l = normHost(host).split('.');
  if (l.length >= 3 && TWO_LEVEL.has(l[l.length - 2]) && l[l.length - 1].length === 2) return l.slice(-3).join('.');
  return l.slice(-2).join('.');
}

function entropy(s) {
  const c = {};
  for (const ch of s) c[ch] = (c[ch] || 0) + 1;
  let e = 0;
  for (const k in c) { const p = c[k] / s.length; e -= p * Math.log2(p); }
  return e;
}

/** Hashed sparse features: Map(index -> value) plus a parallel Map(index -> readable key) when explain=true. */
export function featurize(input, explain = false) {
  const host = normHost(input);
  const feats = new Map();
  const keys = explain ? new Map() : null;
  const add = (key, v = 1) => {
    const i = fnv(key) & MASK;
    feats.set(i, (feats.get(i) || 0) + v);
    if (keys && !keys.has(i)) keys.set(i, key);
  };
  if (!host) return { host, feats, keys };
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
  const labels = host.split('.');
  const tld = labels[labels.length - 1];
  const name = labels.slice(0, -1).join('.');
  const s = '^' + host + '$';
  const norm = 1 / Math.sqrt(Math.max(4, s.length));
  for (let n = 3; n <= 5; n++) for (let i = 0; i + n <= s.length; i++) add(`g${n}:${s.slice(i, i + n)}`, norm);
  add('tld:' + tld, 1);
  for (const tok of name.split(/[.\-_]/)) if (tok.length >= 3 && tok.length <= 24) add('tok:' + tok, 0.6);
  const letters = name.replace(/[^a-z]/g, '');
  const digits = (name.match(/\d/g) || []).length;
  const hyph = (name.match(/-/g) || []).length;
  const vowels = (letters.match(/[aeiou]/g) || []).length;
  const consRun = Math.max(0, ...((letters.match(/[^aeiou]+/g) || []).map(r => r.length)));
  add('len:' + Math.min(10, Math.floor(host.length / 6)));
  add('dig:' + Math.min(5, digits));
  add('hyp:' + Math.min(4, hyph));
  add('lab:' + Math.min(6, labels.length));
  add('maxlab:' + Math.min(8, Math.floor(Math.max(...labels.map(x => x.length)) / 4)));
  add('ent:' + Math.min(10, Math.floor(entropy(name || host) * 2)));
  add('vow:' + (letters.length ? Math.min(6, Math.floor((vowels / letters.length) * 10)) : 'x'));
  add('cons:' + Math.min(6, consRun));
  if (isIp) add('ip');
  if (host.includes('xn--')) add('puny');
  // brand features: a famous name used where it doesn't belong
  if (!isIp && labels.length >= 2) {
    const reg = regPart(host);
    const regLabel = reg.split('.')[0];
    const sub = labels.slice(0, labels.length - reg.split('.').length).join('.');
    const regParts = regLabel.split('-');
    if (BRAND_SET.has(regLabel)) add('brand:exact');
    else {
      for (const b of BRANDS) {
        if (b.length < 4) continue;
        if (regParts.includes(b) || (b.length >= 5 && regLabel.includes(b))) { add('brand:glued'); add('brand:glued:' + (regParts.length > 1 ? 'hyph' : 'solid')); break; }
      }
      if (regLabel.length >= 5) for (const b of BRANDS) if (b.length >= 5 && oneEdit(regLabel, b)) { add('brand:typo'); break; }
    }
    if (sub) for (const b of BRANDS) {
      if (b.length < 4) continue;
      if (sub.split(/[.\-]/).includes(b) || (b.length >= 6 && sub.includes(b))) { add('brand:sub'); break; }
    }
  }
  return { host, feats, keys };
}

// ---- model weights (sparse, int8-quantised, base64) -------------------------------------
let W = null;
function weights() {
  if (W) return W;
  W = new Map();
  if (!MODEL || !MODEL.idx) return W;
  const idx = decodeVarints(MODEL.idx);
  const val = b64bytes(MODEL.val);
  let cur = 0;
  for (let k = 0; k < idx.length; k++) {
    cur += idx[k];
    const q = val[k] > 127 ? val[k] - 256 : val[k];
    W.set(cur, q * MODEL.scale);
  }
  return W;
}
function b64bytes(s) {
  if (typeof atob === 'function') { const b = atob(s); const out = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i); return out; }
  return new Uint8Array(Buffer.from(s, 'base64'));
}
function decodeVarints(s) {
  const bytes = b64bytes(s);
  const out = [];
  let v = 0, shift = 0;
  for (const b of bytes) { v |= (b & 0x7f) << shift; if (b & 0x80) shift += 7; else { out.push(v >>> 0); v = 0; shift = 0; } }
  return out;
}

const sigmoid = z => 1 / (1 + Math.exp(-z));

function readable(key) {
  if (!key) return null;
  if (key.startsWith('tld:')) return { en: `the ending “.${key.slice(4)}”`, ar: `النهاية «.${key.slice(4)}»` };
  if (key.startsWith('tok:')) return { en: `the word “${key.slice(4)}” in the name`, ar: `الكلمة «${key.slice(4)}» في الاسم` };
  if (key.startsWith('hyp:')) return { en: 'several hyphens', ar: 'عدة شرطات' };
  if (key.startsWith('dig:')) return { en: 'digits mixed into the name', ar: 'أرقام داخل الاسم' };
  if (key.startsWith('len:')) return { en: 'an unusually long name', ar: 'اسم طويل بشكل غير معتاد' };
  if (key.startsWith('lab:')) return { en: 'many sub-domains', ar: 'نطاقات فرعية كثيرة' };
  if (key.startsWith('ent:') || key.startsWith('cons:') || key.startsWith('vow:')) return { en: 'random-looking letters', ar: 'حروف تبدو عشوائية' };
  if (key.startsWith('reg:')) return { en: `the host “${key.slice(4)}” (often abused)`, ar: `المضيف «${key.slice(4)}» (يُستغل كثيراً)` };
  if (key === 'ip') return { en: 'a raw IP address instead of a name', ar: 'عنوان IP بدل اسم' };
  if (key === 'puny') return { en: 'disguised (punycode) letters', ar: 'حروف مموّهة (punycode)' };
  if (key.startsWith('brand:glued')) return { en: 'a famous brand name glued to other words', ar: 'اسم علامة مشهورة ملصق بكلمات أخرى' };
  if (key === 'brand:typo') return { en: 'a famous brand name with one letter changed', ar: 'اسم علامة مشهورة مع تغيير حرف واحد' };
  if (key === 'brand:sub') return { en: 'a famous brand name placed in front of another site', ar: 'اسم علامة مشهورة موضوع قبل موقع آخر' };
  if (/^g\d:/.test(key)) return null; // letter n-grams are not explained: they mean nothing to a reader
  return null;
}

/**
 * @returns {{p:number, host:string, why:Array<{en,ar}>, version:string}|null}
 *   p = probability the domain name is a phishing-style name (calibrated on held-out data).
 */
export function mlUrlScore(input) {
  const w = weights();
  if (!w.size) return null;
  const { host, feats, keys } = featurize(input, true);
  if (!host) return null;
  let z = MODEL.bias;
  const contrib = [];
  for (const [i, v] of feats) {
    const wi = w.get(i);
    if (wi) { z += wi * v; contrib.push([i, wi * v]); }
  }
  const p = sigmoid(z);
  const seen = new Set();
  const why = [];
  for (const [i, c] of contrib.sort((a, b) => b[1] - a[1])) {
    if (c <= 0.15 || why.length >= 3) break;
    const r = readable(keys.get(i));
    if (r && !seen.has(r.en)) { seen.add(r.en); why.push(r); }
  }
  // brand misuse (typo, glued, in a sub-domain) is the high-precision part of the evidence
  const brand = contrib.some(([i, c]) => c > 0.1 && /^brand:(typo|glued|sub)/.test(keys.get(i) || ''));
  return { p: +p.toFixed(4), host, why, brand, version: MODEL.version };
}
