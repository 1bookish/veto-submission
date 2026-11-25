// node tools/diag-unseen.js
// Explains the misses of Test A (Phishing.Database, unseen by domain). Same construction as tools/eval-unseen.js.
// Diagnostic only: no threshold or rule is changed. Writes counts per family, never URLs.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';
import { parseUrl } from '../engine/urlml2.js';
import { splitDomain, FREE_HOSTING, USER_CONTENT_HOSTS } from '../engine/url.js';
import { BRANDS } from '../data/brands.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RAW = path.join(ROOT, '..', 'data_raw');
const OUT = path.join(ROOT, 'data', 'unseen-misses-report.json');

const regOf = u => { const x = parseUrl(u); return x ? splitDomain(x.hostname.toLowerCase().replace(/^www\d?\./, '')).registrable : ''; };
const op = fs.readFileSync(path.join(RAW, 'urlv2', 'openphish_history.tsv'), 'utf8').split('\n').map(l => l.split('\t')).filter(x => x[1]);
const days = [...new Set(op.map(x => x[0]))].sort();
const lastDay = days[days.length - 1];
const minus = (d, n) => new Date(Date.parse(d) - n * 86400000).toISOString().slice(0, 10);
const TEST_FROM = minus(lastDay, 30), VAL_FROM = minus(TEST_FROM, 21);
const trainOpRegs = op.filter(x => x[0] < VAL_FROM).map(x => regOf(x[1]));
const testWindowRegs = new Set(op.filter(x => x[0] >= VAL_FROM).map(x => regOf(x[1])));
const seenRegs = new Set(trainOpRegs);
const pdbRaw = fs.readFileSync(path.join(RAW, 'urlv2', 'pdb_active.txt'), 'utf8').split('\n').filter(Boolean);
const pdb = pdbRaw.map(l => l.trim()).filter(Boolean);
let tseed = 7;
const trand = () => ((tseed = (Math.imul(tseed, 1103515245) + 12345) >>> 0) / 4294967296);
let kept = 0;
for (let k = 0; k < pdbRaw.length && kept < 160000; k++) {
  const u = pdbRaw[Math.floor(trand() * pdbRaw.length)];
  const r = regOf(u);
  if (!r || testWindowRegs.has(r)) continue;
  seenRegs.add(r); kept++;
}
const phi = fs.readFileSync(path.join(RAW, 'phiusiil', 'PhiUSIIL_Phishing_URL_Dataset.csv'), 'utf8').replace(/^﻿/, '').split(/\r?\n/).slice(1);
for (const line of phi) { if (!line.trim().endsWith(',0')) continue; const m = /^[^,]*,([^,]*),/.exec(line); if (m) { const r = regOf(m[1]); if (r) seenRegs.add(r); } }
for (const r of testWindowRegs) seenRegs.add(r);
const unseen = [];
for (const u of pdb) { const r = regOf(u); if (!r || seenRegs.has(r)) continue; unseen.push(u); }

// popularity: Tranco top 100k (shipped with the judge)
const tranco = new Set(zlib.gunzipSync(fs.readFileSync(path.join(ROOT, 'data', 'tranco-top100k.txt.gz'))).toString('utf8').split('\n').filter(Boolean).map(s => s.trim().toLowerCase()));

const BUCKET = /(s3[.-][a-z0-9.-]*amazonaws\.com|backblazeb2\.com|storage\.googleapis\.com|blob\.core\.windows\.net|r2\.dev|digitaloceanspaces\.com)/i;
const CHEAP = /\.(xyz|top|icu|site|online|tk|ml|ga|cf|gq|cc|click|link|buzz|monster|shop)$/i;
const brands = BRANDS.filter(t => t.length >= 4);
const WORDS = /(login|signin|verify|secure|account|update|confirm|pay|bank|wallet|otp|reset|unlock|suspend)/i;

function family(u) {
  let host = ''; let p = null;
  try { p = new URL(u); host = p.hostname.toLowerCase(); } catch { return ['unparseable']; }
  const reg = regOf(u);
  const f = [];
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) f.push('ip_host');
  else if (BUCKET.test(host)) f.push('public_bucket');
  else if (FREE_HOSTING.has(reg) || [...FREE_HOSTING].some(s => host.endsWith('.' + s))) f.push('free_hosting_or_builder');
  else if ([...USER_CONTENT_HOSTS].some(s => host === s || host.endsWith('.' + s))) f.push('user_content_host');
  else f.push('ordinary_domain');
  f.push(tranco.has(reg) ? 'popular_top100k' : 'not_popular');
  f.push(CHEAP.test(host) ? 'cheap_tld' : 'other_tld');
  f.push(brands.some(t => u.toLowerCase().includes(t)) ? 'brand_token' : 'no_brand_token');
  f.push(WORDS.test(u) ? 'lure_words' : 'no_lure_words');
  return f;
}

const tally = {};
const bump = (k, caught) => { if (!tally[k]) tally[k] = { n: 0, caught: 0, missed: 0 }; tally[k].n++; if (caught) tally[k].caught++; else tally[k].missed++; };
let caughtAll = 0;
const missFamilies = {};
for (const u of unseen) {
  const caught = judgeOffline(u).verdict === 'phishing';
  if (caught) caughtAll++;
  const fam = family(u);
  for (const f of fam) bump(f, caught);
  if (!caught) {
    const key = fam.join(' + ');
    missFamilies[key] = (missFamilies[key] || 0) + 1;
  }
}
const topMissFamilies = Object.entries(missFamilies).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, n]) => ({ family: k, misses: n }));
const totalMisses = unseen.length - caughtAll;
const report = {
  unseen: unseen.length, caught_strict: caughtAll, recall_strict: +(caughtAll / unseen.length).toFixed(4), misses: totalMisses,
  by_feature: Object.fromEntries(Object.entries(tally).map(([k, v]) => [k, { ...v, recall: +(v.caught / v.n).toFixed(4), share_of_misses: +(v.missed / totalMisses).toFixed(4) }])),
  top_miss_families: topMissFamilies,
  note: 'diagnostic only; no rule or threshold changed; URLs are not written',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ unseen: report.unseen, recall_strict: report.recall_strict, misses: report.misses, by_feature: report.by_feature, top_miss_families: report.top_miss_families }, null, 2));
