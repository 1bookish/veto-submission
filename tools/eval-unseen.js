// node tools/eval-unseen.js [--raw <data_raw dir>] [--out data/unseen-report.json]
// The unseen-data tests, pre-registered in docs/RESEARCH_LOG.md ("Unseen-data tests", 24 Nov, late).
// Offline only: no network and no page visits. Do not change a rule here to fit a result.
// Writes counts and rates only. No URL and no new-domain name is written anywhere.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';
import { parseUrl } from '../engine/urlml2.js';
import { splitDomain } from '../engine/url.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const RAW = arg('--raw', path.join(ROOT, '..', 'data_raw'));
const OUT = arg('--out', path.join(ROOT, 'data', 'unseen-report.json'));
const SEED = 20261124, B = 1000;

// the same registrable-domain rule as tools/train-url-model2.js
const regOf = u => { const x = parseUrl(u); return x ? splitDomain(x.hostname.toLowerCase().replace(/^www\d?\./, '')).registrable : ''; };

// OpenPhish dates and windows, exactly as the training script defines them
const op = fs.readFileSync(path.join(RAW, 'urlv2', 'openphish_history.tsv'), 'utf8').split('\n').map(l => l.split('\t')).filter(x => x[1]);
const days = [...new Set(op.map(x => x[0]))].sort();
const lastDay = days[days.length - 1];
const minus = (d, n) => new Date(Date.parse(d) - n * 86400000).toISOString().slice(0, 10);
const TEST_FROM = minus(lastDay, 30), VAL_FROM = minus(TEST_FROM, 21);

// seeded bootstrap of a rate (1,000 resamples, 95 % percentile interval)
let seed = SEED;
const rnd = () => { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
function bootstrapRate(flags) {
  const n = flags.length;
  if (!n) return [null, null];
  const xs = new Float64Array(B);
  for (let b = 0; b < B; b++) { let s = 0; for (let i = 0; i < n; i++) s += flags[Math.floor(rnd() * n)]; xs[b] = s / n; }
  xs.sort();
  return [+xs[Math.floor(0.025 * B)].toFixed(4), +xs[Math.ceil(0.975 * B) - 1].toFixed(4)];
}
const mean = a => (a.length ? a.reduce((s, x) => s + x, 0) / a.length : null);

// ================= Test A: Phishing.Database, unseen by domain =================
const trainOpRegs = op.filter(x => x[0] < VAL_FROM).map(x => regOf(x[1]));          // OpenPhish training domains
const testWindowRegs = new Set(op.filter(x => x[0] >= VAL_FROM).map(x => regOf(x[1]))); // validation and test windows
const seenRegs = new Set(trainOpRegs);
const pdbRaw = fs.readFileSync(path.join(RAW, 'urlv2', 'pdb_active.txt'), 'utf8').split('\n').filter(Boolean); // as the training script reads it
const pdb = pdbRaw.map(l => l.trim()).filter(Boolean);
// (a) the Phishing.Database sample the training script draws: seed 7, 160,000 draws, the same skip rule
let tseed = 7;
const trand = () => ((tseed = (Math.imul(tseed, 1103515245) + 12345) >>> 0) / 4294967296);
let kept = 0;
for (let k = 0; k < pdbRaw.length && kept < 160000; k++) {
  const u = pdbRaw[Math.floor(trand() * pdbRaw.length)];
  const r = regOf(u);
  if (!r || testWindowRegs.has(r)) continue;
  seenRegs.add(r); kept++;
}
// (b) every PhiUSIIL phishing row (label 0, parsed as the training script parses it): a conservative superset
const phi = fs.readFileSync(path.join(RAW, 'phiusiil', 'PhiUSIIL_Phishing_URL_Dataset.csv'), 'utf8').replace(/^﻿/, '').split(/\r?\n/).slice(1);
let phiRows = 0;
for (const line of phi) {
  if (!line.trim().endsWith(',0')) continue;
  const m = /^[^,]*,([^,]*),/.exec(line);
  if (!m) continue;
  phiRows++;
  const r = regOf(m[1]);
  if (r) seenRegs.add(r);
}
// (c) the OpenPhish validation and test windows
for (const r of testWindowRegs) seenRegs.add(r);

const unseenA = [];
let excludedA = 0;
for (const u of pdb) { const r = regOf(u); if (!r || seenRegs.has(r)) { excludedA++; continue; } unseenA.push(u); }
const vA = unseenA.map(u => judgeOffline(u).verdict);
const strictA = Uint8Array.from(vA, v => (v === 'phishing' ? 1 : 0));
const cautiousA = Uint8Array.from(vA, v => (v === 'phishing' || v === 'suspicious' ? 1 : 0));
const testA = {
  population_lines: pdb.length, excluded_seen_domain: excludedA, unseen: unseenA.length,
  training_domains_excluded_against: seenRegs.size, phiusiil_phishing_rows_read: phiRows,
  recall_strict: +mean(strictA).toFixed(4), recall_strict_95ci: bootstrapRate(strictA),
  recall_cautious: +mean(cautiousA).toFixed(4), recall_cautious_95ci: bootstrapRate(cautiousA),
  note: 'domain-disjoint, not time-disjoint; false alarms on unseen legitimate sites not measured here',
};

// ================= Test B: new domains, early detection =================
const opByReg = new Map();
for (const [d, u] of op) { const r = regOf(u); if (!r) continue; if (!opByReg.has(r)) opByReg.set(r, []); opByReg.get(r).push(d); }
const pct = (a, b) => (b ? +(a / b).toFixed(4) : null);
const median = xs => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const blank = () => ({ names: 0, flagged_strict: 0, flagged_cautious: 0, confirmed: 0, confirmed_flagged_strict: 0, confirmed_flagged_cautious: 0, leads: [] });
function summarize(L) {
  return {
    names: L.names, flagged_strict: L.flagged_strict, flagged_cautious: L.flagged_cautious, confirmed: L.confirmed,
    precision_strict: pct(L.confirmed_flagged_strict, L.flagged_strict),
    precision_cautious: pct(L.confirmed_flagged_cautious, L.flagged_cautious),
    base_rate_confirmed: pct(L.confirmed, L.names),
    recall_strict_on_confirmed: pct(L.confirmed_flagged_strict, L.confirmed),
    lead_days_median: median(L.leads),
    lead_days_min: L.leads.length ? Math.min(...L.leads) : null,
    lead_days_max: L.leads.length ? Math.max(...L.leads) : null,
  };
}
const ALL = blank();
const perList = {};
for (const D of ['2026-11-22', '2026-11-23']) {
  const names = [...new Set(fs.readFileSync(path.join(RAW, 'nrd', D + '.txt'), 'utf8').split('\n').map(l => l.trim().toLowerCase()).filter(Boolean))];
  const L = blank();
  for (const name of names) {
    const url = 'https://' + name + '/';
    const v = judgeOffline(url).verdict;
    const strict = v === 'phishing', cautious = v === 'phishing' || v === 'suspicious';
    const later = (opByReg.get(regOf(url)) || []).filter(d => d >= D).sort();
    const conf = later.length > 0;
    const lead = conf ? Math.round((Date.parse(later[0]) - Date.parse(D)) / 86400000) : null;
    L.names++;
    if (strict) L.flagged_strict++;
    if (cautious) L.flagged_cautious++;
    if (conf) { L.confirmed++; if (strict) L.confirmed_flagged_strict++; if (cautious) L.confirmed_flagged_cautious++; L.leads.push(lead); }
  }
  perList[D] = summarize(L);
  for (const k of ['names', 'flagged_strict', 'flagged_cautious', 'confirmed', 'confirmed_flagged_strict', 'confirmed_flagged_cautious']) ALL[k] += L[k];
  ALL.leads.push(...L.leads);
}
const testB = { per_list: perList, combined: summarize(ALL), note: 'small n: the window after each list is one to two days' };

const report = {
  protocol: 'project/docs/RESEARCH_LOG.md, "Unseen-data tests" (24 Nov, late)',
  window: { test_from: TEST_FROM, val_from: VAL_FROM, last_day: lastDay },
  seed: SEED, bootstrap_resamples: B,
  test_A_phishing_database_unseen_by_domain: testA,
  test_B_new_domains_early_detection: testB,
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ test_A: testA, test_B: testB }, null, 2));
