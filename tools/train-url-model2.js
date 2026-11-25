// node --max-old-space-size=6144 tools/train-url-model2.js --data <dir from tools/url-dataset.js> --phiusiil <csv> --tranco <csv>
// Trains the full-URL model (engine/urlml2.js) -> data/urlml2-model.json.gz, with an honest TIME split:
//   phishing test  = OpenPhish URLs first seen in the last 30 days of the history (never seen in training),
//                    reported again for phishing DOMAINS never seen in training ("brand-new sites")
//   validation     = the 3 weeks before that (threshold and epoch chosen here, never on the test set)
//   legitimate     = crawled deep links + PhiUSIIL legitimate sites + Tranco homepages, split BY DOMAIN
//   UAE official   = every crawled URL on the 77 official UAE institutions' sites: test only, must stay clean
import fs from 'node:fs';
import zlib from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { featurizeUrl, BITS2, parseUrl } from '../engine/urlml2.js';
import { splitDomain } from '../engine/url.js';
import { INSTITUTIONS } from '../data/institutions.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const DATA = arg('--data');
const OFFICIAL_TRAIN = args.includes('--official-as-legit');
const fnv = s => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return h >>> 0; };
const regOf = u => { const x = parseUrl(u); return x ? splitDomain(x.hostname.toLowerCase().replace(/^www\d?\./, '')).registrable : ''; };
const bucket = reg => fnv('split2:' + reg) % 10; // 0 = test, 1 = validation, else train (legitimate side)
const OFFICIAL = new Set(INSTITUTIONS.flatMap(i => i.domains));
let seed = 7;
const rand = () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 4294967296);

const train = [], val = [], test = [], uae = [];
const add = (arr, url, y, src, extra = {}) => arr.push({ url, y, src, ...extra });

// ---- phishing: OpenPhish history (dated) ------------------------------------------------------
const op = fs.readFileSync(path.join(DATA, 'openphish_history.tsv'), 'utf8').split('\n').map(l => l.split('\t')).filter(x => x[1]);
const days = [...new Set(op.map(x => x[0]))].sort();
const lastDay = days[days.length - 1];
const minus = (d, n) => new Date(Date.parse(d) - n * 86400000).toISOString().slice(0, 10);
const TEST_FROM = arg('--test-from', minus(lastDay, 30)), VAL_FROM = minus(TEST_FROM, 21);
const trainPhishRegs = new Set();
for (const [d, u] of op) {
  if (d >= TEST_FROM) continue;
  if (d >= VAL_FROM) add(val, u, 1, 'openphish_val');
  else { add(train, u, 1, 'openphish'); trainPhishRegs.add(regOf(u)); }
}
const testWindowRegs = new Set(op.filter(x => x[0] >= VAL_FROM).map(x => regOf(x[1])));
// ---- phishing: Phishing.Database (undated): training only, minus anything that shares a domain with val/test ----
const pdb = fs.readFileSync(path.join(DATA, 'pdb_active.txt'), 'utf8').split('\n').filter(Boolean);
let pdbKept = 0;
for (let k = 0; k < pdb.length && pdbKept < 160000; k++) {
  const u = pdb[Math.floor(rand() * pdb.length)];
  const r = regOf(u);
  if (!r || testWindowRegs.has(r)) continue;
  add(train, u, 1, 'phishing_database'); trainPhishRegs.add(r); pdbKept++;
}
// ---- PhiUSIIL (2024): phishing -> training only; legitimate -> split by domain ----------------
for (const line of fs.readFileSync(arg('--phiusiil'), 'utf8').replace(/^﻿/, '').split(/\r?\n/).slice(1)) {
  const m = /^[^,]*,([^,]*),/.exec(line);
  if (!m) continue;
  const y = line.trim().endsWith(',0') ? 1 : 0; // PhiUSIIL: label 0 = phishing
  const r = regOf(m[1]);
  if (!r || OFFICIAL.has(r)) continue;
  if (y) { if (!testWindowRegs.has(r)) { add(train, m[1], 1, 'phiusiil'); trainPhishRegs.add(r); } continue; }
  const b = bucket(r);
  add(b === 0 ? test : b === 1 ? val : train, m[1], 0, 'phiusiil_legit');
}
// ---- legitimate deep links (crawl) + Tranco homepages ----------------------------------------
// Optional: labelled SYNTHETIC phishing rows, added to the TRAINING set only (never to validation or test).
if (arg('--synthetic')) { let n = 0; for (const line of fs.readFileSync(arg('--synthetic'), 'utf8').split('\n').slice(1)) { const [y, , , url] = line.split('\t'); if (y === '1' && url) { add(train, url, 1, 'synthetic_phishing'); n++; } } console.log('synthetic (labelled) phishing rows added to training: ' + n); }
for (const line of fs.readFileSync(path.join(DATA, 'legit_crawl.tsv'), 'utf8').split('\n')) {
  const [dom, kind, u] = line.split('\t');
  if (!u) continue;
  const r = regOf(u);
  if (!r) continue;
  if (OFFICIAL.has(r) || OFFICIAL.has(dom)) {
    // Default (the shipped model): official UAE pages are NEVER trained on; they are only checked (model-only false alarms).
    // Experiment --official-as-legit (rejected 24 Nov, see docs/RESEARCH_LOG.md): use them as legit training data
    // split by domain. It did not reduce held-out UAE false alarms (1 of 192 both ways) and raised test false alarms.
    if (!OFFICIAL_TRAIN) { if (kind !== 'out') uae.push({ url: u, y: 0, src: 'uae_official' }); continue; }
    const b = bucket(r);
    if (b === 0) { if (kind !== 'out') uae.push({ url: u, y: 0, src: 'uae_official' }); }
    else add(b === 1 ? val : train, u, 0, 'uae_official_legit');
    continue;
  }
  const b = bucket(r);
  add(b === 0 ? test : b === 1 ? val : train, u, 0, kind === 'out' ? 'crawl_outbound' : 'crawl');
}
const tr = fs.readFileSync(arg('--tranco'), 'utf8').split(/\r?\n/);
for (let k = 0; k < 60000; k++) {
  const d = (tr[Math.floor(rand() * 100000)] || '').split(',')[1];
  if (!d || OFFICIAL.has(d)) continue;
  const b = bucket(d);
  add(b === 0 ? test : b === 1 ? val : train, `https://${d}/`, 0, 'tranco_home');
}
// ---- phishing test: the newest 30 days ----------------------------------------------------------
for (const [d, u] of op) if (d >= TEST_FROM) add(test, u, 1, 'openphish_test', { newDomain: !trainPhishRegs.has(regOf(u)) });

// dedupe (a URL lives in one split only; the earliest split wins: test > val > train)
const seen = new Set();
const dedupe = arr => arr.filter(r => { const k = r.url.trim().toLowerCase(); if (seen.has(k)) return false; seen.add(k); return true; });
const TEST = dedupe(test), VAL = dedupe(val), TRAIN = dedupe(train), UAE = dedupe(uae);
const count = (a, y) => a.filter(r => r.y === y).length;
console.log(`time split: train < ${VAL_FROM} <= validation < ${TEST_FROM} <= test <= ${lastDay}`);
console.log(`train ${TRAIN.length} (phish ${count(TRAIN, 1)}, legit ${count(TRAIN, 0)}) · val ${VAL.length} (phish ${count(VAL, 1)}) · test ${TEST.length} (phish ${count(TEST, 1)}, new-domain phish ${TEST.filter(r => r.newDomain).length}) · UAE official ${UAE.length}`);

// the held-out lists, so the whole URL Judge (not only the model) can be scored on exactly the same URLs
const dump = (name, arr) => fs.writeFileSync(path.join(DATA, name), 'label\tsource\tnew_domain\turl\n' + arr.map(r => `${r.y}\t${r.src}\t${r.newDomain ? 1 : 0}\t${r.url.replace(/[\t\n]/g, ' ')}`).join('\n'));
dump('split_val.tsv', VAL); dump('split_test.tsv', TEST); dump('split_uae.tsv', UAE);

// class balance: equal total weight per class; deep legitimate links count a bit more (they teach "a path is normal")
const wp = 1, wl = count(TRAIN, 1) / Math.max(1, count(TRAIN, 0));
for (const r of TRAIN) r.w = r.y ? wp : wl * (r.src === 'crawl' ? 1.5 : 1);

// ---- logistic regression, AdaGrad, features recomputed each epoch (low memory) ----------------
const D = 1 << BITS2;
const w = new Float32Array(D), g2 = new Float32Array(D).fill(1e-6);
let b = 0, gb = 1e-6;
const LR = Number(arg('--lr', 0.08)), L2 = 1e-6, EPOCHS = Number(arg('--epochs', 3));
const cache = new Map();
const vec = u => { let v = cache.get(u); if (!v) { const f = featurizeUrl(u).feats; v = { i: Int32Array.from(f.keys()), v: Float32Array.from(f.values()) }; if (cache.size < 700000) cache.set(u, v); } return v; };
const score = (u, W = w, B = b) => { const x = vec(u); let z = B; for (let k = 0; k < x.i.length; k++) z += W[x.i[k]] * x.v[k]; return 1 / (1 + Math.exp(-z)); };
function auc(rows, f) {
  const s = rows.map(r => [f(r), r.y]).sort((a, c) => a[0] - c[0]);
  let pos = 0, neg = 0, rank = 0, sum = 0;
  for (const [, y] of s) { rank++; if (y) { pos++; sum += rank; } else neg++; }
  return (sum - pos * (pos + 1) / 2) / Math.max(1, pos * neg);
}
let best = { auc: 0 };
for (let ep = 1; ep <= EPOCHS; ep++) {
  for (let k = TRAIN.length - 1; k > 0; k--) { const j = Math.floor(rand() * (k + 1)); [TRAIN[k], TRAIN[j]] = [TRAIN[j], TRAIN[k]]; }
  let n = 0;
  for (const r of TRAIN) {
    const x = vec(r.url);
    let z = b;
    for (let k = 0; k < x.i.length; k++) z += w[x.i[k]] * x.v[k];
    const g = (1 / (1 + Math.exp(-z)) - r.y) * r.w;
    for (let k = 0; k < x.i.length; k++) { const i = x.i[k], gi = g * x.v[k] + L2 * w[i]; g2[i] += gi * gi; w[i] -= LR * gi / Math.sqrt(g2[i]); }
    gb += g * g; b -= LR * g / Math.sqrt(gb);
    if (++n % 100000 === 0) process.stdout.write(`\r epoch ${ep}: ${n}/${TRAIN.length}   `);
  }
  const a = auc(VAL, r => score(r.url));
  console.log(`\repoch ${ep}: validation AUC ${a.toFixed(4)}            `);
  if (a > best.auc) best = { auc: a, w: Float32Array.from(w), b, ep };
}
w.set(best.w); b = best.b;

// ---- prune + quantise -----------------------------------------------------------------------------
const MAXW = Number(arg('--max-weights', 200000));
const order = [];
for (let i = 0; i < D; i++) if (Math.abs(w[i]) >= 0.01) order.push(i);
order.sort((x, y) => Math.abs(w[y]) - Math.abs(w[x]));
const kept = order.slice(0, MAXW).sort((x, y) => x - y);
let maxAbs = 0; for (const i of kept) maxAbs = Math.max(maxAbs, Math.abs(w[i]));
const scale = maxAbs / 127;
const Wq = new Float32Array(D), vals = Buffer.alloc(kept.length), varints = [];
let prev = 0;
kept.forEach((i, k) => { const q = Math.max(-127, Math.min(127, Math.round(w[i] / scale))); vals[k] = q & 0xff; Wq[i] = q * scale; let d = i - prev; prev = i; do { let by = d & 0x7f; d >>>= 7; if (d) by |= 0x80; varints.push(by); } while (d); });
const P = u => score(u, Wq, b);

// ---- threshold on VALIDATION: best F1 with false alarms <= 1 % ------------------------------------
function at(rows, ps, t) {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  rows.forEach((r, k) => { const hit = ps[k] >= t; if (hit && r.y) tp++; else if (hit) fp++; else if (r.y) fn++; else tn++; });
  const precision = tp / Math.max(1, tp + fp), recall = tp / Math.max(1, tp + fn);
  return { t: +t.toFixed(4), precision: +precision.toFixed(4), recall: +recall.toFixed(4), f1: +(2 * precision * recall / Math.max(1e-9, precision + recall)).toFixed(4), fpr: +(fp / Math.max(1, fp + tn)).toFixed(4), tp, fp, fn, tn };
}
const vps = VAL.map(r => P(r.url));
let thr = { f1: -1 };
for (let t = 0.3; t <= 0.995; t += 0.005) { const m = at(VAL, vps, t); if (m.fpr <= 0.01 && m.f1 > thr.f1) thr = m; }
console.log('validation at chosen threshold:', JSON.stringify(thr));

// ---- TEST (never used above) ------------------------------------------------------------------------
const tps = TEST.map(r => P(r.url));
const recallAtFpr = (rows, ps, fpr) => {
  const neg = ps.filter((p, k) => !rows[k].y).sort((x, y) => y - x);
  const t = neg[Math.floor(fpr * neg.length)] ?? 1;
  return +(rows.filter((r, k) => r.y && ps[k] > t).length / Math.max(1, rows.filter(r => r.y).length)).toFixed(4);
};
const sub = pred => { const idx = TEST.map((r, k) => k).filter(k => pred(TEST[k])); return [idx.map(k => TEST[k]), idx.map(k => tps[k])]; };
const [nd, ndp] = sub(r => !r.y || r.newDomain);
const bySource = {};
for (const src of [...new Set(TEST.map(r => r.src))]) {
  const [rows, ps] = sub(r => r.src === src);
  const m = at(rows, ps, thr.t);
  bySource[src] = rows[0]?.y ? { n: rows.length, recall: m.recall } : { n: rows.length, fpr: m.fpr };
}
const uaeP = UAE.map(r => P(r.url));
const report = {
  split: { train_before: VAL_FROM, validation: [VAL_FROM, TEST_FROM], test: [TEST_FROM, lastDay], train: TRAIN.length, validation_n: VAL.length, test_n: TEST.length },
  threshold: thr.t, validation: thr,
  test: { ...at(TEST, tps, thr.t), auc: +auc(TEST, r => P(r.url)).toFixed(4), recall_at_fpr_0_1pct: recallAtFpr(TEST, tps, 0.001), recall_at_fpr_1pct: recallAtFpr(TEST, tps, 0.01) },
  test_new_domains: { ...at(nd, ndp, thr.t), note: 'phishing only on registrable domains never seen in any training phishing' },
  test_by_source: bySource,
  uae_official: { urls: UAE.length, above_threshold: UAE.filter((r, k) => uaeP[k] >= thr.t).map(r => r.url).slice(0, 20), max: +Math.max(0, ...uaeP).toFixed(4) }
};
console.log(JSON.stringify(report, null, 1));
const version = `veto-url2-${new Date().toISOString().slice(0, 10)}`;
fs.writeFileSync(arg('--out-model', path.join(ROOT, 'data', 'urlml2-model.json.gz')), zlib.gzipSync(JSON.stringify({ version, bias: +b.toFixed(6), scale, threshold: thr.t, weights: kept.length,
  idx: Buffer.from(varints).toString('base64'), val: vals.toString('base64'), report }), { level: 9 }));
fs.writeFileSync(arg('--out-report', path.join(ROOT, 'data', 'urlml2-report.json')), JSON.stringify({ version, ...report }, null, 1));
console.log(`wrote data/urlml2-model.json.gz (${kept.length} weights, ${(fs.statSync(arg('--out-model', path.join(ROOT, 'data', 'urlml2-model.json.gz'))).size / 1024).toFixed(0)} KB)`);
