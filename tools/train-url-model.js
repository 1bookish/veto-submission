// node tools/train-url-model.js --phiusiil <PhiUSIIL_Phishing_URL_Dataset.csv> [--openphish <feed.txt>] [--tranco <top-1m.csv>]
// Trains the on-device link model (engine/urlml.js) and writes data/urlml-model.js.
//
// Honest evaluation, in this order:
//   1. PhiUSIIL held-out split BY DOMAIN (no domain appears in both train and test),
//   2. fresh OpenPhish phishing URLs (published today, never seen in training),
//   3. Tranco top sites (real, mostly legitimate) that are not in training: the false-alarm rate,
//   4. every official UAE domain in the Veto rulebook.
// Datasets are NOT stored in the repo (licences, size). PhiUSIIL: CC BY 4.0, Prasad & Chandra 2024.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { featurize, regPart, normHost, BITS } from '../engine/urlml.js';
import { INSTITUTIONS } from '../data/institutions.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = k => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
if (!arg('--phiusiil')) { console.error('usage: node tools/train-url-model.js --phiusiil <csv> [--openphish <feed>] [--tranco <csv>]'); process.exit(1); }

const fnv = s => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); } return h >>> 0; };
const sigmoid = z => 1 / (1 + Math.exp(-z));

// ---- load PhiUSIIL (label 0 = phishing, 1 = legitimate) -----------------------------------
const csv = fs.readFileSync(arg('--phiusiil'), 'utf8').replace(/^﻿/, '');
const byHost = new Map();
for (const line of csv.split(/\r?\n/).slice(1)) {
  if (!line) continue;
  const m = /^[^,]*,([^,]*),/.exec(line);
  if (!m) continue;
  const lab = line.slice(line.lastIndexOf(',') + 1).trim();
  const host = normHost(m[1]);
  if (!host || byHost.has(host)) continue;
  byHost.set(host, lab === '0' ? 1 : 0);
}
const all = [...byHost].map(([host, y]) => ({ host, y, w: 1 }));
const test = [], train = [];
for (const r of all) ((fnv('split:' + regPart(r.host)) % 5) === 0 ? test : train).push(r);
console.log(`PhiUSIIL: ${all.length} unique hosts (${all.filter(r => r.y).length} phishing) -> train ${train.length}, test ${test.length} (split by domain)`);
// Real popular sites as extra LEGITIMATE examples (PhiUSIIL's legitimate side is mostly small homepages,
// so on its own the model learns "big brand name = phishing", because kits put brand names in hosts).
// Tranco ranks 1-200k, minus a 10 % slice held out for testing; ranks 500k-510k stay fully unseen.
let trancoLines = null;
const trancoHeld = [];
if (arg('--tranco')) {
  trancoLines = fs.readFileSync(arg('--tranco'), 'utf8').split(/\r?\n/);
  const phishRegs = new Set(all.filter(r => r.y).map(r => regPart(r.host)));
  let added = 0;
  for (const l of trancoLines.slice(0, 200000)) {
    const h = normHost(l.split(',')[1]);
    if (!h || phishRegs.has(regPart(h))) continue;
    if (fnv('tranco:' + h) % 10 === 0) { trancoHeld.push(h); continue; }
    train.push({ host: h, y: 0, w: 0.7 });
    added++;
  }
  console.log(`Tranco: +${added} legitimate training hosts, ${trancoHeld.length} held out`);
}
for (const r of train) if (r.y) r.w = 1.6; // phishing examples count a little more (classes are now unbalanced)
const trainRegs = new Set(train.map(r => regPart(r.host)));

const vec = h => { const { feats } = featurize(h); return { i: Int32Array.from(feats.keys()), v: Float32Array.from(feats.values()) }; };
for (const r of train) Object.assign(r, vec(r.host));
for (const r of test) Object.assign(r, vec(r.host));

// ---- logistic regression, AdaGrad ----------------------------------------------------------
const D = 1 << BITS;
const w = new Float32Array(D), g2 = new Float32Array(D).fill(1e-6);
let b = 0, gb = 1e-6;
const LR = 0.08, L2 = 2e-6, EPOCHS = 6;
const predict = (r, W = w, B = b) => { let z = B; for (let k = 0; k < r.i.length; k++) z += W[r.i[k]] * r.v[k]; return sigmoid(z); };
function auc(rows, f) {
  const s = rows.map(r => [f(r), r.y]).sort((a, c) => a[0] - c[0]);
  let pos = 0, neg = 0, rank = 0, sumPos = 0;
  for (const [, y] of s) { rank++; if (y) { pos++; sumPos += rank; } else neg++; }
  return (sumPos - pos * (pos + 1) / 2) / (pos * neg);
}
function at(rows, f, t) {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  for (const r of rows) { const p = f(r) >= t; if (p && r.y) tp++; else if (p) fp++; else if (r.y) fn++; else tn++; }
  return { t, precision: +(tp / Math.max(1, tp + fp)).toFixed(4), recall: +(tp / Math.max(1, tp + fn)).toFixed(4), fpr: +(fp / Math.max(1, fp + tn)).toFixed(4) };
}
let seed = 42;
const rand = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 4294967296);
// early stopping on a VALIDATION slice taken from the training side (the test split stays untouched)
const val = [];
for (let k = train.length - 1; k >= 0; k--) if (train[k].w !== 0.7 && fnv('val:' + regPart(train[k].host)) % 10 === 0) val.push(train.splice(k, 1)[0]);
let best = { auc: 0, w: null, b: 0, ep: 0 };
for (let ep = 1; ep <= EPOCHS; ep++) {
  for (let k = train.length - 1; k > 0; k--) { const j = Math.floor(rand() * (k + 1)); [train[k], train[j]] = [train[j], train[k]]; }
  for (const r of train) {
    const g = (predict(r) - r.y) * r.w;
    for (let k = 0; k < r.i.length; k++) {
      const i = r.i[k], gi = g * r.v[k] + L2 * w[i];
      g2[i] += gi * gi;
      w[i] -= LR * gi / Math.sqrt(g2[i]);
    }
    gb += g * g;
    b -= LR * g / Math.sqrt(gb);
  }
  const va = auc(val, r => predict(r));
  console.log(`epoch ${ep}: validation AUC ${va.toFixed(4)}`);
  if (va > best.auc) best = { auc: va, w: Float32Array.from(w), b, ep };
}
w.set(best.w);
b = best.b;
console.log(`kept epoch ${best.ep} (validation AUC ${best.auc.toFixed(4)})`);

// ---- prune + quantise (what ships to phones) -------------------------------------------------
const MAX_WEIGHTS = 45000;
const order = Array.from({ length: D }, (_, i) => i).filter(i => Math.abs(w[i]) >= 0.02).sort((a, c) => Math.abs(w[c]) - Math.abs(w[a]));
const kept = order.slice(0, MAX_WEIGHTS).sort((a, c) => a - c);
let maxAbs = 0;
for (const i of kept) maxAbs = Math.max(maxAbs, Math.abs(w[i]));
const scale = maxAbs / 127;
const Wq = new Float32Array(D);
const vals = new Uint8Array(kept.length);
kept.forEach((i, k) => { const q = Math.max(-127, Math.min(127, Math.round(w[i] / scale))); vals[k] = q & 0xff; Wq[i] = q * scale; });
const varints = [];
let prev = 0;
for (const i of kept) { let d = i - prev; prev = i; do { let byte = d & 0x7f; d >>>= 7; if (d) byte |= 0x80; varints.push(byte); } while (d); }
const shipped = r => predict(r, Wq, b);

// ---- evaluation ---------------------------------------------------------------------------
const report = { phiusiil: { auc: +auc(test, shipped).toFixed(4), at: [0.5, 0.8, 0.9, 0.95].map(t => at(test, shipped, t)) } };
const scoreHost = h => shipped(vec(h));
if (arg('--openphish')) {
  const hosts = [...new Set(fs.readFileSync(arg('--openphish'), 'utf8').split(/\r?\n/).map(normHost).filter(Boolean))];
  const fresh = hosts.filter(h => !trainRegs.has(regPart(h)));
  const sc = fresh.map(scoreHost);
  report.openphish = { hosts: fresh.length, recall: Object.fromEntries([0.5, 0.8, 0.9].map(t => [t, +(sc.filter(p => p >= t).length / fresh.length).toFixed(3)])) };
}
if (trancoLines) {
  const unseen = trancoLines.slice(500000, 510000).map(l => normHost(l.split(',')[1])).filter(Boolean);
  for (const [name, hosts] of [['tranco_heldout_top200k', trancoHeld], ['tranco_unseen_500k_510k', unseen]]) {
    const sc = hosts.map(scoreHost);
    report[name] = { hosts: hosts.length, fpr: Object.fromEntries([0.5, 0.8, 0.9].map(t => [t, +(sc.filter(p => p >= t).length / hosts.length).toFixed(4)])) };
  }
}
const uae = [...new Set(INSTITUTIONS.flatMap(i => i.domains))];
const uaeScores = uae.map(d => [d, +scoreHost(d).toFixed(3)]).sort((a, c) => c[1] - a[1]);
report.uae_official = { domains: uae.length, above_0_5: uaeScores.filter(x => x[1] >= 0.5).map(x => x.join(' ')), highest: uaeScores.slice(0, 5).map(x => x.join(' ')) };
console.log(JSON.stringify(report, null, 1));

const meta = { version: `phiusiil-lr-${new Date().toISOString().slice(0, 10)}`, trainHosts: train.length, testHosts: test.length, weights: kept.length, report };
fs.writeFileSync(path.join(ROOT, 'data', 'urlml-model.js'),
  `// Generated by tools/train-url-model.js. Logistic regression on hashed host-name features (engine/urlml.js),\n` +
  `// trained on PhiUSIIL (UCI, CC BY 4.0), split by domain. Metrics below are on data the model never saw.\n` +
  `export const MODEL = ${JSON.stringify({ version: meta.version, bias: +b.toFixed(6), scale: +scale.toFixed(8), weights: kept.length, idx: Buffer.from(varints).toString('base64'), val: Buffer.from(vals).toString('base64') })};\n` +
  `export const MODEL_REPORT = ${JSON.stringify(meta, null, 1)};\n`);
console.log(`wrote data/urlml-model.js: ${kept.length} weights, ${(fs.statSync(path.join(ROOT, 'data', 'urlml-model.js')).size / 1024).toFixed(0)} KB`);
