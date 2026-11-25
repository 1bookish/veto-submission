// node tools/sms-cv.js --fold <0-4> --cond A|B [--synth 1000000] [--dir data/sms-cv]   one outer fold
// node tools/sms-cv.js --aggregate [--dir data/sms-cv]                                  pooled result and the decision
// node tools/sms-cv.js --ship                                                           train the adopted model on all texts
// Protocol: docs/RESEARCH_LOG.md, "SMS: nested cross-validation, with and without generated texts" (25 Nov, late; written
// before the run). Outputs hold row indexes, labels, scores and thresholds only: no message text is written.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { smsFeatures, SMS_BITS } from '../engine/smsfeatures.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const CSV = arg('--csv', path.join(ROOT, '..', 'data_raw', 'smishx', 'dataset.csv'));
const DIR = path.resolve(ROOT, arg('--dir', path.join('data', 'sms-cv')));
const REPORT = path.join(ROOT, 'data', 'sms-cv-report.json');
const SEED = 20261230;
const SYNTH = Number(arg('--synth', '1000000'));
const LEARN = 0.05, L2 = 1e-6, TARGET_FA = 0.03, CUE_P = 0.3;
const PASSES = { A: 20, B: 2 };            // passes over the real training texts
const D = 1 << SMS_BITS;

function parseCsv(text) {
  const rows = []; let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (c !== '\r') field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows;
}
function rng(seed) {
  let s = seed >>> 0;
  return () => { s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
function shuffle(arr, r) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}
function wilson(k, n) {
  if (!n) return [null, null];
  const z = 1.959964, p = k / n, d = 1 + z * z / n;
  const c = (p + z * z / (2 * n)) / d, h = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d;
  return [+Math.max(0, c - h).toFixed(4), +Math.min(1, c + h).toFixed(4)];
}
const median = a => { const s = [...a].sort((x, y) => x - y); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

// every labelled text: 1 = scam (smishing), 0 = normal (legitimate); spam is excluded, as in every SMS test before
const rows = parseCsv(fs.readFileSync(CSV, 'utf8'));
const header = rows[0];
const iSMS = header.indexOf('SMS'), iLabel = header.indexOf('label');
const docs = rows.slice(1)
  .map((r, idx) => ({ idx, text: r[iSMS], raw: (r[iLabel] || '').trim().toLowerCase() }))
  .filter(x => (x.raw === 'smishing' || x.raw === 'legitimate') && x.text)
  .map(x => ({ i: x.idx, y: x.raw === 'smishing' ? 1 : 0, text: x.text, f: smsFeatures(x.text) }));

function folds(items, k, seed) {
  const r = rng(seed);
  const out = Array.from({ length: k }, () => []);
  shuffle(items.filter(d => d.y === 1), r).forEach((d, i) => out[i % k].push(d));
  shuffle(items.filter(d => d.y === 0), r).forEach((d, i) => out[i % k].push(d));
  return out;
}

// generated texts: an order-2 word Markov chain per class, learned only from the texts it is given
const SEP = '\u0001', END = '\u0002';
function chainOf(texts) {
  const next = new Map(), starts = [];
  const add = (k, w) => { let a = next.get(k); if (!a) next.set(k, a = []); a.push(w); };
  for (const t of texts) {
    const ws = String(t).toLowerCase().split(/\s+/).filter(Boolean);
    if (ws.length < 2) continue;
    starts.push(ws[0] + SEP + ws[1]);
    for (let i = 0; i + 2 < ws.length; i++) add(ws[i] + SEP + ws[i + 1], ws[i + 2]);
    add(ws[ws.length - 2] + SEP + ws[ws.length - 1], END);
  }
  return { next, starts };
}
// cues appended at the same rate for both classes, drawn from a fixed seeded pool (so random strings do not flood the model)
const CUES = (() => {
  const r = rng(SEED + 7), out = [];
  const letters = 'abcdefghijklmnopqrstuvwxyz', tlds = ['com', 'xyz', 'top', 'info', 'net', 'online'];
  const word = n => Array.from({ length: n }, () => letters[Math.floor(r() * 26)]).join('');
  for (let i = 0; i < 1000; i++) out.push(`http://${word(6)}.${tlds[Math.floor(r() * tlds.length)]}`);
  for (let i = 0; i < 1000; i++) out.push(String(100000 + Math.floor(r() * 900000)));
  for (let i = 0; i < 1000; i++) out.push(`AED ${1 + Math.floor(r() * 900)}.${String(Math.floor(r() * 100)).padStart(2, '0')}`);
  return out;
})();
function generate(chain, r) {
  const s = chain.starts[Math.floor(r() * chain.starts.length)].split(SEP);
  const out = [s[0], s[1]];
  for (let n = 0; n < 40; n++) {
    const a = chain.next.get(out[out.length - 2] + SEP + out[out.length - 1]);
    if (!a) break;
    const w = a[Math.floor(r() * a.length)];
    if (w === END) break;
    out.push(w);
  }
  if (r() < CUE_P) out.push(CUES[Math.floor(r() * CUES.length)]);
  return out.join(' ');
}

// logistic regression by stochastic gradient descent on binary hashed features
function train(real, cond, r) {
  const w = new Float32Array(D);
  let b = 0;
  const step = (f, y) => {
    let z = b;
    for (const j of f) z += w[j];
    const g = 1 / (1 + Math.exp(-z)) - y;
    for (const j of f) w[j] -= LEARN * (g + L2 * w[j]);
    b -= LEARN * g;
  };
  if (cond === 'B') {
    const chains = [chainOf(real.filter(d => d.y === 0).map(d => d.text)), chainOf(real.filter(d => d.y === 1).map(d => d.text))];
    for (let n = 0; n < SYNTH; n++) {
      const y = n % 2 === 0 ? 1 : 0;
      step(smsFeatures(generate(chains[y], r)), y);
    }
  }
  for (let e = 0; e < PASSES[cond]; e++) for (const d of shuffle(real, r)) step(d.f, d.y);
  return { w, b };
}
const score = (m, f) => { let z = m.b; for (const j of f) z += m.w[j]; return z; };

// threshold: the highest recall with false alarms at most TARGET_FA; ties go to the higher threshold
function chooseThreshold(scored) {
  const P = scored.filter(x => x.y === 1).length, N = scored.length - P;
  const sorted = [...scored].sort((a, b) => b.s - a.s);
  let tp = 0, fp = 0, best = null;
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i].y === 1) tp++; else fp++;
    if (i + 1 < sorted.length && sorted[i + 1].s === sorted[i].s) continue;
    if (fp / N <= TARGET_FA && (!best || tp / P > best.recall)) best = { t: sorted[i].s, recall: tp / P, fa: fp / N };
  }
  return best || { t: Infinity, recall: 0, fa: 0 };
}

function runFold(k, cond) {
  const outer = folds(docs, 5, SEED);
  const test = outer[k];
  const trainSet = outer.filter((_, i) => i !== k).flat();
  const inner = folds(trainSet, 4, SEED + 100 + k);
  const innerScored = [];
  for (let j = 0; j < 4; j++) {
    const m = train(inner.filter((_, i) => i !== j).flat(), cond, rng(SEED * 10 + k * 7 + j));
    for (const d of inner[j]) innerScored.push({ s: score(m, d.f), y: d.y });
  }
  const th = chooseThreshold(innerScored);
  const m = train(trainSet, cond, rng(SEED * 10 + k * 7 + 9));
  const preds = test.map(d => { const s = score(m, d.f); return { row: d.i, label: d.y, score: +s.toFixed(5), flagged: s >= th.t }; });
  fs.mkdirSync(DIR, { recursive: true });
  const out = { protocol: 'docs/RESEARCH_LOG.md, "SMS: nested cross-validation, with and without generated texts"', fold: k, cond,
    synth: cond === 'B' ? SYNTH : 0, threshold: th.t, inner_recall: +th.recall.toFixed(4), inner_false_alarm: +th.fa.toFixed(4),
    train_texts: trainSet.length, test_texts: test.length, preds };
  fs.writeFileSync(path.join(DIR, `fold-${k}-${cond}.json`), JSON.stringify(out) + '\n');
  const tp = preds.filter(p => p.label === 1 && p.flagged).length, fp = preds.filter(p => p.label === 0 && p.flagged).length;
  console.log(`fold ${k} ${cond}: threshold ${th.t.toFixed(3)}; caught ${tp} of ${preds.filter(p => p.label === 1).length}; false alarms ${fp} of ${preds.filter(p => p.label === 0).length}`);
}

function aggregate() {
  const res = {};
  for (const cond of ['A', 'B']) {
    const files = [0, 1, 2, 3, 4].map(k => path.join(DIR, `fold-${k}-${cond}.json`));
    if (!files.every(f => fs.existsSync(f))) { res[cond] = 'incomplete'; continue; }
    const parts = files.map(f => JSON.parse(fs.readFileSync(f, 'utf8')));
    const c = { tp: 0, fn: 0, fp: 0, tn: 0 };
    for (const p of parts.flatMap(x => x.preds)) { if (p.label === 1) { if (p.flagged) c.tp++; else c.fn++; } else if (p.flagged) c.fp++; else c.tn++; }
    const pos = c.tp + c.fn, neg = c.fp + c.tn;
    res[cond] = { ...c, scam_texts: pos, normal_texts: neg, synth_per_training: parts[0].synth,
      recall: +(c.tp / pos).toFixed(4), recall_95ci: wilson(c.tp, pos), false_alarm: +(c.fp / neg).toFixed(4), false_alarm_95ci: wilson(c.fp, neg),
      thresholds: parts.map(x => x.threshold), median_threshold: median(parts.map(x => x.threshold)) };
  }
  const A = res.A, B = res.B;
  let adopted = 'A', why = 'rule: keep A unless B qualifies and is at least 5 points higher';
  if (typeof A === 'object' && typeof B === 'object') {
    if (B.false_alarm <= TARGET_FA && B.recall >= A.recall + 0.05) { adopted = 'B'; why = 'B has false alarms at most 3 % and recall at least 5 points above A'; }
    else if (A.false_alarm > TARGET_FA && B.false_alarm > TARGET_FA) why = 'neither has false alarms at most 3 %; A is kept';
  }
  const report = { protocol: 'project/docs/RESEARCH_LOG.md, "SMS: nested cross-validation, with and without generated texts" (25 Nov, late)',
    outer_folds: 5, seed: SEED, target_false_alarm: TARGET_FA, A: res.A, B: res.B, adopted, why,
    note: 'every text scored once by a model that never saw it; no message text written' };
  fs.writeFileSync(REPORT, JSON.stringify(report, null, 2) + '\n');
  for (const c of ['A', 'B']) {
    const x = res[c];
    if (typeof x !== 'object') { console.log(`${c}: ${x}`); continue; }
    console.log(`${c}: caught ${(100 * x.recall).toFixed(1)} % (${x.tp} of ${x.scam_texts}; 95 % ${(100 * x.recall_95ci[0]).toFixed(1)} to ${(100 * x.recall_95ci[1]).toFixed(1)}), false alarms ${(100 * x.false_alarm).toFixed(1)} % (${x.fp} of ${x.normal_texts}; 95 % ${(100 * x.false_alarm_95ci[0]).toFixed(1)} to ${(100 * x.false_alarm_95ci[1]).toFixed(1)})`);
  }
  console.log(`adopted: ${adopted} (${why})`);
}

async function ship() {
  const report = JSON.parse(fs.readFileSync(REPORT, 'utf8'));
  const cond = report.adopted;
  const threshold = report[cond].median_threshold;
  const m = train(docs, cond, rng(SEED * 10 + 99));
  const w = [];
  for (let j = 0; j < D; j++) if (m.w[j] !== 0) w.push([j, m.w[j]]);
  const OUT = path.join(ROOT, 'engine', 'smsmodel-data.js');
  fs.writeFileSync(OUT, '// Generated by tools/sms-cv.js --ship from all 881 labelled texts. Do not edit by hand.\n'
    + `export const SMS_MODEL = ${JSON.stringify({ kind: 'logistic-hashed', bits: SMS_BITS, condition: cond, bias: m.b, threshold, w })};\n`);
  const eng = await import(pathToFileURL(path.join(ROOT, 'engine', 'smsmodel.js')).href);
  let same = 0;
  for (const d of docs) if (Math.abs(eng.smsScore(d.text) - score(m, d.f)) < 1e-9) same++;
  console.log(`wrote engine/smsmodel-data.js: condition ${cond}, ${w.length} weights, threshold ${threshold.toFixed(4)}; phone scorer matches the trainer on ${same} of ${docs.length} texts`);
  if (same !== docs.length) process.exit(1);
}

if (args.includes('--aggregate')) aggregate();
else if (args.includes('--ship')) await ship();
else {
  const k = Number(arg('--fold', 'NaN')), cond = arg('--cond', '');
  if (!(k >= 0 && k <= 4) || !['A', 'B'].includes(cond)) { console.error('use --fold 0-4 --cond A|B, or --aggregate, or --ship'); process.exit(2); }
  runFold(k, cond);
}
