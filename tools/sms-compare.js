// node tools/sms-compare.js [--seed 20261210] [--csv <file>] [--out data/sms-compare-report.json]
// Two on-device SMS candidates on one fresh split: the Naive Bayes model in the app and a logistic regression on the same
// features. Each is trained on the dev half only. The threshold is chosen on the dev half (highest dev recall with dev false
// alarms at most 2 %), then applied once to the test half. Protocol: docs/RESEARCH_LOG.md, "SMS model comparison on a fresh
// split" (25 Nov, written before the run). Counts and intervals only: no message text is written.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { smsTokens } from '../engine/smstokens.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const SEED = Number(arg('--seed', '20261210'));
const CSV = arg('--csv', path.join(ROOT, '..', 'data_raw', 'smishx', 'dataset.csv'));
const OUT = arg('--out', path.join(ROOT, 'data', 'sms-compare-report.json'));
const TARGET_FA = 0.02;
const ALPHA = 1;
const LR = { lambda: 0.01, epochs: 300, lr: 0.5, minCount: 2 };

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

// Naive Bayes, as in the app (engine/smsmodel.js is the same rule with the weights fixed)
function trainNB(docs) {
  const cnt = [new Map(), new Map()], total = [0, 0], n = [0, 0];
  for (const d of docs) { n[d.y]++; for (const w of d.tok) { cnt[d.y].set(w, (cnt[d.y].get(w) || 0) + 1); total[d.y]++; } }
  const vocab = new Set([...cnt[0].keys(), ...cnt[1].keys()]);
  return { cnt, total, n, V: vocab.size, vocab };
}
function scoreNB(m, tok) {
  let s = Math.log(m.n[1] / m.n[0]);
  for (const w of tok) {
    if (!m.vocab.has(w)) continue;
    s += Math.log(((m.cnt[1].get(w) || 0) + ALPHA) / (m.total[1] + ALPHA * m.V)) - Math.log(((m.cnt[0].get(w) || 0) + ALPHA) / (m.total[0] + ALPHA * m.V));
  }
  return s;
}

// Logistic regression on the same features (binary), full-batch gradient descent with an L2 penalty
function trainLR(docs) {
  const df = new Map();
  for (const d of docs) for (const t of d.tok) df.set(t, (df.get(t) || 0) + 1);
  const vocab = new Map();
  for (const [t, c] of df) if (c >= LR.minCount) vocab.set(t, vocab.size);
  const X = docs.map(d => d.tok.filter(t => vocab.has(t)).map(t => vocab.get(t)));
  const Y = docs.map(d => d.y);
  const n = docs.length;
  const w = new Float64Array(vocab.size);
  let b = 0;
  for (let e = 0; e < LR.epochs; e++) {
    const g = new Float64Array(vocab.size);
    let gb = 0;
    for (let k = 0; k < n; k++) {
      let z = b;
      for (const j of X[k]) z += w[j];
      const err = 1 / (1 + Math.exp(-z)) - Y[k];
      gb += err;
      for (const j of X[k]) g[j] += err;
    }
    for (let j = 0; j < w.length; j++) w[j] -= LR.lr * (g[j] / n + LR.lambda * w[j]);
    b -= LR.lr * (gb / n);
  }
  return { w, b, vocab };
}
function scoreLR(m, tok) {
  let z = m.b;
  for (const t of tok) if (m.vocab.has(t)) z += m.w[m.vocab.get(t)];
  return z;
}

// data and the fresh split
const rows = parseCsv(fs.readFileSync(CSV, 'utf8'));
const header = rows[0];
const iSMS = header.indexOf('SMS'), iLabel = header.indexOf('label');
const all = rows.slice(1).map((r, idx) => ({ idx, text: r[iSMS], raw: (r[iLabel] || '').trim().toLowerCase() }))
  .map(x => ({ ...x, label: x.raw === 'smishing' ? 'phishing' : x.raw }))
  .filter(x => (x.label === 'phishing' || x.label === 'legitimate') && x.text);
const r = rng(SEED);
const pos = shuffle(all.filter(x => x.label === 'phishing'), r);
const neg = shuffle(all.filter(x => x.label === 'legitimate'), r);
const half = a => Math.floor(a.length / 2);
const toDoc = (x, y) => ({ tok: smsTokens(x.text), y });
const dev = [...pos.slice(0, half(pos)).map(x => toDoc(x, 1)), ...neg.slice(0, half(neg)).map(x => toDoc(x, 0))];
const test = [...pos.slice(half(pos)).map(x => toDoc(x, 1)), ...neg.slice(half(neg)).map(x => toDoc(x, 0))];
const devPos = dev.filter(d => d.y === 1).length, devNeg = dev.length - devPos;

// one candidate: threshold on dev (highest dev recall with dev false alarms at most TARGET_FA), then one test run
function evaluate(name, score, trainScore) {
  const devScored = dev.map(d => ({ s: trainScore(d.tok), y: d.y }));
  let best = null;
  for (const t of [...new Set(devScored.map(x => x.s))].sort((a, b) => a - b)) {
    const tp = devScored.filter(x => x.y === 1 && x.s >= t).length;
    const fp = devScored.filter(x => x.y === 0 && x.s >= t).length;
    if (fp / devNeg <= TARGET_FA) {
      const rec = tp / devPos;
      if (!best || rec > best.rec || (rec === best.rec && t > best.t)) best = { t, rec, fa: fp / devNeg };
    }
  }
  const c = { tp: 0, fn: 0, fp: 0, tn: 0 };
  const threshold = best ? best.t : Infinity;
  for (const d of test) {
    const flagged = score(d.tok) >= threshold;
    if (d.y === 1) { if (flagged) c.tp++; else c.fn++; }
    else if (flagged) c.fp++; else c.tn++;
  }
  const tPos = c.tp + c.fn, tNeg = c.fp + c.tn;
  return {
    model: name,
    dev: { threshold: best ? best.t : null, recall: best ? +best.rec.toFixed(4) : null, false_alarm: best ? +best.fa.toFixed(4) : null, threshold_met: !!best },
    test: { positives: tPos, negatives: tNeg, ...c,
      recall: +(c.tp / Math.max(1, tPos)).toFixed(4), recall_95ci: wilson(c.tp, tPos),
      false_alarm: +(c.fp / Math.max(1, tNeg)).toFixed(4), false_alarm_95ci: wilson(c.fp, tNeg) },
  };
}

const nb = trainNB(dev);
const lr = trainLR(dev);
const results = [
  evaluate('Naive Bayes (in the app)', tok => scoreNB(nb, tok), tok => scoreNB(nb, tok)),
  evaluate('Logistic regression (same features)', tok => scoreLR(lr, tok), tok => scoreLR(lr, tok)),
];
const report = {
  protocol: 'project/docs/RESEARCH_LOG.md, "SMS model comparison on a fresh split" (25 Nov, written before the run)',
  split: `stratified, seed ${SEED}; dev = first half of each label, test = second half`,
  parameters: { alpha: ALPHA, target_false_alarm: TARGET_FA, logistic_regression: LR },
  dev: { positives: devPos, negatives: devNeg },
  test: { positives: test.filter(d => d.y === 1).length, negatives: test.filter(d => d.y === 0).length },
  results,
  decision_rule: 'the app keeps the Naive Bayes model; a switch needs a team decision from these numbers and a phone test',
  note: 'counts and intervals only; no message text is written; one run per model; the test half was not used for any choice',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
for (const x of results) {
  console.log(`${x.model}: dev threshold ${x.dev.threshold === null ? 'none' : x.dev.threshold.toFixed(3)}; test recall ${(100 * x.test.recall).toFixed(1)} % (${x.test.tp} of ${x.test.positives}), false alarms ${(100 * x.test.false_alarm).toFixed(1)} % (${x.test.fp} of ${x.test.negatives})`);
}
