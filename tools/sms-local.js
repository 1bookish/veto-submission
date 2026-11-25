// node tools/sms-local.js [--csv <file>] [--out data/sms-local-report.json]
// On-device candidate for the SMS check: a multinomial Naive Bayes model over word unigrams, word pairs and three cues
// (a link, a number of four or more digits, Arabic script). It is trained on the dev half only. The threshold is chosen on
// the dev half (the highest dev recall with dev false alarms at most 2 %), then applied once to the test half. Same split as
// the cloud protocol (stratified, seed 20261125). Protocol: docs/RESEARCH_LOG.md, "SMS local model, held-out split"
// (24 Nov, late). Counts only: no message text is written.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const CSV = arg('--csv', path.join(ROOT, '..', 'data_raw', 'smishx', 'dataset.csv'));
const OUT = arg('--out', path.join(ROOT, 'data', 'sms-local-report.json'));
const TARGET_FA = 0.02;
const ALPHA = 1;

function parseCsv(text) {
  const rows = []; let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; }
      else field += c;
    } else if (c === '"') q = true;
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
function tokens(text) {
  const t = text.toLowerCase();
  const words = t.split(/[^\p{L}\p{N}]+/u).filter(w => w.length > 1 && w.length < 30);
  const out = new Set(words);
  for (let i = 0; i + 1 < words.length; i++) out.add(words[i] + ' ' + words[i + 1]);
  if (/https?:\/\/|www\.|\.(com|net|org|xyz|top|info|site|online|icu|shop|ly|me|co)\b/.test(t)) out.add('__LINK__');
  if (/\d{4,}/.test(t)) out.add('__LONGNUM__');
  if (/[؀-ۿ]/.test(t)) out.add('__ARABIC__');
  return [...out];
}
function train(docs) {
  const cnt = [new Map(), new Map()], total = [0, 0], n = [0, 0];
  for (const d of docs) {
    n[d.y]++;
    for (const w of d.tok) { cnt[d.y].set(w, (cnt[d.y].get(w) || 0) + 1); total[d.y]++; }
  }
  const vocab = new Set([...cnt[0].keys(), ...cnt[1].keys()]);
  return { cnt, total, n, V: vocab.size, vocab };
}
function score(m, tok) {
  let s = Math.log(m.n[1] / m.n[0]);
  for (const w of tok) {
    if (!m.vocab.has(w)) continue;
    s += Math.log(((m.cnt[1].get(w) || 0) + ALPHA) / (m.total[1] + ALPHA * m.V)) - Math.log(((m.cnt[0].get(w) || 0) + ALPHA) / (m.total[0] + ALPHA * m.V));
  }
  return s;
}
function wilson(k, n) {
  if (!n) return [null, null];
  const z = 1.959964, p = k / n, d = 1 + z * z / n;
  const c = (p + z * z / (2 * n)) / d, h = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d;
  return [+Math.max(0, c - h).toFixed(4), +Math.min(1, c + h).toFixed(4)];
}

// data and split: the same code and seed as tools/eval-sms-second-opinion.js
const rows = parseCsv(fs.readFileSync(CSV, 'utf8'));
const header = rows[0];
const iSMS = header.indexOf('SMS'), iLabel = header.indexOf('label');
const all = rows.slice(1).map((r, idx) => ({ idx, text: r[iSMS], raw: (r[iLabel] || '').trim().toLowerCase() }))
  .map(x => ({ ...x, label: x.raw === 'smishing' ? 'phishing' : x.raw }))
  .filter(x => (x.label === 'phishing' || x.label === 'legitimate') && x.text);
const r = rng(20261125);
const pos = shuffle(all.filter(x => x.label === 'phishing'), r);
const neg = shuffle(all.filter(x => x.label === 'legitimate'), r);
const half = a => Math.floor(a.length / 2);
const toDoc = (x, y) => ({ tok: tokens(x.text), y, idx: x.idx });
const dev = [...pos.slice(0, half(pos)).map(x => toDoc(x, 1)), ...neg.slice(0, half(neg)).map(x => toDoc(x, 0))];
const test = [...pos.slice(half(pos)).map(x => toDoc(x, 1)), ...neg.slice(half(neg)).map(x => toDoc(x, 0))];

// train on dev only
const model = train(dev);
const devScored = dev.map(d => ({ s: score(model, d.tok), y: d.y }));
const devPos = devScored.filter(x => x.y === 1).length, devNeg = devScored.length - devPos;
// threshold on dev only: highest dev recall with dev false alarms at most TARGET_FA (ties: the higher threshold)
let best = null;
for (const t of [...new Set(devScored.map(x => x.s))].sort((a, b) => a - b)) {
  const tp = devScored.filter(x => x.y === 1 && x.s >= t).length;
  const fp = devScored.filter(x => x.y === 0 && x.s >= t).length;
  if (fp / devNeg <= TARGET_FA) {
    const rec = tp / devPos;
    if (!best || rec > best.dev_recall || (rec === best.dev_recall && t > best.threshold)) best = { threshold: t, dev_recall: rec, dev_false_alarm: fp / devNeg };
  }
}
const threshold = best ? best.threshold : Infinity;

// the test half, once
const counts = { tp: 0, fn: 0, fp: 0, tn: 0 };
for (const d of test) {
  const flagged = score(model, d.tok) >= threshold;
  if (d.y === 1) { if (flagged) counts.tp++; else counts.fn++; }
  else if (flagged) counts.fp++; else counts.tn++;
}
const testPos = counts.tp + counts.fn, testNeg = counts.fp + counts.tn;
const report = {
  protocol: 'project/docs/RESEARCH_LOG.md, "SMS local model, held-out split" (24 Nov, late)',
  split: 'stratified, seed 20261125; dev = first half of each label, test = second half',
  model: { type: 'multinomial Naive Bayes, Laplace alpha 1', features: 'word unigrams, word pairs, cues: link, four or more digits, Arabic script', vocabulary: model.V, trained_on: 'dev half only' },
  dev: { positives: devPos, negatives: devNeg, threshold: best ? best.threshold : null, recall: best ? +best.dev_recall.toFixed(4) : null, false_alarm: best ? +best.dev_false_alarm.toFixed(4) : null, target_false_alarm: TARGET_FA, threshold_met: !!best },
  test: { positives: testPos, negatives: testNeg, ...counts, recall: +(counts.tp / Math.max(1, testPos)).toFixed(4), recall_95ci: wilson(counts.tp, testPos), false_alarm: +(counts.fp / Math.max(1, testNeg)).toFixed(4), false_alarm_95ci: wilson(counts.fp, testNeg) },
  note: 'counts only; no message text is written; one run; the test half was not used for any choice',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
