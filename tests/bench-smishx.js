// External benchmark on the SmishX dataset (Wang et al., SOUPS 2025; MIT licence):
// 1,200 real SMS labelled legitimate / spam / phishing, mostly from the US and India.
//   1) download: https://raw.githubusercontent.com/yizhu-joy/SmishX/main/data/dataset.csv
//   2) node tests/bench-smishx.js path/to/dataset.csv [-v] [--json]
// Veto is run UNCHANGED (no tuning on this data). "Flagged" = verdict scam or very-likely.
// Veto's rulebook is UAE-specific, so this measures how its universal rules, link forensics and
// pressure tactics transfer to another country, not its home-turf accuracy.
import fs from 'node:fs';
import { analyze } from '../engine/index.js';

const file = process.argv.slice(2).find(a => !a.startsWith('-'));
if (!file) { console.error('usage: node tests/bench-smishx.js path/to/dataset.csv [-v]'); process.exit(2); }
const verbose = process.argv.includes('-v');

function parseCsv(text) {
  const rows = [];
  let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') q = false;
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

const [header, ...data] = parseCsv(fs.readFileSync(file, 'utf8'));
const iText = header.indexOf('SMS'), iLabel = header.indexOf('label');
const items = data.filter(r => r.length > iLabel).map(r => {
  const l = r[iLabel].trim().toLowerCase();
  return { text: r[iText].trim(), label: l === 'smishing' ? 'phishing' : l }; // the dataset calls phishing "smishing"
});

const dist = {};
const errors = { fn: [], fp: [] };
const times = [];
for (const it of items) {
  const t0 = performance.now();
  const r = analyze({ text: it.text, channel: 'sms' });
  times.push(performance.now() - t0);
  it.verdict = r.verdict;
  it.flagged = r.verdict === 'scam' || r.verdict === 'high';
  it.top = r.findings[0]?.title.en || '';
  dist[it.label] ??= {};
  dist[it.label][r.verdict] = (dist[it.label][r.verdict] || 0) + 1;
  if (it.label === 'phishing' && !it.flagged) errors.fn.push(it);
  if (it.label === 'legitimate' && it.flagged) errors.fp.push(it);
}

function metrics(pos, neg) {
  const tp = pos.filter(x => x.flagged).length, fn = pos.length - tp;
  const fp = neg.filter(x => x.flagged).length, tn = neg.length - fp;
  const p = tp / (tp + fp || 1), r = tp / (tp + fn || 1);
  return { tp, fn, fp, tn, precision: p, recall: r, f1: (2 * p * r) / (p + r || 1), fpr: fp / (fp + tn || 1) };
}
const phish = items.filter(x => x.label === 'phishing');
const legit = items.filter(x => x.label === 'legitimate');
const spam = items.filter(x => x.label === 'spam');
const m1 = metrics(phish, legit);
const m2 = metrics(phish, [...legit, ...spam]);
const pct = x => (x * 100).toFixed(1) + '%';
const show = (name, m) => console.log(`${name.padEnd(34)} TP ${m.tp}  FN ${m.fn}  FP ${m.fp}  TN ${m.tn}  | precision ${pct(m.precision)}  recall ${pct(m.recall)}  F1 ${pct(m.f1)}  false-alarm ${pct(m.fpr)}`);

console.log(`SmishX dataset: ${items.length} messages, ${phish.length} phishing, ${legit.length} legitimate, ${spam.length} spam`);
show('Phishing vs legitimate', m1);
show('Phishing vs legitimate + spam', m2);
console.log(`Spam flagged as scam/very likely: ${spam.filter(x => x.flagged).length}/${spam.length}`);
console.log('Verdicts by label:', JSON.stringify(dist));
times.sort((a, b) => a - b);
console.log(`Latency: median ${times[Math.floor(times.length / 2)].toFixed(2)} ms, p95 ${times[Math.floor(times.length * 0.95)].toFixed(2)} ms`);
if (verbose) {
  const clip = s => s.replace(/\s+/g, ' ').slice(0, 150);
  console.log(`\n--- missed phishing (${errors.fn.length}) ---`);
  for (const e of errors.fn.slice(0, 40)) console.log(`[${e.verdict}] ${clip(e.text)}`);
  console.log(`\n--- false alarms on legitimate (${errors.fp.length}) ---`);
  for (const e of errors.fp) console.log(`[${e.verdict}] ${clip(e.text)}  <= ${e.top}`);
}
if (process.argv.includes('--json')) console.log(JSON.stringify({ n: items.length, phishVsLegit: m1, phishVsRest: m2 }));
