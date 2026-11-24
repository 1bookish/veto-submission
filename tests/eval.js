// npm run eval, development corpus (the engine was tuned on it)
// npm run eval -- --holdout, held-out corpus (never tuned on: the honest number)
// A message counts as "flagged" when the verdict is scam or high-risk.
import { analyze } from '../engine/index.js';
import { CORPUS as DEV } from './corpus.js';
import { HOLDOUT } from './holdout.js';

const CORPUS = process.argv.includes('--holdout') ? HOLDOUT : process.argv.includes('--all') ? [...DEV, ...HOLDOUT] : DEV;
console.log(process.argv.includes('--holdout') ? 'HELD-OUT set (not used for tuning)' : process.argv.includes('--all') ? 'ALL messages' : 'DEVELOPMENT set (used for tuning)');
const verbose = process.argv.includes('-v');
let tp = 0, fp = 0, tn = 0, fn = 0;
const times = [];
const rows = [];
for (const c of CORPUS) {
  const t0 = performance.now();
  const r = analyze({ text: c.text, channel: c.channel, sender: c.sender });
  times.push(performance.now() - t0);
  const flagged = r.verdict === 'scam' || r.verdict === 'high';
  const ok = (c.label === 'scam') === flagged;
  if (c.label === 'scam') flagged ? tp++ : fn++;
  else flagged ? fp++ : tn++;
  rows.push({ id: c.id, label: c.label, verdict: r.verdict, risk: r.risk, ok, type: r.scamType || '', top: r.findings[0]?.title.en || (r.otp ? 'OTP: ' + r.otp.unlocks.en : '') });
}
const pad = (s, n) => String(s).padEnd(n).slice(0, n);
for (const r of rows) if (verbose || !r.ok) console.log(`${r.ok ? '  ' : '✗ '}${pad(r.id, 4)} ${pad(r.label, 6)} ${pad(r.verdict, 8)} ${pad(r.risk.toFixed(2), 5)} ${pad(r.type, 20)} ${r.top}`);
const precision = tp / (tp + fp || 1), recall = tp / (tp + fn || 1);
const f1 = (2 * precision * recall) / (precision + recall || 1);
const fpr = fp / (fp + tn || 1);
times.sort((a, b) => a - b);
const p50 = times[Math.floor(times.length / 2)], p95 = times[Math.floor(times.length * 0.95)];
console.log(`\nCorpus: ${CORPUS.length} messages (${tp + fn} scam / ${tn + fp} legit)`);
console.log(`Confusion: TP ${tp}  FN ${fn}  TN ${tn}  FP ${fp}`);
console.log(`Precision ${(precision * 100).toFixed(1)}%  Recall ${(recall * 100).toFixed(1)}%  F1 ${(f1 * 100).toFixed(1)}%  False-alarm rate ${(fpr * 100).toFixed(1)}%`);
console.log(`Latency on-device: median ${p50.toFixed(2)} ms, p95 ${p95.toFixed(2)} ms (first call includes warm-up)`);
if (process.argv.includes('--json')) console.log(JSON.stringify({ n: CORPUS.length, tp, fn, tn, fp, precision, recall, f1, fpr, p50, p95 }));
process.exitCode = fn + fp > 0 && process.argv.includes('--strict') ? 1 : 0;
