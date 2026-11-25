// node tools/eval-ai-run.js [--limit 100] [--seed 20261202] [--ai] [--out <file>]
// The AI run. A labelled sample of SMS texts is judged twice: by the rules alone (AI off), then by the rules plus the
// Claude deep check (AI on). AI on runs only with --ai AND an Anthropic key set in the environment (never in a file).
// The AI can only add findings (server/ai-merge.js, the web page's rule). Protocol: project/docs/RESEARCH_LOG.md,
// "AI run on a labelled SMS sample" (25 Nov, written before the run). Counts and intervals only: no text is written.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze, fuse } from '../engine/index.js';
import { deepCheck } from '../server/ai.js';
import { mergeAi } from '../server/ai-merge.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const LIMIT = Number(arg('--limit', '100'));           // total messages: half smishing, half legitimate
const SEED = Number(arg('--seed', '20261202'));
const CSV = process.env.VETO_SMS_CSV || path.resolve(ROOT, '..', 'veto-team', 'data_raw', 'smishx', 'dataset.csv');
const OUT = arg('--out', path.resolve(ROOT, '..', 'veto-team', 'project', 'data', 'ai-run-report.json'));
const WARN = new Set(['caution', 'high', 'scam', 'otp']);  // any verdict that shows a warning
const KEY_SET = !!(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN);
const RUN_AI = args.includes('--ai') && KEY_SET;

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

// the sample: the same labels as the SMS work (smishing = phishing; spam excluded)
const rows = parseCsv(fs.readFileSync(CSV, 'utf8'));
const header = rows[0];
const iSMS = header.indexOf('SMS'), iLabel = header.indexOf('label');
const all = rows.slice(1).map((r, idx) => ({ idx, text: r[iSMS], raw: (r[iLabel] || '').trim().toLowerCase() }))
  .map(x => ({ ...x, label: x.raw === 'smishing' ? 'phishing' : x.raw }))
  .filter(x => (x.label === 'phishing' || x.label === 'legitimate') && x.text);
const r = rng(SEED);
const half = Math.floor(LIMIT / 2);
const sample = [
  ...shuffle(all.filter(x => x.label === 'phishing'), r).slice(0, half).map(x => ({ ...x, y: 1 })),
  ...shuffle(all.filter(x => x.label === 'legitimate'), r).slice(0, half).map(x => ({ ...x, y: 0 })),
];

const off = { tp: 0, fn: 0, fp: 0, tn: 0 };
const on = { tp: 0, fn: 0, fp: 0, tn: 0 };
let aiErrors = 0, model = null;
const bump = (c, y, warned) => { if (y === 1) { if (warned) c.tp++; else c.fn++; } else if (warned) c.fp++; else c.tn++; };

for (const x of sample) {
  const report = fuse(analyze({ text: x.text, channel: 'sms' }), []);
  bump(off, x.y, WARN.has(report.verdict));
  if (RUN_AI) {
    let ai;
    try { ai = await deepCheck({ text: x.text, channel: 'sms' }); } catch { ai = { error: 'request failed' }; }
    model = model || ai.model || null;
    const failed = !!(ai.error || ai.refused || ai.risk === undefined);
    if (failed) aiErrors++;
    const merged = failed ? report : mergeAi(report, ai);   // an error counts as no AI finding
    bump(on, x.y, WARN.has(merged.verdict));
  }
}

const summarise = c => {
  const pos = c.tp + c.fn, neg = c.fp + c.tn;
  return { ...c, positives: pos, negatives: neg,
    recall: +(c.tp / Math.max(1, pos)).toFixed(4), recall_95ci: wilson(c.tp, pos),
    false_alarm: +(c.fp / Math.max(1, neg)).toFixed(4), false_alarm_95ci: wilson(c.fp, neg) };
};
const report = {
  protocol: 'project/docs/RESEARCH_LOG.md, "AI run on a labelled SMS sample" (25 Nov, written before the run)',
  sample: { messages: sample.length, phishing: half, legitimate: half, seed: SEED, source: path.basename(CSV) },
  warned_when_verdict_is: [...WARN],
  rules_only: summarise(off),
  with_ai: RUN_AI ? { ...summarise(on), ai_errors: aiErrors, model } : 'not run (needs --ai and ANTHROPIC_API_KEY set in the environment)',
  note: 'counts and intervals only; no message text is written',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
const show = s => `recall ${(100 * s.recall).toFixed(1)} % (${s.tp} of ${s.positives}), false alarms ${(100 * s.false_alarm).toFixed(1)} % (${s.fp} of ${s.negatives})`;
console.log(`rules only: ${show(report.rules_only)}`);
console.log(RUN_AI ? `rules + AI:  ${show(report.with_ai)}; AI errors ${aiErrors}` : 'rules + AI: not run (set ANTHROPIC_API_KEY and pass --ai)');
console.log(`written: ${OUT}`);
