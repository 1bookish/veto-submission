// node tools/eval-sms-second-opinion.js --phase dev|test --prompt P1|P2 [--workers 3] [--out <file>]
// Held-out design for the SMS cloud second opinion. Protocol: docs/RESEARCH_LOG.md, "SMS second opinion, held-out
// split" (24 Nov, evening; written before any run). The split is stratified and seeded (20261125): half of the
// smishing messages and half of the legitimate ones form the dev set; the other halves form the test set.
// GROQ_API_KEY is read ONLY from the environment. The output keeps counts and per-message answers
// (CSV row index, label, answer). No message text is written.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const PHASE = arg('--phase', 'dev');
const PROMPT = arg('--prompt', 'P1');
const WORKERS = Math.max(1, Number(arg('--workers', '3')));
const CSV = arg('--csv', path.join(ROOT, '..', 'data_raw', 'smishx', 'dataset.csv'));
const OUT = arg('--out', path.join(ROOT, 'data', `sms-second-opinion-${PHASE}-${PROMPT}.json`));
const KEY = process.env.GROQ_API_KEY;
if (!KEY) { console.error('GROQ_API_KEY is not set in the environment.'); process.exit(2); }
const MODEL = 'qwen/qwen3.8-27b';

// P1 is the research prompt, unchanged since the zero-shot run. P2 adds the common cues. Both fixed before the dev run.
const P1 = 'You check text messages for fraud. Answer PHISHING if the message is a scam or phishing attempt, for example a fake bank, delivery, government or account alert that asks the reader to click a link, pay a fee, or give codes or personal details. Answer LEGITIMATE otherwise. Reply with one word: PHISHING or LEGITIMATE.';
const P2 = P1 + ' Signs that often appear in scam texts: a link to act on, a deadline or threat, a request for a code, a payment or personal details, a parcel, a prize or refund, an account that is locked or suspended.';
const SYSTEM = { P1, P2 }[PROMPT];
if (!SYSTEM) { console.error('unknown prompt ' + PROMPT); process.exit(2); }

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

const rows = parseCsv(fs.readFileSync(CSV, 'utf8'));
const header = rows[0];
const iSMS = header.indexOf('SMS'), iLabel = header.indexOf('label');
const all = rows.slice(1).map((r, idx) => ({ idx, text: r[iSMS], raw: (r[iLabel] || '').trim().toLowerCase() }))
  .map(x => ({ ...x, label: x.raw === 'smishing' ? 'phishing' : x.raw }))
  .filter(x => (x.label === 'phishing' || x.label === 'legitimate') && x.text);
const r = rng(20261125);
const pos = shuffle(all.filter(x => x.label === 'phishing'), r);
const neg = shuffle(all.filter(x => x.label === 'legitimate'), r);
const half = (a) => Math.floor(a.length / 2);
const dev = [...pos.slice(0, half(pos)), ...neg.slice(0, half(neg))];
const test = [...pos.slice(half(pos)), ...neg.slice(half(neg))];
const items = PHASE === 'test' ? test : dev;

const wilson = (k, n) => { if (!n) return [null, null]; const z = 1.959964, p = k / n, d = 1 + z * z / n; const c = (p + z * z / (2 * n)) / d, h = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d; return [+Math.max(0, c - h).toFixed(4), +Math.min(1, c + h).toFixed(4)]; };

async function ask(text, attempt = 0) {
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: MODEL, temperature: 0, max_tokens: 5, messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: text }] }),
    signal: AbortSignal.timeout(60000),
  });
  if ((res.status === 429 || res.status >= 500) && attempt < 6) {
    await new Promise(s => setTimeout(s, 1500 * 2 ** attempt));
    return ask(text, attempt + 1);
  }
  if (!res.ok) throw new Error('HTTP ' + res.status); // the status only: never the response body or the key
  const j = await res.json();
  return String(j.choices?.[0]?.message?.content || '').trim().toUpperCase();
}

const answers = new Array(items.length).fill(null);
let next = 0, errors = 0;
async function worker() {
  while (next < items.length) {
    const i = next++;
    try { answers[i] = await ask(items[i].text); } catch (e) { errors++; answers[i] = 'ERROR ' + e.message; }
  }
}
const t0 = Date.now();
await Promise.all(Array.from({ length: WORKERS }, () => worker()));

let tp = 0, fn = 0, fp = 0, tn = 0, unparsed = 0;
items.forEach((it, i) => {
  const a = answers[i] || '';
  const flagged = a.includes('PHISHING');
  const clear = flagged || a.includes('LEGITIMATE');
  if (!clear) unparsed++;
  if (it.label === 'phishing') { if (flagged) tp++; else fn++; }
  else { if (flagged) fp++; else tn++; }
});
const report = {
  protocol: 'project/docs/RESEARCH_LOG.md, "SMS second opinion, held-out split" (24 Nov, evening)',
  phase: PHASE, prompt: PROMPT, model: MODEL, provider: 'Groq (not Claude)', temperature: 0, max_tokens: 5,
  split: 'stratified, seed 20261125; dev = first half of each label, test = second half',
  positives: tp + fn, negatives: fp + tn,
  recall: +(tp / Math.max(1, tp + fn)).toFixed(4), recall_95ci: wilson(tp, tp + fn),
  false_alarm_rate: +(fp / Math.max(1, fp + tn)).toFixed(4), false_alarm_95ci: wilson(fp, fp + tn),
  unparsed, request_errors: errors, minutes: +((Date.now() - t0) / 60000).toFixed(1),
  per_item: items.map((it, i) => ({ row: it.idx, label: it.label, answer: answers[i] })),
  note: 'counts and per-message answers only; no message text stored',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
const { per_item, ...summary } = report;
console.log(JSON.stringify(summary, null, 2));
