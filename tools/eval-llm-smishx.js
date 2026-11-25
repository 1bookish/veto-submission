// node tools/eval-llm-smishx.js [--csv <SmishX dataset.csv>] [--model llama-3.3-70b-versatile] [--out data/llm-smishx-report.json]
// Zero-shot LLM second opinion on the SmishX dataset, pre-registered in docs/RESEARCH_LOG.md (24 Nov, late).
// The API key is read ONLY from the environment (GROQ_API_KEY). It is never written to a file and never printed.
// Writes counts and per-message answers without any message text.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const CSV = arg('--csv', path.join(ROOT, '..', 'data_raw', 'smishx', 'dataset.csv'));
const MODEL = arg('--model', 'qwen/qwen3.8-27b');
const OUT = arg('--out', path.join(ROOT, 'data', 'llm-smishx-report.json'));
const KEY = process.env.GROQ_API_KEY;
if (!KEY) { console.error('GROQ_API_KEY is not set in the environment.'); process.exit(2); }

// fixed before the run; not changed after seeing any result
const SYSTEM = 'You check text messages for fraud. Answer PHISHING if the message is a scam or phishing attempt, for example a fake bank, delivery, government or account alert that asks the reader to click a link, pay a fee, or give codes or personal details. Answer LEGITIMATE otherwise. Reply with one word: PHISHING or LEGITIMATE.';

// CSV parser that handles quoted fields with commas, newlines and doubled quotes
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

const rows = parseCsv(fs.readFileSync(CSV, 'utf8'));
const header = rows[0];
const iSMS = header.indexOf('SMS'), iLabel = header.indexOf('label');
const items = rows.slice(1).filter(r => r.length > iLabel).map(r => {
  const l = r[iLabel].trim().toLowerCase();
  return { text: r[iSMS], label: l === 'smishing' ? 'phishing' : l };
}).filter(x => x.label === 'phishing' || x.label === 'legitimate');

async function ask(text, attempt = 0) {
  const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: MODEL, temperature: 0, max_tokens: 5, messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: text }] }),
    signal: AbortSignal.timeout(60000),
  });
  if ((r.status === 429 || r.status >= 500) && attempt < 6) {
    await new Promise(s => setTimeout(s, 1500 * 2 ** attempt));
    return ask(text, attempt + 1);
  }
  if (!r.ok) throw new Error('HTTP ' + r.status); // status only: never print the response body or the key
  const j = await r.json();
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
await Promise.all([worker(), worker()]);

const wilson = (k, n) => { if (!n) return [null, null]; const z = 1.959964, p = k / n, d = 1 + z * z / n; const c = (p + z * z / (2 * n)) / d, h = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d; return [+Math.max(0, c - h).toFixed(4), +Math.min(1, c + h).toFixed(4)]; };
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
  protocol: 'project/docs/RESEARCH_LOG.md, "Zero-shot LLM second opinion on SmishX" (24 Nov, late)',
  model: MODEL, provider: 'Groq (not Claude)', temperature: 0, max_tokens: 5,
  positives: tp + fn, negatives: fp + tn,
  recall: +(tp / (tp + fn)).toFixed(4), recall_95ci: wilson(tp, tp + fn),
  false_alarm_rate: +(fp / (fp + tn)).toFixed(4), false_alarm_95ci: wilson(fp, fp + tn),
  unparsed, request_errors: errors, minutes: +((Date.now() - t0) / 60000).toFixed(1),
  note: 'zero-shot, one run, no tuning on this data; counts only, no message text stored',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
