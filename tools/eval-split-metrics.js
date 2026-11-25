// node tools/eval-split-metrics.js --data <dir> [--out file]
// Strict and cautious precision, recall and false alarms of the offline judge on the held-out URL test split and on the
// crawled official UAE pages (split_test.tsv, split_uae.tsv from tools/train-url-model2.js). Used as a control when a
// rule changes (docs/RESEARCH_LOG.md). Counts only; no URL is written.
import fs from 'node:fs';
import path from 'node:path';
import { judgeOffline, metrics } from '../server/judge.js';
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const DATA = arg('--data');
const read = f => fs.readFileSync(path.join(DATA, f), 'utf8').split('\n').slice(1).filter(Boolean).map(l => { const [y, , , url] = l.split('\t'); return { label: Number(y), url }; });
const out = { switch: process.env.VETO_NO_WATCHLIST === '1' ? 'off (rules before the change)' : 'on' };
for (const [name, file] of [['test', 'split_test.tsv'], ['uae_official', 'split_uae.tsv']]) {
  const rows = read(file).map(r => ({ ...r, ...judgeOffline(r.url), label: r.label }));
  out[name] = metrics(rows);
}
const OUT = arg('--out');
if (OUT) fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify(out));
