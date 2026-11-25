// node tools/eval-scale.js [--n 1000000] [--raw <data_raw folder>] [--out data/scale-report.json]
// Scale check of the offline judge (no network). Half the URLs come from the Phishing.Database active list,
// half from the top of the Tranco list as https domains. Writes counts, timing and memory only; no URL is written.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const N = Number(arg('--n', '1000000'));
const RAW = arg('--raw', path.join(ROOT, '..', 'data_raw'));
const OUT = arg('--out', path.join(ROOT, 'data', 'scale-report.json'));
const half = Math.floor(N / 2);

const phish = fs.readFileSync(path.join(RAW, 'urlv2', 'pdb_active.txt'), 'utf8').split('\n').map(s => s.trim()).filter(Boolean);
const popular = fs.readFileSync(path.join(RAW, 'tranco', 'top-1m.csv'), 'utf8').split('\n')
  .map(l => l.split(',')[1]).filter(d => d && d.includes('.')).map(d => 'https://' + d.trim() + '/');
if (phish.length < half || popular.length < N - half) throw new Error('not enough input lines for ' + N + ' URLs');

const parts = [
  { name: 'phishing_db', urls: phish.slice(0, half) },
  { name: 'popular_domains', urls: popular.slice(0, N - half) },
];
const all = {}, byPart = {};
let errors = 0, peakMb = 0;
const t0 = performance.now();
for (const part of parts) {
  byPart[part.name] = {};
  part.urls.forEach((u, i) => {
    try {
      const r = judgeOffline(u);
      const v = String(r.verdict);
      all[v] = (all[v] || 0) + 1;
      byPart[part.name][v] = (byPart[part.name][v] || 0) + 1;
      if (r.score != null && !Number.isFinite(r.score)) errors++;
    } catch (e) { errors++; }
    if (i % 100000 === 0) peakMb = Math.max(peakMb, process.memoryUsage().rss / 1e6);
  });
}
const seconds = (performance.now() - t0) / 1000;
peakMb = Math.max(peakMb, process.memoryUsage().rss / 1e6);
const report = {
  protocol: 'project/docs/RESEARCH_LOG.md, "Scale check" (24 Nov, late)',
  urls: N,
  inputs: { phishing_db_urls: half, popular_domains_urls: N - half },
  errors,
  verdicts: all,
  verdicts_by_input: byPart,
  seconds: +seconds.toFixed(1),
  ms_per_url: +(seconds * 1000 / N).toFixed(3),
  peak_rss_mb: +peakMb.toFixed(0),
  network: 'none (judgeOffline only)',
  note: 'counts, timing and memory only; no URL is written',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
