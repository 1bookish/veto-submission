// Recompute the README's derived held-out rows on the TEST split: long-tail and popular legitimate false alarms,
// and recall on phishing hosted on popular (top-100,000) domains. Offline. Usage (from project/): node tools/eval-breakdown.mjs   (VETO_DATA=<folder with split_test.tsv> to override)
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath, pathToFileURL } from 'node:url';
const ROOT = process.env.VETO_ROOT || fileURLToPath(new URL('../', import.meta.url));
const DATA = process.env.VETO_DATA || fileURLToPath(new URL('../../data_raw/urlv2/', import.meta.url));
const { judgeOffline } = await import(pathToFileURL(path.join(ROOT, 'server/judge.js')).href);
const { trancoRank, parseUrl } = await import(pathToFileURL(path.join(ROOT, 'engine/urlml2.js')).href);
const { splitDomain } = await import(pathToFileURL(path.join(ROOT, 'engine/url.js')).href);
const rows = fs.readFileSync(path.join(DATA, 'split_test.tsv'), 'utf8').split('\n').slice(1).filter(Boolean).map(l => l.split('\t'));
const o = { longtail_legit: [0, 0], popular_legit: [0, 0], popular_phish: [0, 0], new_domain_phish: [0, 0] };
for (const [label, , nd, url] of rows) {
  const u = parseUrl(url); if (!u) continue;
  const reg = splitDomain(u.hostname.toLowerCase().replace(/^www\d?\./, '')).registrable;
  const rank = trancoRank(reg); const pop = rank && rank <= 100000;
  const flagged = judgeOffline(url).verdict === 'phishing';
  if (label === '0') { const k = pop ? 'popular_legit' : 'longtail_legit'; o[k][0] += flagged; o[k][1]++; }
  else { if (pop) { o.popular_phish[0] += flagged; o.popular_phish[1]++; } if (nd === '1') { o.new_domain_phish[0] += flagged; o.new_domain_phish[1]++; } }
}
const pct = ([a, b]) => `${a} of ${b} (${(100 * a / b).toFixed(2)} %)`;
console.log(JSON.stringify(Object.fromEntries(Object.entries(o).map(([k, v]) => [k, pct(v)])), null, 1));
