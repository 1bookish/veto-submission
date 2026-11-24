// node tools/eval-watch.js [--raw <data_raw dir>] [--out data/watch-report.json]
// Test C of docs/RESEARCH_LOG.md ("Unseen-data tests"): the new-domain watch on its own output.
// Calls the production function suspectsIn (server/nrd.js). Offline, no network. Writes counts only, never names.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { suspectsIn } from '../server/nrd.js';
import { parseUrl } from '../engine/urlml2.js';
import { splitDomain } from '../engine/url.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const RAW = arg('--raw', path.join(ROOT, '..', 'data_raw'));
const OUT = arg('--out', path.join(ROOT, 'data', 'watch-report.json'));

const regOf = u => { const x = parseUrl(u); return x ? splitDomain(x.hostname.toLowerCase().replace(/^www\d?\./, '')).registrable : ''; };
const op = fs.readFileSync(path.join(RAW, 'urlv2', 'openphish_history.tsv'), 'utf8').split('\n').map(l => l.split('\t')).filter(x => x[1]);
const opByReg = new Map();
for (const [d, u] of op) { const r = regOf(u); if (!r) continue; if (!opByReg.has(r)) opByReg.set(r, []); opByReg.get(r).push(d); }

// lead in days from the list date to the first OpenPhish sighting on or after it; null if never confirmed
const leadOf = (host, D) => {
  const later = (opByReg.get(regOf('https://' + host + '/')) || []).filter(d => d >= D).sort();
  return later.length ? Math.round((Date.parse(later[0]) - Date.parse(D)) / 86400000) : null;
};
const pct = (a, b) => (b ? +(a / b).toFixed(4) : null);
const median = xs => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const summarize = S => ({
  list_names: S.names, suspects: S.suspects, confirmed_suspects: S.confS,
  precision: pct(S.confS, S.suspects),
  base_rate: pct(S.confAll, S.names),
  lift: S.suspects && S.confAll ? +((S.confS / S.suspects) / (S.confAll / S.names)).toFixed(2) : null,
  recall_on_confirmed: pct(S.confS, S.confAll),
  lead_days_median: median(S.leads),
  lead_days_min: S.leads.length ? Math.min(...S.leads) : null,
  lead_days_max: S.leads.length ? Math.max(...S.leads) : null,
});

const ALL = { names: 0, suspects: 0, confS: 0, confAll: 0, leads: [] };
const perList = {};
for (const D of ['2026-11-22', '2026-11-23']) {
  const list = fs.readFileSync(path.join(RAW, 'nrd', D + '.txt'), 'utf8').split(/\r?\n/).filter(Boolean);
  const names = [...new Set(list.map(l => l.trim().toLowerCase()).filter(Boolean))];
  const suspects = suspectsIn(list, D);
  const S = { names: names.length, suspects: suspects.length, confS: 0, confAll: 0, leads: [] };
  for (const s of suspects) { const lead = leadOf(s.host, D); if (lead !== null) { S.confS++; S.leads.push(lead); } }
  for (const n of names) if (leadOf(n, D) !== null) S.confAll++;
  perList[D] = summarize(S);
  ALL.names += S.names; ALL.suspects += S.suspects; ALL.confS += S.confS; ALL.confAll += S.confAll; ALL.leads.push(...S.leads);
}
const report = {
  protocol: 'project/docs/RESEARCH_LOG.md, "Test C: the new-domain watch on its own output"',
  per_list: perList, combined: summarize(ALL),
  note: 'small n: the confirmation window is one to two days',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
