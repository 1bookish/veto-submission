// node tools/eval-judge.js --data <dir> [--split test|val] [--online-sample 300]
// Scores the WHOLE URL Judge (allowlist + rules + model + popularity guard), not only the model, on the held-out
// lists written by tools/train-url-model2.js (time split: phishing first seen in the last 30 days; legitimate sites
// split by domain), and on every crawled URL of the 77 official UAE institutions. Writes data/judge-report.json.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeOffline, judgeOnline, metrics } from '../server/judge.js';
import { setFeedsEnabled } from '../server/feeds.js';
import { model2Info, mlUrlScore2 } from '../engine/urlml2.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const DATA = arg('--data');
const split = arg('--split', 'test');
const read = f => fs.readFileSync(path.join(DATA, f), 'utf8').split('\n').slice(1).filter(Boolean).map(l => { const [y, src, nd, url] = l.split('\t'); return { label: Number(y), src, newDomain: nd === '1', url }; });
const rows = read(`split_${split}.tsv`);
const uae = read('split_uae.tsv');
const t0 = Date.now();
const res = rows.map(r => ({ ...r, ...judgeOffline(r.url), label: r.label }));
const ms = (Date.now() - t0) / rows.length;
const pick = pred => res.filter(pred);
// Example URLs in the report are defanged (hxxp, [.]) so the saved file never holds a live, clickable phishing link.
const defang = u => String(u).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
const report = {
  model: model2Info()?.version, split, n: rows.length, ms_per_url: +ms.toFixed(3),
  all: metrics(res),
  new_phishing_domains: metrics(pick(r => !r.label || r.newDomain)),
  by_source: Object.fromEntries([...new Set(res.map(r => r.src))].map(src => {
    const m = metrics(pick(r => r.src === src));
    const sub = pick(r => r.src === src);
    return [src, sub[0]?.label ? { n: sub.length, recall_strict: m.strict.recall, recall_cautious: m.cautious.recall } : { n: sub.length, fpr_strict: m.strict.fpr, fpr_cautious: m.cautious.fpr }];
  })),
  // official UAE pages: the JUDGE passes them by design (allowlist); the MODEL alone is the honest test of unknown UAE sites
  uae_official_heldout: (() => { const u = uae.map(r => judgeOffline(r.url)); const m = uae.map(r => mlUrlScore2(r.url)); const mf = m.map((x, k) => !!x && x.p >= x.threshold); return { urls: uae.length, judge_flagged_allowlist_on: u.filter(x => x.verdict !== 'legitimate').length, model_flagged_allowlist_off: mf.filter(Boolean).length, model_false_alarm_rate: +(mf.filter(Boolean).length / Math.max(1, uae.length)).toFixed(4), model_examples: uae.filter((r, k) => mf[k]).slice(0, 10).map(r => r.url) }; })(),
  errors: {
    false_alarms: pick(r => !r.label && r.verdict === 'phishing').slice(0, 15).map(r => [defang(r.url.slice(0, 120)), r.score, r.reasons.map(x => x.id).join('+')]),
    missed: pick(r => r.label && r.verdict === 'legitimate').slice(0, 15).map(r => [defang(r.url.slice(0, 120)), r.score])
  }
};
// optional: the online layer on a random sample (network!), with feeds OFF so it measures zero-day behaviour
const N = Number(arg('--online-sample', 0));
if (N) {
  setFeedsEnabled(false);
  // seeded shuffle (mulberry32), so the same command gives the same sample and the same numbers
  let seed = 20261124;
  const rnd = () => { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  // Fisher-Yates shuffle (a comparator-based sort is biased; the earlier samples were not random)
  const sample = [...rows];
  for (let k = sample.length - 1; k > 0; k--) { const j = Math.floor(rnd() * (k + 1)); [sample[k], sample[j]] = [sample[j], sample[k]]; }
  sample.length = Math.min(sample.length, N);
  const out = [];
  let k = 0;
  await Promise.all(Array.from({ length: 16 }, async () => { while (k < sample.length) { const r = sample[k++]; out.push({ ...(await judgeOnline(r.url).catch(() => judgeOffline(r.url))), label: r.label }); } }));
  report.online_sample = { n: out.length, feeds: 'off', ...metrics(out) };
}
const show = (name, m) => m && console.log(`${name.padEnd(34)} P ${(m.precision * 100).toFixed(1)} %  R ${(m.recall * 100).toFixed(1)} %  F1 ${(m.f1 * 100).toFixed(1)} %  FPR ${(m.fpr * 100).toFixed(2)} %  (TP ${m.tp} FP ${m.fp} FN ${m.fn} TN ${m.tn})`);
console.log(`URL Judge on the ${split} split: ${rows.length} URLs, ${ms.toFixed(2)} ms per URL`);
show('strict (phishing)', report.all.strict); show('cautious (phishing+suspicious)', report.all.cautious);
show('new domains, strict', report.new_phishing_domains.strict);
if (report.online_sample) { show('ONLINE sample strict', report.online_sample.strict); show('ONLINE sample cautious', report.online_sample.cautious); }
console.log('by source', JSON.stringify(report.by_source));
console.log('UAE official, held-out domains', JSON.stringify(report.uae_official_heldout));
console.log('false alarms', JSON.stringify(report.errors.false_alarms.slice(0, 8), null, 0));
console.log('missed', JSON.stringify(report.errors.missed.slice(0, 8), null, 0));
if (split === 'test') fs.writeFileSync(path.join(ROOT, 'data', 'judge-report.json'), JSON.stringify(report, null, 1));
