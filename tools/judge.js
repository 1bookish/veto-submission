// npm run judge -- <urls.txt | urls.csv> [--online] [--no-feeds] [--out results.csv] [--concurrency 12]
//
// The Veto URL Judge on a list: one verdict, score and reasons per URL. Input is either one URL per line, or a CSV
// with a `url` column and an optional `label` column (1/0, phishing/legitimate …). With labels it prints precision,
// recall, F1 and the false-alarm rate. Offline (default) sends nothing anywhere; --online also follows redirects and
// short links, checks DNS, domain age / registry holds and the landing page, and the local phishing feeds.
import fs from 'node:fs';
import path from 'node:path';
import { judgeList, parseList } from '../server/judge.js';
import { setFeedsEnabled } from '../server/feeds.js';

const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const file = args.find(a => !a.startsWith('--') && args[args.indexOf(a) - 1] !== '--out' && args[args.indexOf(a) - 1] !== '--concurrency');
if (!file) { console.error('usage: npm run judge -- <urls.txt|urls.csv> [--online] [--no-feeds] [--out results.csv]'); process.exit(1); }
const online = args.includes('--online');
if (args.includes('--no-feeds')) setFeedsEnabled(false);
const rows = parseList(fs.readFileSync(file, 'utf8'));
const out = arg('--out', path.join(path.dirname(file), path.basename(file).replace(/\.\w+$/, '') + '.veto.csv'));
console.log(`Veto URL Judge · ${rows.length} URLs · ${online ? 'ONLINE (redirects, DNS, RDAP, page, feeds' + (args.includes('--no-feeds') ? ' off' : '') + ')' : 'offline (nothing leaves this computer)'}`);
const t0 = Date.now();
const { results, metrics, model } = await judgeList(rows, { online, concurrency: Number(arg('--concurrency', 12)), onProgress: (d, n) => process.stdout.write(`\r ${d}/${n}`) });
const esc = s => `"${String(s ?? '').replace(/"/g, '""')}"`;
fs.writeFileSync(out, ['url,verdict,score,label,final_url,reasons_en,reasons_ar,ms',
  ...results.map(r => [esc(r.url), r.verdict, r.score ?? '', r.label ?? '', esc(r.finalUrl || ''), esc(r.reasons.map(x => x.en).join(' | ')), esc(r.reasons.map(x => x.ar).join(' | ')), r.ms].join(','))].join('\n'));
const count = v => results.filter(r => r.verdict === v).length;
console.log(`\r${results.length} URLs in ${((Date.now() - t0) / 1000).toFixed(1)} s: ${count('phishing')} phishing, ${count('suspicious')} suspicious, ${count('legitimate')} legitimate, ${count('invalid')} invalid`);
if (metrics) {
  const show = (name, m) => console.log(`${name.padEnd(30)} precision ${(m.precision * 100).toFixed(1)} %  recall ${(m.recall * 100).toFixed(1)} %  F1 ${(m.f1 * 100).toFixed(1)} %  false alarms ${(m.fpr * 100).toFixed(2)} %  (TP ${m.tp} FP ${m.fp} FN ${m.fn} TN ${m.tn})`);
  show('phishing = flagged', metrics.strict);
  show('phishing or suspicious', metrics.cautious);
}
console.log(`results: ${out}${model ? ` · model ${model.version}` : ''}`);
