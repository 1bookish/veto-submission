// node tools/diag-brand-fp.js
// Diagnostic for D2 of the UAE protocol (docs/RESEARCH_LOG.md). Validation split only. Reports which brand token or
// keyword each false alarm matched, and which rules and model score fired. Changes no threshold and no rule.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';
import { mlUrlScore2 } from '../engine/urlml2.js';
import { BRANDS } from '../data/brands.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA = path.join(ROOT, '..', 'data_raw', 'urlv2');
const UAE = BRANDS.slice(0, BRANDS.indexOf('paypal')).filter(t => t.length >= 4);
const matchOf = url => { const s = url.toLowerCase(); return UAE.find(t => s.includes(t)) || (/login/i.test(url) ? 'login' : null); };

const rows = fs.readFileSync(path.join(DATA, 'split_val.tsv'), 'utf8').split('\n').map(l => l.replace(/\r$/, '')).filter(Boolean).slice(1)
  .map(l => { const [label, , , url] = l.split('\t'); return { label: Number(label), url }; });
const legit = rows.filter(r => r.label === 0).map(r => ({ url: r.url, matched: matchOf(r.url) })).filter(r => r.matched);

const cases = [];
for (const r of legit) {
  const j = judgeOffline(r.url);
  if (j.verdict !== 'phishing') continue;
  const m = mlUrlScore2(r.url);
  cases.push({ matched: r.matched, verdict: j.verdict, score: j.score, rules: (j.reasons || []).map(x => x.id), model_p: m ? m.p : null, threshold: m ? m.threshold : null });
}
const byToken = {};
for (const c of cases) byToken[c.matched] = (byToken[c.matched] || 0) + 1;
console.log(JSON.stringify({ legitimate_with_token_or_login: legit.length, strict_false_alarms: cases.length, by_token: byToken, cases }, null, 2));
