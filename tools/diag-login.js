// node tools/diag-login.js
// Trade-off for one possible rule, measured on the VALIDATION split only (no test split, no code change):
// a strict phishing verdict whose only reason is the model (ml_url2) and whose URL contains the word "login"
// would be capped at suspicious. Suspicious still counts in the cautious view, so the cautious numbers do not move.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA = path.join(ROOT, '..', 'data_raw', 'urlv2');
const rows = fs.readFileSync(path.join(DATA, 'split_val.tsv'), 'utf8').split('\n').map(l => l.replace(/\r$/, '')).filter(Boolean).slice(1)
  .map(l => { const [label, , , url] = l.split('\t'); return { label: Number(label), url }; });
const onlyModel = j => (j.reasons || []).length > 0 && (j.reasons || []).every(x => x.id === 'ml_url2');
const s = { legit_n: 0, legit_strict_fa: 0, legit_login_n: 0, legit_login_fa: 0, legit_login_fa_capped: 0,
  phish_n: 0, phish_strict_caught: 0, phish_login_n: 0, phish_login_strict_caught: 0, phish_login_capped: 0 };
for (const r of rows) {
  const j = judgeOffline(r.url);
  const strict = j.verdict === 'phishing';
  const login = /login/i.test(r.url);
  const capped = strict && login && onlyModel(j);
  if (r.label === 0) {
    s.legit_n++; if (strict) s.legit_strict_fa++;
    if (login) { s.legit_login_n++; if (strict) s.legit_login_fa++; if (capped) s.legit_login_fa_capped++; }
  } else {
    s.phish_n++; if (strict) s.phish_strict_caught++;
    if (login) { s.phish_login_n++; if (strict) s.phish_login_strict_caught++; if (capped) s.phish_login_capped++; }
  }
}
const withCap = {
  legit_strict_false_alarm_rate: +((s.legit_strict_fa - s.legit_login_fa_capped) / s.legit_n).toFixed(4),
  phish_strict_recall: +((s.phish_strict_caught - s.phish_login_capped) / s.phish_n).toFixed(4),
};
const today = {
  legit_strict_false_alarm_rate: +(s.legit_strict_fa / s.legit_n).toFixed(4),
  phish_strict_recall: +(s.phish_strict_caught / s.phish_n).toFixed(4),
};
console.log(JSON.stringify({ counts: s, today, with_login_cap: withCap }, null, 2));
