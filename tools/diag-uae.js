// node tools/diag-uae.js
// Diagnostics for the UAE protocol (docs/RESEARCH_LOG.md). Reads the same files as eval-uae.js. Changes no rule and no threshold.
// Part A (validation split): false alarms by group, a UAE brand token versus the word "login".
// Part B (test window): how each UAE brand token matched the UAE phishing URLs, whole label or inside a longer word.
// Prints counts and token names only, never URLs.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';
import { BRANDS } from '../data/brands.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA = path.join(ROOT, '..', 'data_raw', 'urlv2');
const UAE = BRANDS.slice(0, BRANDS.indexOf('paypal')).filter(t => t.length >= 4);
const tokensIn = url => { const s = url.toLowerCase(); return UAE.filter(t => s.includes(t)); };
const wholeLabel = (url, t) => {
  let h = '';
  try { h = new URL(url).hostname.toLowerCase(); } catch { return false; }
  return h.split(/[.-]/).includes(t);
};
const lines = f => fs.readFileSync(path.join(DATA, f), 'utf8').split('\n').map(l => l.replace(/\r$/, '')).filter(Boolean);
const withHeader = f => lines(f).slice(1).map(l => { const [label, , , url] = l.split('\t'); return { label: Number(label), url }; });
const rate = (k, n) => (n ? +(k / n).toFixed(4) : null);

// Part A: validation legitimate URLs, grouped by brand token and keyword
const legit = withHeader('split_val.tsv').filter(r => r.label === 0).map(r => r.url);
const groups = { uae_token_only: [], login_only: [], uae_token_and_login: [] };
for (const u of legit) {
  const t = tokensIn(u).length > 0, l = /login/i.test(u);
  if (t && l) groups.uae_token_and_login.push(u);
  else if (t) groups.uae_token_only.push(u);
  else if (l) groups.login_only.push(u);
}
const partA = {};
for (const [name, urls] of Object.entries(groups)) {
  const flagged = urls.filter(u => judgeOffline(u).verdict === 'phishing').length;
  partA[name] = { n: urls.length, strict_false_alarms: flagged, rate: rate(flagged, urls.length) };
}

// Part B: UAE phishing in the test window (same set as eval-uae.js), token match quality
const history = lines('openphish_history.tsv').map(l => l.split('\t')).filter(r => r.length >= 2);
const testPhish = new Set(withHeader('split_test.tsv').filter(r => r.label === 1).map(r => r.url));
const windowUrls = [...new Set(history.filter(([d]) => d >= '2026-10-25' && d <= '2026-11-24').map(([, u]) => u))];
const uaeSet = windowUrls.filter(u => testPhish.has(u) && tokensIn(u).length > 0);
const rowsB = uaeSet.map(u => ({
  boundary: tokensIn(u).some(t => wholeLabel(u, t)),
  tokens: tokensIn(u),
  strict: judgeOffline(u).verdict === 'phishing',
}));
const tokenCounts = {};
for (const r of rowsB) for (const t of r.tokens) tokenCounts[t] = (tokenCounts[t] || 0) + 1;
const boundaryRows = rowsB.filter(r => r.boundary);
const partB = {
  n: rowsB.length,
  caught_strict: rowsB.filter(r => r.strict).length,
  whole_label_match_n: boundaryRows.length,
  whole_label_match_caught_strict: boundaryRows.filter(r => r.strict).length,
  token_counts: tokenCounts,
};
console.log(JSON.stringify({ partA, partB }, null, 2));
