// node tools/eval-uae.js [--data <dir>] [--out data/uae-report.json]
// The UAE-only test. Protocol: docs/RESEARCH_LOG.md, "Prior art and the UAE test protocol" (fixed before the first run).
// Offline only: no network, no page visits. Do not change a rule here to fit a result.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';
import { mlUrlScore2, model2Info } from '../engine/urlml2.js';
import { splitDomain } from '../engine/url.js';
import { BRANDS } from '../data/brands.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const DATA = arg('--data', path.join(ROOT, '..', 'data_raw', 'urlv2'));
const OUT = arg('--out', path.join(ROOT, 'data', 'uae-report.json'));

const WINDOW = ['2026-10-25', '2026-11-24'];   // protocol 1: the held-out test window
const BEFORE = '2026-10-04';                    // diagnostic D1: phishing seen before this date (training used it)
const SEED = 20261124, B = 1000;                // protocol 4: bootstrap

// protocol 1: the UAE block of the brand list (everything before the first global brand), tokens of 4+ characters
const UAE = BRANDS.slice(0, BRANDS.indexOf('paypal')).filter(t => t.length >= 4);
const uaeHit = url => { const s = url.toLowerCase(); return UAE.some(t => s.includes(t)); };

const lines = f => fs.readFileSync(path.join(DATA, f), 'utf8').split('\n').map(l => l.replace(/\r$/, '')).filter(Boolean);
const history = lines('openphish_history.tsv').map(l => l.split('\t')).filter(r => r.length >= 2); // date, url (no header)
const withHeader = f => lines(f).slice(1).map(l => { const [label, source, , url] = l.split('\t'); return { label: Number(label), source, url }; });
const testSplit = withHeader('split_test.tsv');
const valSplit = withHeader('split_val.tsv');
const uaeLegit = withHeader('split_uae.tsv');

const hostOf = u => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } };
const regOf = h => (h ? splitDomain(h).registrable : '');

// protocol 1: phishing first seen in the window, with a UAE brand token, must be label 1 in split_test
const testPhish = new Set(testSplit.filter(r => r.label === 1).map(r => r.url));
const windowUrls = [...new Set(history.filter(([d]) => d >= WINDOW[0] && d <= WINDOW[1]).map(([, u]) => u))];
const uaePhish = windowUrls.filter(uaeHit);
const outside = uaePhish.filter(u => !testPhish.has(u));
if (outside.length) throw new Error(`protocol 1 broken: ${outside.length} UAE phishing URLs are not label 1 in split_test.tsv`);
// protocol 2: the official UAE institution pages, held out from the shipped model
const uaeLegitUrls = uaeLegit.filter(r => r.label === 0).map(r => r.url);
if (!uaePhish.length || !uaeLegitUrls.length) throw new Error('empty set');

// protocol 3: the whole judge offline, and the model alone (the model flags when p >= threshold)
const modelFlag = u => { const m = mlUrlScore2(u); return !!m && m.p >= m.threshold; };
const run = urls => urls.map(u => { const j = judgeOffline(u); return { u, verdict: j.verdict, rules: (j.reasons || []).length, model: modelFlag(u) }; });
const strict = r => r.verdict === 'phishing';
const cautious = r => r.verdict === 'phishing' || r.verdict === 'suspicious';
const rate = (rows, f) => (rows.length ? rows.filter(f).length / rows.length : 0);

const P = run(uaePhish), L = run(uaeLegitUrls);

// protocol 4: stratified bootstrap, B resamples, seeded
let seed = SEED;
const rnd = () => { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
const pick = arr => arr[Math.floor(rnd() * arr.length)];
function interval(stat) {
  const xs = [];
  for (let b = 0; b < B; b++) {
    const ps = Array.from({ length: P.length }, () => pick(P));
    const ls = Array.from({ length: L.length }, () => pick(L));
    xs.push(stat(ps, ls));
  }
  xs.sort((a, b) => a - b);
  return [xs[Math.floor(0.025 * B)], xs[Math.ceil(0.975 * B) - 1]].map(x => +x.toFixed(4));
}
const precisionOf = (ps, ls) => { const tp = ps.filter(strict).length, fp = ls.filter(strict).length; return tp + fp ? tp / (tp + fp) : 0; };
const headlineOf = f => ({
  recall: +rate(P, f).toFixed(4), recall_95ci: interval((ps) => rate(ps, f)),
  false_alarm_rate: +rate(L, f).toFixed(4), false_alarm_95ci: interval((ps, ls) => rate(ls, f)),
});
const headline = {
  n_phishing: P.length, n_legitimate: L.length,
  judge_strict: headlineOf(strict),
  judge_cautious: headlineOf(cautious),
  model_alone: headlineOf(r => r.model),
  precision_judge_strict_combined: { value: +precisionOf(P, L).toFixed(4), ci: interval((ps, ls) => precisionOf(ps, ls)) },
};

// breakdown: which UAE phishing the judge (strict) and the model alone caught
const breakdown = { both: 0, judge_only: 0, model_only: 0, neither: 0 };
for (const r of P) { const j = strict(r), m = r.model; if (j && m) breakdown.both++; else if (j) breakdown.judge_only++; else if (m) breakdown.model_only++; else breakdown.neither++; }
const judgeStrictWithRules = P.filter(r => strict(r) && r.rules > 0).length;

// diagnostic D1: infrastructure reuse (phishing first seen before 4 Oct)
const seenRegs = new Set(), seenHosts = new Set();
for (const [d, u] of history) if (d < BEFORE) { const h = hostOf(u); if (h) { seenHosts.add(h); seenRegs.add(regOf(h)); } }
const hostsOf = P.map(r => hostOf(r.u));
const unseen = P.filter((r, i) => !seenRegs.has(regOf(hostsOf[i])));
const D1 = {
  same_host_seen_before: hostsOf.filter(h => seenHosts.has(h)).length,
  same_registrable_domain_seen_before: hostsOf.filter(h => seenRegs.has(regOf(h))).length,
  unseen_registrable_n: unseen.length,
  unseen_registrable_recall_strict: +rate(unseen, strict).toFixed(4),
};

// diagnostic D2: false alarms on legitimate validation URLs with a UAE brand token or the word "login"
const valLegit = valSplit.filter(r => r.label === 0).map(r => r.url);
const brandOrLogin = valLegit.filter(u => uaeHit(u) || /login/i.test(u));
const VL = run(valLegit), VB = run(brandOrLogin);
const D2 = {
  validation_legitimate_n: VL.length,
  all_false_alarm_strict: +rate(VL, strict).toFixed(4),
  all_false_alarm_model: +rate(VL, r => r.model).toFixed(4),
  brand_or_login_n: VB.length,
  brand_or_login_false_alarm_strict: +rate(VB, strict).toFixed(4),
  brand_or_login_false_alarm_model: +rate(VB, r => r.model).toFixed(4),
};

// phishing examples are defanged in anything written (protocol 8)
const defang = u => u.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
const misses = P.filter(r => !strict(r)).slice(0, 10).map(r => defang(r.u));

const info = model2Info();
const report = {
  protocol: 'project/docs/RESEARCH_LOG.md, "Prior art and the UAE test protocol"',
  model_version: info?.version ?? null, model_threshold: info?.threshold ?? null,
  brand_tokens: UAE.length, window: WINDOW,
  headline, breakdown, judge_strict_catches_with_rules: judgeStrictWithRules,
  D1, D2, misses_defanged: misses,
  bootstrap: { resamples: B, seed: SEED, method: 'stratified percentile, 95%' },
  caveat: 'Brand-named phishing is the easier case. The test window was measured after each change, so this set is not blind.',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ headline, breakdown, D1, D2 }, null, 2));
