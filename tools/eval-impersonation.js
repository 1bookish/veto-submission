// node tools/eval-impersonation.js [--seed 20261124] [--raw <data_raw folder>] [--out data/impersonation-report.json]
// Impersonation categories test. Protocol: docs/RESEARCH_LOG.md, "Impersonation test" (24 Nov, late; written before the run).
// Offline judge only (no network). The report holds counts and intervals only; no generated URL is written.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';
import { INSTITUTIONS } from '../data/institutions.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const SEED = Number(arg('--seed', '20261124'));
const RAW = arg('--raw', path.join(ROOT, '..', 'data_raw'));
const OUT = arg('--out', path.join(ROOT, 'data', 'impersonation-report.json'));

// seeded random numbers (mulberry32)
let seedState = SEED >>> 0;
const R = () => { seedState = (seedState + 0x6D2B79F5) >>> 0; let t = seedState; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const pick = arr => arr[Math.floor(R() * arr.length)];

// held-out words must not appear in the rule code (checked before any run; comments are ignored)
const HELD_OUT_WORDS = ['saudi', 'qatar', 'kuwait', 'hub', 'members', 'home'];
const codeText = fs.readFileSync(path.join(ROOT, 'engine', 'url.js'), 'utf8').toLowerCase()
  .split('\n').filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
const leaked = HELD_OUT_WORDS.filter(w => new RegExp(`\\b${w}\\b`).test(codeText));
if (leaked.length) throw new Error('held-out words found in the rule code: ' + leaked.join(', ') + ' (test not run)');

// reference names: the listed institutions, first official domain, two labels only
const refsAll = [];
let listed = 0, threeLabel = 0;
for (const inst of INSTITUTIONS) {
  const d = (inst.domains || [])[0];
  if (!d) continue;
  listed++;
  const labels = d.toLowerCase().split('.');
  if (labels.length !== 2) { threeLabel++; continue; }
  refsAll.push({ id: inst.id, sld: labels[0], tld: labels[1], domain: d.toLowerCase() });
}
// keep only names the judge already treats as official (so the test measures impersonation, not the list)
const refs = refsAll.filter(r => {
  const v = judgeOffline('https://' + r.domain + '/');
  return (v.reasons || []).some(x => x.id === 'official');
});
const notOfficial = refsAll.length - refs.length;

const LEET = { l: '1', o: '0', e: '3', s: '5', t: '7', a: '4' };
const CHEAP_TLDS = ['xyz', 'top', 'shop', 'online', 'site', 'icu'];
const OTHER_TLDS = ['net', 'co', 'org', 'info'];
const COUNTRY_WORDS = ['saudi', 'qatar', 'kuwait'];
const WORDS = ['hub', 'members', 'home'];

const CATS = [
  { id: 'D1', role: 'development', name: 'digit added at the end', gen: r => ({ sld: r.sld + pick(['1', '0', '3', '7', '9']), tld: r.tld }) },
  { id: 'D2', role: 'development', name: 'digit in place of a letter', gen: r => {
    const idx = [...r.sld].map((c, i) => (LEET[c] ? i : -1)).filter(i => i >= 0);
    if (!idx.length) return null;
    const i = pick(idx);
    return { sld: r.sld.slice(0, i) + LEET[r.sld[i]] + r.sld.slice(i + 1), tld: r.tld };
  } },
  { id: 'D3', role: 'development', name: 'one letter dropped', gen: r => {
    if (r.sld.length < 5) return null;
    const i = 1 + Math.floor(R() * (r.sld.length - 2));
    return { sld: r.sld.slice(0, i) + r.sld.slice(i + 1), tld: r.tld };
  } },
  { id: 'D4', role: 'development', name: 'one letter doubled', gen: r => {
    const i = 1 + Math.floor(R() * (r.sld.length - 1));
    return { sld: r.sld.slice(0, i) + r.sld[i] + r.sld.slice(i), tld: r.tld };
  } },
  { id: 'D5', role: 'development', name: 'two neighbouring letters swapped', gen: r => {
    const idx = [];
    for (let i = 0; i < r.sld.length - 1; i++) if (r.sld[i] !== r.sld[i + 1]) idx.push(i);
    if (!idx.length) return null;
    const i = pick(idx);
    return { sld: r.sld.slice(0, i) + r.sld[i + 1] + r.sld[i] + r.sld.slice(i + 2), tld: r.tld };
  } },
  { id: 'H1', role: 'held-out', name: 'country word with a hyphen', gen: r => ({ sld: r.sld + '-' + pick(COUNTRY_WORDS), tld: r.tld }) },
  { id: 'H3', role: 'held-out', name: 'exact name on a cheap TLD', gen: r => ({ sld: r.sld, tld: pick(CHEAP_TLDS) }) },
  { id: 'H4', role: 'held-out', name: 'exact name on another TLD', gen: r => ({ sld: r.sld, tld: pick(OTHER_TLDS) }) },
  { id: 'H5', role: 'held-out', name: 'a word with a hyphen', gen: r => ({ sld: r.sld + '-' + pick(WORDS), tld: r.tld }) },
  { id: 'H6', role: 'held-out', name: 'two reference names joined', gen: (r, all) => {
    const others = all.filter(x => x.id !== r.id && x.sld.length >= 5);
    if (!others.length) return null;
    return { sld: r.sld + '-' + pick(others).sld, tld: r.tld };
  } },
  { id: 'H7', role: 'held-out', name: '"-com" inserted before the TLD', gen: r => ({ sld: r.sld + '-com', tld: 'net' }) },
  { id: 'H8', role: 'held-out', name: 'underscore in place of the hyphen', gen: r => ({ sld: r.sld + '_' + pick(WORDS), tld: r.tld }) },
  { id: 'H9', role: 'held-out', name: '"www" glued to the name', gen: r => ({ sld: 'www' + r.sld, tld: r.tld }) },
];

function wilson(k, n) {
  if (!n) return [null, null];
  const z = 1.959964, p = k / n, d = 1 + z * z / n;
  const c = (p + z * z / (2 * n)) / d, h = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d;
  return [+Math.max(0, c - h).toFixed(4), +Math.min(1, c + h).toFixed(4)];
}

function variants(cat, r) {
  const out = [];
  for (let tries = 0; out.length < 3 && tries < 12; tries++) {
    const g = cat.gen(r, refs);
    if (!g) continue;
    const dom = `${g.sld}.${g.tld}`;
    if (g.sld.length > 63 || dom.length > 253) continue;
    out.push('https://' + dom + '/');
  }
  return out;
}

const categories = {};
for (const cat of CATS) {
  let n = 0, strict = 0, cautious = 0, n5 = 0, strict5 = 0, short = 0;
  const byRule = { lookalike_domain: 0, brand_in_domain: 0, other: 0 };
  for (const r of refs) {
    const urls = variants(cat, r);
    if (urls.length < 3) short++;
    for (const u of urls) {
      const v = judgeOffline(u);
      const s = v.verdict === 'phishing', c = v.verdict !== 'legitimate';
      n++; if (s) strict++; if (c) cautious++;
      if (r.sld.length >= 5) { n5++; if (s) strict5++; }
      if (s) {
        const ids = (v.reasons || []).map(x => x.id);
        if (ids.includes('lookalike_domain')) byRule.lookalike_domain++;
        else if (ids.includes('brand_in_domain')) byRule.brand_in_domain++;
        else byRule.other++;
      }
    }
  }
  categories[cat.id] = {
    name: cat.name, role: cat.role, n,
    strict, strict_ci: wilson(strict, n),
    cautious, cautious_ci: wilson(cautious, n),
    names_5_letters_or_more: { n: n5, strict: strict5, strict_ci: wilson(strict5, n5) },
    strict_detections_by_reason: byRule,
    names_with_fewer_than_3_variants: short,
  };
}

// legitimate controls (not labelled): false-alarm rates only
const tranco = fs.readFileSync(path.join(RAW, 'tranco', 'top-1m.csv'), 'utf8').split('\n').filter(Boolean)
  .map(l => { const [rank, dom] = l.split(','); return { rank: Number(rank), dom: (dom || '').trim().toLowerCase() }; })
  .filter(x => x.dom.includes('.'));
const bigNames = refs.filter(r => r.sld.length >= 5).map(r => r.sld);
const L1 = tranco.filter(x => x.rank <= 10000 && x.dom.split('.').length <= 3 && bigNames.some(sld => x.dom.split('.')[0].includes(sld)));
const pool = tranco.filter(x => x.rank >= 200001 && x.rank <= 210000);
const picked = new Set();
while (picked.size < Math.min(10000, pool.length)) picked.add(Math.floor(R() * pool.length));
const L2 = [...picked].map(i => pool[i]);
function control(list) {
  let s = 0, c = 0;
  for (const x of list) { const v = judgeOffline('https://' + x.dom + '/'); if (v.verdict === 'phishing') s++; if (v.verdict !== 'legitimate') c++; }
  return { n: list.length, strict_flags: s, strict_rate: +(s / list.length).toFixed(4), strict_ci: wilson(s, list.length), cautious_flags: c, cautious_rate: +(c / list.length).toFixed(4), cautious_ci: wilson(c, list.length) };
}
const controls = { L1_popular_containing_reference_name: control(L1), L2_tranco_200001_210000_sample: control(L2) };

const report = {
  protocol: 'project/docs/RESEARCH_LOG.md, "Impersonation test" (24 Nov, late)',
  seed: SEED,
  references: { listed, two_label_used: refs.length, three_label_excluded: threeLabel, not_official_in_judge_excluded: notOfficial, names_5_letters_or_more: bigNames.length },
  held_out_words_checked_against_rules: HELD_OUT_WORDS,
  categories, controls,
  note: 'counts and Wilson intervals only; no generated URL is written; controls are not labelled',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
const pct = (k, n) => (n ? (100 * k / n).toFixed(1) + ' %' : 'n/a');
console.log(`references used: ${refs.length} of ${listed} listed (3-label ${threeLabel}, not official in judge ${notOfficial})`);
for (const [id, c] of Object.entries(categories)) {
  console.log(`${id} ${c.role.padEnd(11)} ${c.name.padEnd(34)} n=${String(c.n).padStart(4)}  strict ${pct(c.strict, c.n).padStart(7)}  cautious ${pct(c.cautious, c.n).padStart(7)}  names 5+ letters strict ${pct(c.names_5_letters_or_more.strict, c.names_5_letters_or_more.n).padStart(7)}`);
}
console.log(`L1 popular names containing a reference name: n=${controls.L1_popular_containing_reference_name.n}, strict flags ${pct(controls.L1_popular_containing_reference_name.strict_flags, controls.L1_popular_containing_reference_name.n)}, cautious ${pct(controls.L1_popular_containing_reference_name.cautious_flags, controls.L1_popular_containing_reference_name.n)}`);
console.log(`L2 Tranco 200001-210000 sample: n=${controls.L2_tranco_200001_210000_sample.n}, strict flags ${pct(controls.L2_tranco_200001_210000_sample.strict_flags, controls.L2_tranco_200001_210000_sample.n)}, cautious ${pct(controls.L2_tranco_200001_210000_sample.cautious_flags, controls.L2_tranco_200001_210000_sample.n)}`);
