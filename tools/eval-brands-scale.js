// node tools/eval-brands-scale.js [--brands 100000] [--variants 10] [--legit 100000] [--out data/brands-scale-report.json]
// Scale test of the look-alike rules. Protocol: docs/RESEARCH_LOG.md, "Brand scale test" (24 Nov, late; written before the run).
// Brands are the public domains in the Tranco top list (ranks 1 to --brands, names of 4 letters or more). Each brand gets
// --variants generated look-alikes, one per category (digit, leet, dropped and doubled letters, swapped letters, country
// word, cheap TLD, word, "-com", "www"). The variants are SYNTHETIC phishing, labelled as such. The legitimate controls
// are Tranco ranks 500,001 to 600,000 (assumed legitimate by rank, an estimate). Offline judge only; no network.
// Counts and intervals only: no URL is written.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';
import { INSTITUTIONS } from '../data/institutions.js';
import { splitDomain } from '../engine/url.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const BRANDS = Number(arg('--brands', '100000'));
const VARIANTS = Math.min(10, Number(arg('--variants', '10')));
const LEGIT = Number(arg('--legit', '100000'));
const RAW = path.join(ROOT, '..', 'data_raw');
const OUT = arg('--out', path.join(ROOT, 'data', 'brands-scale-report.json'));

// --seed: 20261126 for the first run; the watchlist test uses a fresh seed. --uae-only: UAE brands only (same controls).
const SEED = Number(arg('--seed', '20261126'));
const UAE_ONLY = args.includes('--uae-only');
let seedState = SEED >>> 0;
const R = () => { seedState = (seedState + 0x6D2B79F5) >>> 0; let t = seedState; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const pick = arr => arr[Math.floor(R() * arr.length)];

const LEET = { l: '1', o: '0', e: '3', s: '5', t: '7', a: '4' };
const CHEAP = ['xyz', 'top', 'shop', 'online', 'site', 'icu'];
const COUNTRY = ['saudi', 'qatar', 'kuwait'];
const WORDS = ['hub', 'members', 'home'];
const CATS = ['D1', 'D2', 'D3', 'D4', 'D5', 'H1', 'H3', 'H5', 'H7', 'H9'];

const rulebookSlds = new Set();
for (const inst of INSTITUTIONS) {
  const d = (inst.domains || [])[0];
  if (d) rulebookSlds.add(d.toLowerCase().split('.')[0]);
}

function variant(cat, sld, tld) {
  switch (cat) {
    case 'D1': return { sld: sld + pick(['1', '0', '3', '7', '9']), tld };
    case 'D2': {
      const idx = [...sld].map((c, i) => (LEET[c] ? i : -1)).filter(i => i >= 0);
      if (!idx.length) return null;
      const i = pick(idx);
      return { sld: sld.slice(0, i) + LEET[sld[i]] + sld.slice(i + 1), tld };
    }
    case 'D3': {
      if (sld.length < 5) return null;
      const i = 1 + Math.floor(R() * (sld.length - 2));
      return { sld: sld.slice(0, i) + sld.slice(i + 1), tld };
    }
    case 'D4': { const i = 1 + Math.floor(R() * (sld.length - 1)); return { sld: sld.slice(0, i) + sld[i] + sld.slice(i), tld }; }
    case 'D5': {
      const idx = []; for (let i = 0; i < sld.length - 1; i++) if (sld[i] !== sld[i + 1]) idx.push(i);
      if (!idx.length) return null;
      const i = pick(idx);
      return { sld: sld.slice(0, i) + sld[i + 1] + sld[i] + sld.slice(i + 2), tld };
    }
    case 'H1': return { sld: sld + '-' + pick(COUNTRY), tld };
    case 'H3': return { sld, tld: pick(CHEAP) };
    case 'H5': return { sld: sld + '-' + pick(WORDS), tld };
    case 'H7': return { sld: sld + '-com', tld: 'net' };
    case 'H9': return { sld: 'www' + sld, tld };
    default: return null;
  }
}

// Tranco: rank,domain
const tranco = fs.readFileSync(path.join(RAW, 'tranco', 'top-1m.csv'), 'utf8').split('\n').filter(Boolean)
  .map(l => { const [rank, d] = l.split(','); return { rank: Number(rank), dom: (d || '').trim().toLowerCase() }; })
  .filter(x => x.dom.includes('.') && x.rank > 0);
const bands = [['top1k', 1, 1000], ['1k_10k', 1001, 10000], ['10k_100k', 10001, 100000], ['100k_1m', 100001, 1000000]];
const bandOf = rank => (bands.find(([, a, b]) => rank >= a && rank <= b) || [null])[0];

const wilson = (k, n) => { if (!n) return [null, null]; const z = 1.959964, p = k / n, d = 1 + z * z / n; const c = (p + z * z / (2 * n)) / d, h = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d; return [+Math.max(0, c - h).toFixed(4), +Math.min(1, c + h).toFixed(4)]; };
const tally = () => ({ n: 0, strict: 0, cautious: 0 });
const add = (t, v) => { t.n++; if (v.verdict === 'phishing') t.strict++; if (v.verdict === 'phishing' || v.verdict === 'suspicious') t.cautious++; };
const fin = t => ({ n: t.n, strict: t.strict, strict_ci: wilson(t.strict, t.n), cautious: t.cautious, cautious_ci: wilson(t.cautious, t.n) });

const t0 = Date.now();
const byCat = Object.fromEntries(CATS.map(c => [c, tally()]));
const byBand = Object.fromEntries(bands.map(([b]) => [b, tally()]));
const byBandSmallLen = tally(), byBandBig = tally();
const uaeVariants = tally();
const uaeByCat = Object.fromEntries(CATS.map(c => [c, tally()]));
const brandFA = Object.fromEntries(bands.map(([b]) => [b, tally()]));
const uaeBrandFA = tally();
const outOfRulebookVariants = tally(), outOfRulebookOwn = tally();
let brandsUsed = 0, uaeBrands = 0, uaeInRulebook = 0, variantsBuilt = 0, errors = 0;

const brandList = tranco.filter(x => x.rank <= BRANDS && (!UAE_ONLY || x.dom.endsWith('.ae')));
for (const b of brandList) {
  const reg = splitDomain(b.dom).registrable;
  if (!reg) continue;
  const parts = reg.split('.');
  const sld = parts[0];
  const tld = parts.slice(1).join('.');
  if (sld.length < 4 || !tld) continue;
  brandsUsed++;
  const isUae = tld === 'ae' || tld.endsWith('.ae');
  if (isUae) uaeBrands++;
  if (isUae && rulebookSlds.has(sld)) uaeInRulebook++;
  const band = bandOf(b.rank);
  // the brand's own domain: a real site, so a flag is a false alarm (popular sites are protected by the popularity guard)
  const own = judgeOffline('https://' + reg + '/');
  if (band) add(brandFA[band], own);
  if (isUae) add(uaeBrandFA, own);
  if (!rulebookSlds.has(sld)) add(outOfRulebookOwn, own);
  // the generated look-alikes
  for (let k = 0; k < VARIANTS; k++) {
    const cat = CATS[k % CATS.length];
    const g = variant(cat, sld, tld);
    if (!g) continue;
    const host = `${g.sld}.${g.tld}`;
    if (g.sld.length > 63 || host.length > 253) continue;
    let v;
    try { v = judgeOffline('https://' + host + '/'); } catch (e) { errors++; continue; }
    variantsBuilt++;
    add(byCat[cat], v);
    if (band) add(byBand[band], v);
    if (sld.length >= 5) add(byBandBig, v); else add(byBandSmallLen, v);
    if (isUae) { add(uaeVariants, v); add(uaeByCat[cat], v); }
    if (!rulebookSlds.has(sld)) add(outOfRulebookVariants, v);
  }
}

// the legitimate control: assumed legitimate by rank (an estimate)
const pool = tranco.filter(x => x.rank >= 500001 && x.rank <= 600000);
const legit = tally();
const legitIdx = new Set();
while (legitIdx.size < Math.min(LEGIT, pool.length)) legitIdx.add(Math.floor(R() * pool.length));
for (const i of legitIdx) {
  const reg = splitDomain(pool[i].dom).registrable;
  if (!reg) continue;
  try { add(legit, judgeOffline('https://' + reg + '/')); } catch (e) { errors++; }
}

const report = {
  protocol: UAE_ONLY ? 'project/docs/RESEARCH_LOG.md, "UAE brand watchlist and two look-alike fixes" (25 Nov)' : 'project/docs/RESEARCH_LOG.md, "Brand scale test" (24 Nov, late)',
  seed: SEED, uae_only: UAE_ONLY, watchlist_switch: process.env.VETO_NO_WATCHLIST === '1' ? 'off (rules before the change)' : 'on',
  brands_requested: BRANDS, brands_used: brandsUsed, variants_per_brand: VARIANTS, variants_built: variantsBuilt,
  uae_brands: uaeBrands, uae_brands_in_rulebook: uaeInRulebook,
  synthetic_variants: { label: 'SYNTHETIC: generated from public brand domains; not real phishing', by_category: Object.fromEntries(CATS.map(c => [c, fin(byCat[c])])),
    by_brand_rank_band: Object.fromEntries(bands.map(([b]) => [b, fin(byBand[b])])),
    names_5_letters_or_more: fin(byBandBig), names_4_letters: fin(byBandSmallLen),
    uae_brands_variants: fin(uaeVariants), uae_by_category: Object.fromEntries(CATS.map(c => [c, fin(uaeByCat[c])])), outside_rulebook: fin(outOfRulebookVariants) },
  false_alarms: { label: 'the brands\' own domains (real sites; a flag is a false alarm)',
    by_brand_rank_band: Object.fromEntries(bands.map(([b]) => [b, fin(brandFA[b])])),
    uae_brands_own_domains: fin(uaeBrandFA), outside_rulebook_own_domains: fin(outOfRulebookOwn) },
  assumed_legitimate_controls: { label: 'Tranco ranks 500,001 to 600,000 (assumed legitimate by rank; an estimate)', n: legit.n, flagged_strict: legit.strict, strict_ci: wilson(legit.strict, legit.n), flagged_cautious: legit.cautious, cautious_ci: wilson(legit.cautious, legit.n) },
  minutes: +((Date.now() - t0) / 60000).toFixed(1), errors,
  note: 'counts and intervals only; no URL is written; the variants are synthetic',
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
const pct = (k, n) => (n ? (100 * k / n).toFixed(1) + ' %' : 'n/a');
console.log(`brands used ${brandsUsed} (UAE ${uaeBrands}, of which in the rulebook ${uaeInRulebook}); variants ${variantsBuilt}; minutes ${report.minutes}`);
for (const c of CATS) console.log(`${c} variants: strict ${pct(byCat[c].strict, byCat[c].n)} cautious ${pct(byCat[c].cautious, byCat[c].n)} (n=${byCat[c].n})`);
for (const [b] of bands) console.log(`band ${b}: variants strict ${pct(byBand[b].strict, byBand[b].n)}; own-domain false alarms ${pct(brandFA[b].strict, brandFA[b].n)} (n=${brandFA[b].n})`);
console.log(`UAE brands: variants strict ${pct(uaeVariants.strict, uaeVariants.n)}; own-domain false alarms ${pct(uaeBrandFA.strict, uaeBrandFA.n)} (n=${uaeBrandFA.n})`);
console.log(`outside the rulebook: variants strict ${pct(outOfRulebookVariants.strict, outOfRulebookVariants.n)}; own-domain false alarms strict ${pct(outOfRulebookOwn.strict, outOfRulebookOwn.n)} (n=${outOfRulebookOwn.n})`);
console.log(`assumed-legitimate controls: strict flags ${pct(legit.strict, legit.n)} cautious ${pct(legit.cautious, legit.n)} (n=${legit.n})`);
