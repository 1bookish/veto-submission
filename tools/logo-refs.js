// node tools/logo-refs.js [--only enbd,adcb] [--tranco <top-1m.csv>]      -> data/logos.js
//
// Visits each institution's OFFICIAL website in the X-ray browser and records fingerprints of its tab icon
// and logo pictures: SHA-256 of the bytes, perceptual hashes (dHash, aHash, mean colour) and the Shodan
// favicon hash. Never the pictures themselves. The X-ray then spots a scam page that wears the real
// brand's icon or logo on a domain that is not the brand's.
//
// Self-check (--tranco): the favicons of popular unrelated sites must match NONE of the references; the
// count is written into LOGO_REPORT so the false-match rate is on record.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getBrowser } from '../server/xray.js';
import { hashImages, sniffImage, sha256hex, shodanFaviconHash, sameImage } from '../server/forensics.js';
import { INSTITUTIONS } from '../data/institutions.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = k => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
const only = arg('--only') ? new Set(arg('--only').split(',')) : null;
const DESKTOP_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
const MAX_BYTES = 600_000;

const insts = INSTITUTIONS.filter(i => !i.generic && i.domains.length && (!only || only.has(i.id)));
const browser = await getBrowser();

async function collect(inst) {
  const domain = inst.domains[0];
  const ctx = await browser.newContext({ userAgent: DESKTOP_UA, viewport: { width: 1280, height: 900 }, locale: 'en-AE', timezoneId: 'Asia/Dubai', serviceWorkers: 'block', ignoreHTTPSErrors: true });
  const got = new Map(); // url -> {bytes, type, kind}
  try {
    const page = await ctx.newPage();
    page.on('response', async r => {
      try {
        if (r.request().resourceType() !== 'image' || r.status() !== 200) return;
        // only the site's own tab icon here; logos are picked from the page below (partner and social logos are not the brand)
        if (!/favicon|apple-touch-icon/i.test(r.url())) return;
        const b = await r.body();
        if (b.length && b.length < MAX_BYTES) got.set(r.url(), { bytes: b, type: sniffImage(b, r.headers()['content-type']), kind: 'favicon' });
      } catch { /* body gone */ }
    });
    let ok = false;
    for (const start of [`https://www.${domain}/`, `https://${domain}/`]) {
      try { await page.goto(start, { waitUntil: 'domcontentloaded', timeout: 20000 }); ok = true; break; } catch { /* try next */ }
    }
    if (!ok) return { inst: inst.id, domain, error: 'unreachable', refs: [] };
    await page.waitForLoadState('networkidle', { timeout: 6000 }).catch(() => {});
    const found = await page.evaluate(tokens => {
      const icons = Array.from(document.querySelectorAll('link[rel~="icon" i], link[rel="shortcut icon" i], link[rel~="apple-touch-icon" i]')).map(l => l.href).filter(Boolean);
      // the brand's own logo: named "logo" AND either in the page header or carrying the brand's name
      const logos = Array.from(document.querySelectorAll('img')).filter(i => {
        const s = `${i.currentSrc || i.src} ${i.alt} ${i.className} ${i.id} ${i.parentElement ? i.parentElement.className : ''}`;
        if (!/logo/i.test(s) || i.naturalWidth < 16) return false;
        const top = i.getBoundingClientRect().top + scrollY;
        return top < 220 || tokens.some(t => s.toLowerCase().includes(t)) || !!i.closest('header, nav, [class*=header i]');
      }).slice(0, 3).map(i => i.currentSrc || i.src);
      return { icons: icons.slice(0, 4), logos, origin: location.origin };
    }, [...inst.tokens, ...inst.domains.map(d => d.split('.')[0])].map(t => t.toLowerCase())).catch(() => ({ icons: [], logos: [], origin: `https://${domain}` }));
    const want = [...found.icons.map(u => [u, 'favicon']), [found.origin + '/favicon.ico', 'favicon'], ...found.logos.map(u => [u, 'logo'])];
    for (const [u, kind] of want) {
      if (got.has(u) || !/^https?:/.test(u)) { if (got.has(u)) got.get(u).kind = kind; continue; }
      try {
        const r = await ctx.request.get(u, { timeout: 10000 });
        if (!r.ok()) continue;
        const b = await r.body();
        if (b.length && b.length < MAX_BYTES) got.set(u, { bytes: b, type: sniffImage(b, r.headers()['content-type']), kind });
      } catch { /* skip */ }
    }
  } finally { await ctx.close().catch(() => {}); }
  const items = [...got].filter(([, v]) => v.type).map(([url, v]) => ({ url, ...v }));
  const ph = await hashImages(browser, items);
  const refs = [];
  items.forEach((it, k) => {
    const sha = sha256hex(it.bytes);
    if (refs.some(r => r.sha256 === sha)) return;
    refs.push({ inst: inst.id, domain, kind: it.kind, src: it.url.slice(0, 160), sha256: sha, shodan: it.kind === 'favicon' ? shodanFaviconHash(it.bytes) : null,
      ...(ph[k] ? { dh: ph[k].dh, ah: ph[k].ah, rgb: ph[k].rgb, sd: ph[k].sd, w: ph[k].w, h: ph[k].h } : {}) });
  });
  return { inst: inst.id, domain, refs };
}

const results = [];
const queue = [...insts];
await Promise.all(Array.from({ length: 4 }, async () => {
  while (queue.length) {
    const inst = queue.shift();
    const r = await collect(inst).catch(e => ({ inst: inst.id, domain: inst.domains[0], error: String(e.message || e).split('\n')[0], refs: [] }));
    console.log(`${r.inst.padEnd(16)} ${r.domain.padEnd(28)} ${r.error ? 'ERROR ' + r.error : r.refs.map(x => `${x.kind}${x.dh ? '' : '(raw)'}`).join(' ') || 'no icons'}`);
    results.push(r);
  }
}));

let LOGOS = results.flatMap(r => r.refs).map(({ w, h, ...x }) => ({ ...x, ph: x.dh ? { dh: x.dh, ah: x.ah, rgb: x.rgb, sd: x.sd } : null }))
  .map(({ dh, ah, rgb, sd, ...x }) => x);
// a picture shared by two different institutions (a generic icon, a shared CMS default) is not a brand mark
const shared = new Set();
for (let a = 0; a < LOGOS.length; a++) for (let b = a + 1; b < LOGOS.length; b++) {
  if (LOGOS[a].inst !== LOGOS[b].inst && sameImage(LOGOS[a], LOGOS[b])) { shared.add(a); shared.add(b); }
}
const before = LOGOS.length;
LOGOS = LOGOS.filter((_, k) => !shared.has(k));
console.log(`dropped ${before - LOGOS.length} pictures shared between institutions`);

// ---- self-check on popular unrelated sites --------------------------------------------------------
// calibration set (Tranco ranks 2,000-2,400): a reference that matches an unrelated site's icon is a generic
// picture (CMS or CDN default), not a brand mark, so it is dropped. Test set (ranks 6,000-6,400, never used for
// calibration): the false-match rate that goes on record.
let report = { institutions: insts.length, reached: results.filter(r => !r.error).length, generatedAt: new Date().toISOString() };
const sibling = (inst, domain) => {
  const i = INSTITUTIONS.find(x => x.id === inst);
  const [label, ...rest] = domain.split('.');
  return !!i && i.domains.some(d => d.split('.')[0] === label) && /^[a-z]{2}$|^(co|com|org|net)\.[a-z]{2}$/.test(rest.join('.'));
};
async function favicons(domains) {
  const icons = [];
  const q2 = [...domains];
  await Promise.all(Array.from({ length: 16 }, async () => {
    while (q2.length) {
      const d = q2.shift();
      try {
        const r = await fetch(`https://${d}/favicon.ico`, { signal: AbortSignal.timeout(5000), headers: { 'user-agent': DESKTOP_UA } });
        if (!r.ok) continue;
        const bb = Buffer.from(await r.arrayBuffer());
        const type = sniffImage(bb, r.headers.get('content-type') || '');
        if (type && bb.length < MAX_BYTES) icons.push({ domain: d, bytes: bb, type });
      } catch { /* unreachable */ }
    }
  }));
  const ph = await hashImages(browser, icons);
  return icons.map((ic, k) => ({ domain: ic.domain, sha256: sha256hex(ic.bytes), ph: ph[k] }));
}
if (arg('--tranco')) {
  const all = fs.readFileSync(arg('--tranco'), 'utf8').split(/\r?\n/).map(l => l.split(',')[1]).filter(Boolean);
  const own = new Set(INSTITUTIONS.flatMap(i => i.domains));
  const calib = await favicons(all.slice(2000, 2400).filter(d => !own.has(d)));
  const generic = new Set();
  for (const im of calib) LOGOS.forEach((ref, k) => { if (!sibling(ref.inst, im.domain) && sameImage(im, ref)) generic.add(k); });
  const before = LOGOS.length;
  LOGOS = LOGOS.filter((_, k) => !generic.has(k));
  console.log(`calibration: ${calib.length} unrelated favicons, dropped ${before - LOGOS.length} generic references`);
  const test = await favicons(all.slice(6000, 6400).filter(d => !own.has(d)));
  const matches = [];
  for (const im of test) for (const ref of LOGOS) { if (sibling(ref.inst, im.domain)) continue; const m = sameImage(im, ref); if (m) matches.push(`${im.domain} ~ ${ref.inst} (${m.exact ? 'exact' : 'd=' + m.d})`); }
  report.calibration = { unrelatedFavicons: calib.length, genericReferencesDropped: before - LOGOS.length };
  report.test = { unrelatedFavicons: test.length, falseMatches: matches.length, examples: matches.slice(0, 10) };
  console.log(`test: ${test.length} favicons of unrelated popular sites (never seen), ${matches.length} false matches`, matches.slice(0, 10));
}
report.references = LOGOS.length;

fs.writeFileSync(path.join(ROOT, 'data', 'logos.js'),
  `// Generated by tools/logo-refs.js on ${report.generatedAt}. Do not edit by hand.\n` +
  `// Fingerprints of the official institutions' own tab icons and logos (never the pictures): SHA-256, perceptual\n` +
  `// hashes and the Shodan favicon hash. The X-ray flags a page that wears one of them on a domain that is not the brand's.\n` +
  `export const LOGOS = ${JSON.stringify(LOGOS)};\n` +
  `export const LOGO_REPORT = ${JSON.stringify(report, null, 1)};\n`);
console.log(`wrote data/logos.js: ${LOGOS.length} references from ${report.reached}/${report.institutions} institutions`);
process.exit(0);
