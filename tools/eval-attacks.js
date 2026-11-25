// node tools/eval-attacks.js [--out data/attacks-report.json]
// Attack-style robustness test, pre-registered in docs/RESEARCH_LOG.md ("Attack-style robustness test").
// Real held-out URLs (phishing and legitimate) are transformed with 18 attack styles; the judge runs offline.
// A labelled synthetic set and a third-party set are reported separately. Writes counts only, never URLs.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';
import { BRANDS } from '../data/brands.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const RAW = path.join(ROOT, '..', 'data_raw');
const OUT = arg('--out', path.join(ROOT, 'data', 'attacks-report.json'));
const N = 2000;

// seeded generator (fixed seed, so the same run gives the same numbers)
let seed = 20261124;
const rnd = () => { seed = (Math.imul(seed, 1103515245) + 12345) >>> 0; return seed / 4294967296; };
const pick = a => a[Math.floor(rnd() * a.length)];
const code = n => Array.from({ length: n }, () => 'abcdefghijkmnpqrstuvwxyz23456789'[Math.floor(rnd() * 32)]).join('');
const sample = (arr, k) => { const a = arr.slice(); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a.slice(0, k); };

const split = fs.readFileSync(arg('--split', path.join(RAW, 'urlv2', 'split_test.tsv')), 'utf8').split('\n').map(l => l.replace(/\r$/, '')).filter(Boolean).slice(1)
  .map(l => { const [label, , , url] = l.split('\t'); return { label: Number(label), url }; });
const phish = sample(split.filter(r => r.label === 1).map(r => r.url), N);
const legit = sample(split.filter(r => r.label === 0).map(r => r.url), N);

// ---- the 18 transforms (each returns a variant string; on failure the input is returned unchanged) ----
const HOST = /^(https?:\/\/)([^/?#]+)(.*)$/i;
const split3 = u => { const m = HOST.exec(u); return m ? { scheme: m[1], host: m[2], rest: m[3] } : null; };
const T = [
  ['identity', u => u],
  ['uppercase host', u => { const p = split3(u); return p ? p.scheme + p.host.toUpperCase() + p.rest : u; }],
  ['percent-encoded host', u => { const p = split3(u); return p ? p.scheme + p.host.replace(/[a-z]/gi, c => '%' + c.charCodeAt(0).toString(16)) + p.rest : u; }],
  ['credentials before the host', u => { const p = split3(u); return p ? p.scheme + 'www.google.com@' + p.host + p.rest : u; }],
  ['subdomain stuffing', u => { const p = split3(u); return p ? p.scheme + 'login.secure-verify.' + p.host + p.rest : u; }],
  ['open-redirect wrapper', u => 'https://www.google.com/url?q=' + encodeURIComponent(u)],
  ['IP-address host', u => { const p = split3(u); return p ? p.scheme + `185.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}` + p.rest : u; }],
  ['Cyrillic homoglyph', u => { const p = split3(u); if (!p) return u; const map = { a: 'а', e: 'е', o: 'о' }; const h = p.host.replace(/[aeo]/, c => map[c]); return p.scheme + h + p.rest; }],
  ['cheap TLD swap', u => { const p = split3(u); if (!p) return u; const parts = p.host.split('.'); parts[parts.length - 1] = pick(['xyz', 'top', 'icu']); return p.scheme + parts.join('.') + p.rest; }],
  ['hyphen words inserted', u => { const p = split3(u); if (!p) return u; const parts = p.host.split('.'); parts[parts.length - 2] += '-secure-verify'; return p.scheme + parts.join('.') + p.rest; }],
  ['base64 redirect parameter', u => 'https://redirect-check.test/?d=' + Buffer.from(u).toString('base64')],
  ['long path padding', u => u + '/' + 'a'.repeat(400)],
  ['short-link wrapper', u => 'https://bit.ly/' + code(6)],
  ['plain http', u => u.replace(/^https:\/\//i, 'http://')],
  ['defanged form', u => u.replace(/^https/i, 'hxxps').replace(/\./g, '[.]')],
  ['tracking parameters', u => u + (u.includes('?') ? '&' : '?') + 'utm_source=sms&ref=' + code(5)],
  ['unicode full stop', u => { const p = split3(u); if (!p) return u; return p.scheme + p.host.replace('.', '。') + p.rest; }],
  ['encoded path', u => { const p = split3(u); return p ? p.scheme + p.host + p.rest.replace(/[a-z]/g, c => '%' + c.charCodeAt(0).toString(16)) : u; }],
];

const wilson = (k, n) => {
  if (!n) return [null, null];
  const z = 1.959964, p = k / n, d = 1 + z * z / n;
  const c = (p + z * z / (2 * n)) / d, h = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d;
  return [+Math.max(0, c - h).toFixed(4), +Math.min(1, c + h).toFixed(4)];
};
const rate = (k, n) => (n ? +(k / n).toFixed(4) : null);

// ---- real base URLs under every transform ----
const rows = [];
for (const [name, f] of T) {
  let pStrict = 0, pCaut = 0, lStrict = 0, lCaut = 0;
  for (const u of phish) { const v = judgeOffline(f(u)).verdict; if (v === 'phishing') pStrict++; if (v === 'phishing' || v === 'suspicious') pCaut++; }
  for (const u of legit) { const v = judgeOffline(f(u)).verdict; if (v === 'phishing') lStrict++; if (v === 'phishing' || v === 'suspicious') lCaut++; }
  rows.push({
    transform: name,
    phishing_n: N, recall_strict: rate(pStrict, N), recall_strict_95ci: wilson(pStrict, N),
    recall_cautious: rate(pCaut, N), recall_cautious_95ci: wilson(pCaut, N),
    legitimate_n: N, false_alarm_strict: rate(lStrict, N), false_alarm_strict_95ci: wilson(lStrict, N),
    false_alarm_cautious: rate(lCaut, N),
  });
}

// ---- labelled synthetic set: generated here, labelled SYNTHETIC, not an accuracy claim ----
const brands = BRANDS.slice(0, BRANDS.indexOf('paypal')).filter(t => t.length >= 5);
const patterns = [
  b => `${b}-secure-login.xyz`, b => `${b}-verify.top`, b => `${b}-update.icu`, b => `${b}-pay-fine.site`,
  b => `secure-${b}.com.${code(4)}.xyz`, b => `${b}${code(3)}.top`, b => `${b.slice(0, 2)}${b.slice(3)}-online.xyz`,
  b => `login-${b}.${code(5)}.icu`, b => `${b}-account-suspended.top`, b => `${b}.${code(6)}.xyz/login`,
  b => `${b}-otp-confirm.site`, b => `apply-${b}-refund.top`, b => `${b}-help-center.xyz`, b => `${b}-card-verify.icu`,
  b => `m-${b}-login.top`, b => `${b}-kyc-update.site`, b => `${b}-rewards-claim.xyz`, b => `${b}-fine-discount.top`,
  b => `${b}-unlock.icu/${code(8)}`, b => `${b}-security-alert.site`, b => `${b}-payment-failed.top`,
  b => `bit.ly/${code(6)}?to=${b}`, b => `${b}-appointment.xyz`, b => `${b}-parcel-fee.icu`, b => `${b}-helpdesk.top`,
];
const syn = [];
for (const b of sample(brands, 40)) for (const p of patterns) syn.push('https://' + p(b));
let synHit = 0, synCaut = 0;
for (const u of syn) { const v = judgeOffline(u).verdict; if (v === 'phishing') synHit++; if (v === 'phishing' || v === 'suspicious') synCaut++; }
const synthetic = {
  label: 'SYNTHETIC (generated here; not real phishing; not an accuracy claim)',
  n: syn.length, recall_strict: rate(synHit, syn.length), recall_cautious: rate(synCaut, syn.length),
  patterns: patterns.length, brands: 40,
};

// ---- third-party set: real look-alike domains named by public sources; labels are the sources' ----
// the names and their sources are kept in the workspace audit folder, not in the repository
const tp = JSON.parse(fs.readFileSync(path.join(ROOT, '..', 'audit', 'third-party-uae.json'), 'utf8'));
let tpStrict = 0, tpCaut = 0;
for (const d of tp.domains) { const v = judgeOffline('https://' + d.name + '/').verdict; if (v === 'phishing') tpStrict++; if (v === 'phishing' || v === 'suspicious') tpCaut++; }
const thirdParty = { label: 'third-party labelled (labels from the named sources; n is tiny)', n: tp.domains.length, caught_strict: tpStrict, caught_cautious: tpCaut };

const report = {
  protocol: 'project/docs/RESEARCH_LOG.md, "Attack-style robustness test" (24 Nov, night)',
  seed: 20261124, base_sample: { phishing: N, legitimate: N },
  transforms: rows, synthetic, third_party: thirdParty,
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ transforms: rows.map(r => ({ t: r.transform, rec: r.recall_strict, recC: r.recall_cautious, fa: r.false_alarm_strict, faC: r.false_alarm_cautious })), synthetic, third_party: thirdParty }, null, 2));
