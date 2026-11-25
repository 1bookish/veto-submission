// npm run radar [-- --days 120 emiratesnbd adpolice]     query crt.sh and rebuild data/radar.js
// npm run radar -- --refilter                           re-apply the filters to the saved list (no network)
//
// Veto Radar, finds look-alike domains of UAE institutions in public Certificate Transparency logs.
// Most phishing sites need an HTTPS certificate, and every publicly trusted certificate is logged,
// usually hours or days BEFORE the scam SMS goes out (Drichel et al., ARES 2021; x0rz/phishing_catcher).
//
// Lesson from the first run (20 Nov 2026): a name match alone flags the brand's OWN sites abroad
// (aramex.net, aramex.co.za… with enterprise DigiCert certificates) and whole app-hosting platforms.
// So the filter now (1) skips certificates from enterprise/OV-EV issuers, phishing overwhelmingly uses
// free or cheap domain-validated certificates (Aalborg University study), (2) treats app-hosting
// platforms as separate sites, and (3) splits the output: `candidates` for human review, and a stricter
// `domains` list (name imitation PLUS another phishing signal) that is shipped to devices.
// Uses crt.sh (free community service): be gentle.

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeUrl, splitDomain } from '../engine/url.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const REFILTER = args.includes('--refilter');
const daysArg = args.indexOf('--days');
const DAYS = daysArg >= 0 ? Number(args[daysArg + 1]) : 120;
const only = args.filter((a, i) => !a.startsWith('--') && (daysArg < 0 || i !== daysArg + 1));
const PRIORITY = ['emiratesnbd', 'adcb', 'bankfab', 'mashreq', 'adib', 'rakbank', 'emiratesislamic', 'adpolice', 'dubaipolice', 'uaepass',
  'salik', 'emiratespost', 'aramex', 'etisalat', 'dewa', 'tamm', 'mohre', 'gdrfa', 'centralbank', 'cbuae', 'emiratesid', 'ecrime'];
const TOKENS = only.length ? only : PRIORITY;
const ENTERPRISE_CA = /digicert|entrust|globalsign|geotrust|thawte|symantec|verisign|quovadis|swisssign|certum|identrust|harica|trustwave/i;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function judge(host, issuer) {
  if (ENTERPRISE_CA.test(issuer || '')) return null; // organisation-validated: almost always the real company
  const a = analyzeUrl('https://' + host + '/');
  if (a.official) return null;
  const imitation = a.lookalike?.inst || a.brand?.inst;
  if (!imitation) return null;
  const extra = !!a.lookalike || a.signals.some(s => s.id !== 'brand_in_domain' && s.w >= 0.15);
  return { a, imitation, extra };
}

async function crtsh(token) {
  const url = `https://crt.sh/?q=%25${encodeURIComponent(token)}%25&output=json`;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(90000), headers: { accept: 'application/json' } });
      if (r.ok) return await r.json();
      process.stdout.write(`  (crt.sh HTTP ${r.status}, retry ${attempt})\n`);
    } catch (e) {
      process.stdout.write(`  (crt.sh ${String(e.message || e).slice(0, 60)}, retry ${attempt})\n`);
    }
    await sleep(4000 * attempt);
  }
  return null;
}

let previous = { candidates: [], domains: [] };
try { previous = (await import('../data/radar.js')).default; } catch { /* first run */ }
const pool = new Map(); // host-level records {host, firstSeen, issuer}
for (const d of [...(previous.candidates || []), ...(previous.domains || [])]) {
  for (const host of d.hosts || [d.registrable]) pool.set(host, { host, firstSeen: d.firstSeen, issuer: d.issuer });
}

let failures = 0;
if (!REFILTER) {
  const since = Date.now() - DAYS * 86400000;
  for (const token of TOKENS) {
    process.stdout.write(`- ${token} … `);
    const certs = await crtsh(token);
    if (!certs) { failures++; console.log('unavailable'); continue; }
    let n = 0;
    for (const c of certs) {
      const t = Date.parse(c.not_before + 'Z');
      if (!(t >= since)) continue;
      const issuer = (/O=([^,]+)/.exec(c.issuer_name) || [])[1] || '';
      for (const raw of String(c.name_value).split('\n')) {
        const host = raw.trim().toLowerCase().replace(/^\*\./, '');
        if (!host || !host.includes(token)) continue;
        const day = new Date(t).toISOString().slice(0, 10);
        const prev = pool.get(host);
        if (!prev) { pool.set(host, { host, firstSeen: day, issuer, notBefore: c.not_before, loggedAt: c.entry_timestamp }); n++; }
        else {
          if (day < prev.firstSeen) prev.firstSeen = day;
          if (!prev.notBefore || c.not_before < prev.notBefore) { prev.notBefore = c.not_before; prev.loggedAt = c.entry_timestamp; }
        }
      }
    }
    console.log(`${certs.length} certificates, ${n} new names`);
    await sleep(2500);
  }
}

const byReg = new Map();
let enterprise = 0, platformOrOfficial = 0;
for (const rec of pool.values()) {
  if (ENTERPRISE_CA.test(rec.issuer || '')) { enterprise++; continue; }
  const j = judge(rec.host, rec.issuer);
  if (!j) { platformOrOfficial++; continue; }
  const reg = splitDomain(rec.host).registrable;
  const cur = byReg.get(reg) || { registrable: reg, brand: j.imitation.name.en, brandAr: j.imitation.name.ar, inst: j.imitation.id,
    firstSeen: rec.firstSeen, notBefore: rec.notBefore, loggedAt: rec.loggedAt, hosts: [], issuer: rec.issuer, risk: +j.a.risk.toFixed(2), extraSignal: false };
  if (rec.firstSeen < cur.firstSeen) cur.firstSeen = rec.firstSeen;
  if (rec.notBefore && (!cur.notBefore || rec.notBefore < cur.notBefore)) { cur.notBefore = rec.notBefore; cur.loggedAt = rec.loggedAt; }
  if (cur.hosts.length < 3 && !cur.hosts.includes(rec.host)) cur.hosts.push(rec.host);
  cur.extraSignal = cur.extraSignal || j.extra;
  byReg.set(reg, cur);
}
const candidates = [...byReg.values()].sort((a, b) => b.firstSeen.localeCompare(a.firstSeen));
const domains = candidates.filter(d => d.extraSignal);

await fs.writeFile(path.join(ROOT, 'data', 'radar.js'), `// Generated by tools/radar.js on ${new Date().toISOString()}. Do not edit by hand, re-run \`npm run radar\`.
// Look-alike domains of UAE institutions seen in public Certificate Transparency logs (via crt.sh).
// candidates = name imitations for human review; domains = stricter subset shipped to devices (weight 0.6).
// A listing means "uses the brand's name with a cheap certificate", NOT a confirmed crime, verify before acting.
export default ${JSON.stringify({ generatedAt: new Date().toISOString(), windowDays: REFILTER ? previous.windowDays : DAYS,
  tokens: REFILTER ? previous.tokens : TOKENS, failures: REFILTER ? previous.failures : failures,
  filtered: { enterpriseCertificates: enterprise, officialOrPlatform: platformOrOfficial }, candidates, domains }, null, 2)};
`);
console.log(`\nWrote data/radar.js, ${candidates.length} candidates for review, ${domains.length} shipped to devices ` +
  `(skipped ${enterprise} enterprise-certificate names and ${platformOrOfficial} official/platform names).`);
for (const d of candidates.slice(0, 25)) console.log(`  ${d.firstSeen}  ${d.registrable.padEnd(48)} uses ${d.brand}${d.extraSignal ? '  [shipped]' : ''}`);
