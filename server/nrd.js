// Newly registered domains: every domain registered worldwide YESTERDAY (WhoisDS free daily list, ~70,000 a day),
// read in about 20 seconds and filtered for names that imitate an institution in the Veto rulebook. A scam domain is
// usually registered a day or more before its SMS wave, so this is the earliest public trace there is, before the
// certificate, before the first victim. Files are cached in var/nrd/ (private). No key needed.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readZipEntry } from './zip.js';
import { analyzeUrl } from '../engine/url.js';
import { mlUrlScore2 } from '../engine/urlml2.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(process.env.VETO_VAR || path.join(ROOT, 'var'), 'nrd');
// short brand tokens that are ordinary words in other languages ("du", "moi", "tax") only count as real look-alikes
const WEAK = new Set(['du', 'moi', 'icp', 'rta', 'fab', 'dib', 'cbd', 'nbf', 'sib', 'uab', 'wio', 'liv', 'tax', 'fta', 'dhl', 'ups', 'noon', 'live']);

export async function nrdList(day) {
  fs.mkdirSync(DIR, { recursive: true });
  const f = path.join(DIR, day + '.txt');
  if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').split(/\r?\n/).filter(Boolean);
  const b64 = Buffer.from(day + '.zip').toString('base64');
  const r = await fetch(`https://www.whoisds.com//whois-database/newly-registered-domains/${b64}/nrd`, { headers: { 'user-agent': 'Mozilla/5.0 (Veto research)' }, signal: AbortSignal.timeout(60000) });
  if (!r.ok) throw new Error(`WhoisDS ${day}: HTTP ${r.status}`);
  const buf = Buffer.from(await r.arrayBuffer());
  const data = await readZipEntry(buf, 'domain-names.txt');
  if (!data) throw new Error(`WhoisDS ${day}: no domain list in the archive`);
  const txt = data.toString('utf8');
  fs.writeFileSync(f, txt);
  return txt.split(/\r?\n/).filter(Boolean);
}

/** Suspects among the domains registered on the last `days` days (yesterday first). */
export async function nrdCandidates({ days = 2, insts = null, log = () => {} } = {}) {
  const out = [];
  for (let k = 1; k <= days; k++) {
    const day = new Date(Date.now() - k * 86400000).toISOString().slice(0, 10);
    let list;
    try { list = await nrdList(day); } catch (e) { log(`newly registered (${day}): ${e.message}`); continue; }
    let n = 0;
    for (const d of list) {
      const a = analyzeUrl('https://' + d + '/');
      if (a.official) continue;
      const hit = a.lookalike || a.brand;
      const inst = hit?.inst;
      if (!inst || (insts && !insts.includes(inst.id))) continue;
      if (WEAK.has(hit.token) && !a.lookalike) continue;
      if (a.risk < 0.6) continue;
      const m = mlUrlScore2('https://' + d + '/');
      out.push({ host: d, inst: inst.id, how: `registered on ${day}${a.lookalike ? ' (look-alike letters)' : ''}`, sources: ['nrd'], nrdDay: day, ml2: m ? m.p : null });
      n++;
    }
    log(`newly registered on ${day}: ${list.length.toLocaleString('en')} domains read, ${n} imitate a rulebook institution`);
  }
  return out;
}
