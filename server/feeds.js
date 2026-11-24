// Known-phishing feeds for the URL Judge's online mode (`npm run feeds` refreshes them into var/feeds/, private).
//   OpenPhish community feed (research use) · Phishing.Database ACTIVE domains (MIT)
// A feed is a REACTIVE layer: it only knows sites someone already reported. Veto's accuracy numbers are reported
// with feeds OFF (zero-day) and ON, separately. On hosting platforms (Google Sites, web.app …) only the exact URL
// counts, never the whole platform.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isPlatform } from '../engine/urlml2.js';
import { splitDomain } from '../engine/url.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(process.env.VETO_VAR || path.join(ROOT, 'var'), 'feeds');
const SOURCES = [
  { name: 'OpenPhish', file: 'openphish.txt', url: 'https://openphish.com/feed.txt', kind: 'url' },
  { name: 'Phishing.Database', file: 'pdb-domains.txt', url: 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt', kind: 'host' }
];
let loaded = null, enabled = process.env.VETO_FEEDS !== '0';
export const setFeedsEnabled = v => { enabled = !!v; };
const norm = u => String(u).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/+$/, '');

function load() {
  if (loaded) return loaded;
  loaded = { urls: new Map(), hosts: new Map(), info: [] };
  for (const s of SOURCES) {
    const f = path.join(DIR, s.file);
    if (!fs.existsSync(f)) continue;
    let n = 0;
    for (const line of fs.readFileSync(f, 'utf8').split(/\r?\n/)) {
      const l = line.trim();
      if (!l || l.startsWith('#')) continue;
      if (s.kind === 'host') { loaded.hosts.set(l.toLowerCase().replace(/^www\./, ''), s.name); n++; continue; }
      loaded.urls.set(norm(l), s.name);
      try {
        const h = new URL(/^[a-z]+:\/\//i.test(l) ? l : 'http://' + l).hostname.toLowerCase().replace(/^www\./, '');
        if (!isPlatform(h, splitDomain(h).registrable) && !loaded.hosts.has(h)) loaded.hosts.set(h, s.name);
      } catch { /* skip */ }
      n++;
    }
    loaded.info.push({ name: s.name, entries: n, updated: fs.statSync(f).mtime.toISOString() });
  }
  return loaded;
}

export function feedHit(url, host) {
  if (!enabled) return null;
  const L = load();
  const byUrl = L.urls.get(norm(url));
  if (byUrl) return byUrl;
  const h = String(host || '').toLowerCase().replace(/^www\./, '');
  if (!h || isPlatform(h, splitDomain(h).registrable)) return null;
  return L.hosts.get(h) || null;
}
export function feedsInfo() { return { enabled, sources: load().info }; }

export async function refreshFeeds(log = console.log) {
  fs.mkdirSync(DIR, { recursive: true });
  for (const s of SOURCES) {
    try {
      const r = await fetch(s.url, { headers: { 'user-agent': 'Veto-anti-scam/0.4 (research)' }, signal: AbortSignal.timeout(60000) });
      if (!r.ok) { log(`${s.name}: HTTP ${r.status}`); continue; }
      const t = await r.text();
      fs.writeFileSync(path.join(DIR, s.file), t);
      log(`${s.name}: ${t.split('\n').filter(x => x.trim() && !x.startsWith('#')).length} entries`);
    } catch (e) { log(`${s.name}: ${e.message}`); }
  }
  loaded = null;
  return feedsInfo();
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  refreshFeeds().then(i => console.log(JSON.stringify(i)));
}
