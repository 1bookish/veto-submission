// node tools/url-dataset.js --out <dir> [--days 200] [--crawl 3500]
// Collects the public data for the full-URL model (tools/train-url-model2.js). Nothing is stored in the repo.
//   1. phishing, DATED: the OpenPhish community feed history kept on GitHub (openphish/public_feed), one snapshot
//      per day, so the test set can be the most recent weeks (a time split, like a real deployment).
//   2. phishing: Phishing.Database "ACTIVE" links (GitHub, MIT), undated, training only.
//   3. legitimate DEEP links: the homepages of popular sites (Tranco), of the 77 official UAE institutions and of
//      PhiUSIIL's legitimate sites are fetched once and their own links collected. Without deep legitimate links a
//      model learns "has a path = phishing", which is wrong.
import fs from 'node:fs';
import path from 'node:path';
import { INSTITUTIONS } from '../data/institutions.js';
import { splitDomain } from '../engine/url.js';

const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const OUT = arg('--out');
if (!OUT) { console.error('usage: node tools/url-dataset.js --out <dir> [--days 200] [--crawl 3500] [--tranco <csv>] [--phiusiil <csv>]'); process.exit(1); }
const DAYS = Number(arg('--days', 200));
const CRAWL = Number(arg('--crawl', 3500));
fs.mkdirSync(OUT, { recursive: true });
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function pool(items, n, fn) { const q = items.slice(); await Promise.all(Array.from({ length: n }, async () => { while (q.length) await fn(q.shift()); })); }
const only = (args.find(a => a.startsWith('--only=')) || '').slice(7).split(',').filter(Boolean);
const want = k => !only.length || only.includes(k);

// ---- 1. OpenPhish history (one snapshot per day) --------------------------------------------
if (want('openphish')) {
  const byDay = new Map();
  for (let page = 1; page <= 60; page++) {
    const r = await fetch(`https://api.github.com/repos/openphish/public_feed/commits?per_page=100&page=${page}`, { headers: { 'user-agent': 'veto-research', accept: 'application/vnd.github+json' } });
    if (!r.ok) { console.log('github api', r.status, await r.text().then(t => t.slice(0, 120))); break; }
    const list = await r.json();
    if (!list.length) break;
    for (const c of list) {
      const day = (c.commit?.committer?.date || c.commit?.author?.date || '').slice(0, 10);
      if (day && !byDay.has(day)) byDay.set(day, c.sha);
    }
    const oldest = [...byDay.keys()].sort()[0];
    process.stdout.write(`\r openphish commits: page ${page}, ${byDay.size} days (oldest ${oldest})   `);
    if (byDay.size >= DAYS) break;
    await sleep(800);
  }
  console.log();
  const rows = [];
  let got = 0;
  await pool([...byDay].slice(0, DAYS), 8, async ([day, sha]) => {
    try {
      const r = await fetch(`https://raw.githubusercontent.com/openphish/public_feed/${sha}/feed.txt`, { headers: { 'user-agent': 'veto-research' } });
      if (!r.ok) return;
      for (const u of (await r.text()).split(/\r?\n/)) if (/^https?:\/\//i.test(u.trim())) rows.push([u.trim(), day]);
      got++;
    } catch { /* skip day */ }
  });
  // keep the FIRST day each URL was seen
  const first = new Map();
  for (const [u, d] of rows) if (!first.has(u) || d < first.get(u)) first.set(u, d);
  fs.writeFileSync(path.join(OUT, 'openphish_history.tsv'), [...first].map(([u, d]) => `${d}\t${u}`).join('\n'));
  console.log(`openphish history: ${got} daily snapshots, ${first.size} unique URLs`);
}

// ---- 2. Phishing.Database active links ------------------------------------------------------
if (want('pdb')) {
  try {
    const r = await fetch('https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt', { headers: { 'user-agent': 'veto-research' } });
    const t = await r.text();
    const lines = t.split(/\r?\n/).filter(l => /^https?:\/\//i.test(l));
    fs.writeFileSync(path.join(OUT, 'pdb_active.txt'), lines.join('\n'));
    console.log(`phishing.database active: ${lines.length} URLs`);
  } catch (e) { console.log('phishing.database failed', e.message); }
}

// ---- 3. legitimate deep links ----------------------------------------------------------------
if (want('crawl')) {
  const domains = new Set();
  for (const i of INSTITUTIONS) for (const d of i.domains) domains.add(d);
  const tranco = arg('--tranco');
  if (tranco) for (const l of fs.readFileSync(tranco, 'utf8').split(/\r?\n/).slice(0, CRAWL)) { const d = l.split(',')[1]; if (d) domains.add(d.trim()); }
  const phi = arg('--phiusiil');
  if (phi) {
    const legit = [];
    for (const line of fs.readFileSync(phi, 'utf8').split(/\r?\n/).slice(1)) {
      const m = /^[^,]*,([^,]*),/.exec(line);
      if (m && line.trim().endsWith(',1')) legit.push(m[1]);
    }
    for (let k = 0; k < Math.min(1500, legit.length); k += 1) { try { domains.add(new URL(legit[Math.floor(k * legit.length / 1500)]).hostname.replace(/^www\./, '')); } catch { /* skip */ } }
  }
  const SKIP = Number(arg('--skip', 0));
  const out = fs.createWriteStream(path.join(OUT, 'legit_crawl.tsv'), { flags: SKIP ? 'a' : 'w' });
  let ok = 0, n = 0, urls = 0;
  const list = [...domains].slice(SKIP);
  // a hard deadline per site: some servers trickle bytes forever, which an abort signal alone does not always stop
  const within = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('deadline')), ms))]);
  await pool(list, 32, async d => {
    n++;
    for (const base of [`https://${d}/`, `https://www.${d}/`]) {
      try {
        const ctl = new AbortController();
        const got = await within((async () => {
          const r = await fetch(base, { headers: { 'user-agent': UA, accept: 'text/html' }, redirect: 'follow', signal: ctl.signal });
          if (!r.ok || !/html/i.test(r.headers.get('content-type') || '')) return null;
          return { r, html: (await r.text()).slice(0, 1_500_000) };
        })(), 10000).catch(e => { ctl.abort(); throw e; });
        if (!got) continue;
        const { r, html } = got;
        const finalUrl = r.url;
        const reg = splitDomain(new URL(finalUrl).hostname).registrable;
        const seen = new Set();
        for (const m of html.matchAll(/<a\b[^>]*?href\s*=\s*["']([^"'#]+)["']/gi)) {
          let u;
          try { u = new URL(m[1].replace(/&amp;/g, '&'), finalUrl); } catch { continue; }
          if (!/^https?:$/.test(u.protocol)) continue;
          const href = u.href;
          if (href.length > 400 || seen.has(href)) continue;
          // own links only (the site's own pages), plus a few outbound links to other real sites
          const own = splitDomain(u.hostname).registrable === reg;
          if (!own && seen.size > 3) continue;
          seen.add(href);
          out.write(`${d}\t${own ? 'own' : 'out'}\t${href}\n`);
          urls++;
          if (seen.size >= 30) break;
        }
        out.write(`${d}\thome\t${finalUrl}\n`);
        ok++;
        break;
      } catch { /* try www. */ }
    }
    if (n % 200 === 0) process.stdout.write(`\r crawl: ${n}/${list.length} domains, ${ok} reached, ${urls} links   `);
  });
  out.end();
  console.log(`\nlegit crawl: ${ok}/${list.length} sites reached, ${urls} links`);
}
console.log('done');
