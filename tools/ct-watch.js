// node tools/ct-watch.js [--minutes 10] [--poll-s 5] [--batch 256] [--par 4] [--max-backlog 5000] [--sample 0.02] [--out data/ct-watch-report.json]
// --minutes 0 runs until stopped and rewrites the report every minute. Live watch of public Certificate Transparency logs,
// read directly from the logs (RFC 6962 get-sth and get-entries), not from crt.sh. Only usable, current, production logs
// from the published Google log list are read. A name is judged offline with judgeOffline when its registrable domain
// carries a UAE institution token (the brand gate, generic words excluded as in server/judge.js), and a deterministic 2 %
// sample of the other names is judged to measure the generic rate. An alert is a brand-gated name judged phishing or
// suspicious on a registrable domain outside the Tranco top 100,000. Protocol: docs/RESEARCH_LOG.md, "Live CT watch" and
// its amendments (24 and 25 Nov). Counts and times only: no name is written.
// Two kinds of log are read: RFC 6962 logs (get-sth, get-entries) and tiled logs (the static CT API: a checkpoint and
// data tiles of 256 entries). Let's Encrypt, Google's newest shards and several other operators now log only to tiled
// logs, so a watch that reads only RFC 6962 logs misses most new certificates.
// Alerts are enriched (does the name resolve, which network hosts it, how old is the domain) and linked: alerts on the
// same IP address are counted as one group. Alert names and their details go only to a private file outside the
// repositories (--private-out); the report holds counts.
import crypto from 'node:crypto';
import dns from 'node:dns';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { judgeOffline } from '../server/judge.js';
import { tilePath, tileLeaves, fastCert } from '../server/ctparse.js';
import { rdapDomain, ipInfo } from '../server/forensics.js';
import { INSTITUTIONS } from '../data/institutions.js';
import { splitDomain } from '../engine/url.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const MINUTES = Number(arg('--minutes', '10'));
const POLL_MS = Math.round(Number(arg('--poll-s', '5')) * 1000);
const BATCH = Number(arg('--batch', '256'));
const PAR = Math.max(1, Number(arg('--par', '4')));
const ADAPTIVE = args.includes('--adaptive');
const MAX_BACKLOG = Number(arg('--max-backlog', '5000'));
const SAMPLE = Number(arg('--sample', '0.02'));
const OUT = arg('--out', path.join(ROOT, 'data', 'ct-watch-report.json'));
const TILED = !args.includes('--no-tiled');
const ENRICH = !args.includes('--no-enrich');
const PRIVATE_OUT = arg('--private-out', path.join(ROOT, '..', '..', 'veto-laptop-only', 'runtime-state', 'ct-alerts-private.jsonl'));
const TILE_PAR = Math.max(1, Number(arg('--tile-par', '6')));
const RUN_START = Date.now();
const deadline = MINUTES > 0 ? RUN_START + MINUTES * 60000 : Infinity;
const LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json';
const NEWLINE = String.fromCharCode(10);
const DAY_MS = 86400000;
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function getJson(url, timeoutMs = 20000) {
  let last = new Error('no response');
  for (let a = 0; a < 4; a++) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
      if (r.status === 429 || r.status >= 500) { last = new Error('HTTP ' + r.status); await sleep(1000 * (a + 1)); continue; }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.json();
    } catch (e) { last = e; await sleep(400 * (a + 1)); }
  }
  throw last;
}

// Tranco top list as registrable domains (a public ranking): used only to mark likely false alarms
const popular = new Set(zlib.gunzipSync(fs.readFileSync(path.join(ROOT, 'data', 'tranco-top100k.txt.gz'))).toString('utf8')
  .split(NEWLINE).map(l => l.split(',').pop().trim().toLowerCase()).filter(Boolean));
// Generic words that the offline judge already treats as generic (server/judge.js, GENERIC_TOKENS): not brand gates
const GENERIC = new Set(['centralbank', 'police', 'emirates', 'finance', 'post', 'customs', 'courts', 'tax', 'bank', 'gov']);
// UAE institution name tokens (approximate brand gate)
const uaeTokens = [...new Set(INSTITUTIONS.map(i => ((i.domains || [])[0] || '').toLowerCase().split('.')[0]).filter(s => s.length >= 4 && !GENERIC.has(s)))];
function brandOf(reg) {
  const sld = reg.split('.')[0];
  const parts = sld.split('-');
  return uaeTokens.find(t => sld.length <= t.length + 20 && (parts.includes(t) || sld.startsWith(t) || sld.endsWith(t))) || null;
}
// deterministic sample: the same name always gives the same decision
const sampled = name => crypto.createHash('sha256').update(name).digest()[0] / 256 < SAMPLE;
function wilson(k, n) {
  if (!n) return [null, null];
  const z = 1.959964, p = k / n, d = 1 + z * z / n;
  const c = (p + z * z / (2 * n)) / d, h = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d;
  return [+Math.max(0, c - h).toFixed(4), +Math.min(1, c + h).toFixed(4)];
}

async function getBytes(url, timeoutMs = 30000) {
  let last = new Error('no response');
  for (let a = 0; a < 3; a++) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
      if (r.status === 429 || r.status >= 500) { last = new Error('HTTP ' + r.status); await sleep(1000 * (a + 1)); continue; }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return Buffer.from(await r.arrayBuffer());
    } catch (e) { last = e; if (/HTTP 4/.test(String(e.message))) break; await sleep(400 * (a + 1)); }
  }
  throw last;
}

const list = await getJson(LIST_URL, 60000);
const now0 = Date.now();
const logs = [], notRead = [];
for (const op of list.operators) {
  for (const [kind, arr] of [['rfc6962', op.logs || []], ['tiled', op.tiled_logs || []]]) for (const l of arr) {
    const state = Object.keys(l.state || {})[0] || 'unknown';
    const end = l.temporal_interval?.end_exclusive;
    const ended = end && Date.parse(end) <= now0;
    const url = kind === 'tiled' ? l.monitoring_url : l.url;
    if (state === 'usable' && !ended && (l.log_type || 'prod') === 'prod' && url && (kind === 'rfc6962' || TILED)) {
      logs.push({ kind, operator: op.name, desc: l.description || '', base: url.endsWith('/') ? url : url + '/', next: null, startSize: 0, sequenced: 0, fetched: 0, skipped: 0, errors: 0, parseErrors: 0, names: 0, brandNames: 0, alerts: 0 });
    } else notRead.push({ kind, operator: op.name, log: l.description || '', state: ended ? 'ended' : state === 'usable' && kind === 'tiled' && !TILED ? 'tiled, off' : state });
  }
}

const stats = {
  certs: 0, names: 0, parseErrors: 0, judgeErrors: 0, judgeMs: 0, judged: 0,
  byType: { precert: 0, x509: 0 },
  brandNames: 0, brandVerdicts: {}, brandFlaggedPopular: 0, alerts: 0,
  sampleNames: 0, sampleVerdicts: {}, sampleFlagged: 0,
  logToWatch: [], logToWatchAlerts: [], backdate: [], issuanceToWatchPrecert: [], issuanceToWatchAlerts: [],
  issuers: {},
  fast: { compared: 0, mismatches: 0, fallbacks: 0 },
  enrich: { queued: 0, done: 0, resolves: 0, noDns: 0, ageDays: [], under30d: 0, asns: {}, countries: {}, ips: {}, errors: 0 },
};

function parseEntry(e) {
  const leaf = Buffer.from(e.leaf_input, 'base64');
  const sct = Number(leaf.readBigUInt64BE(2));
  const type = leaf.readUInt16BE(10);
  if (type === 0) return { sct, type: 'x509', der: leaf.subarray(15, 15 + leaf.readUIntBE(12, 3)) };
  const x = Buffer.from(e.extra_data, 'base64');
  return { sct, type: 'precert', der: x.subarray(3, 3 + x.readUIntBE(0, 3)) };
}

function cleanName(n) {
  let x = n.startsWith('*.') ? n.slice(2) : n;
  if (x.endsWith('.')) x = x.slice(0, -1);
  return x;
}

function judge(name) {
  const t0 = performance.now();
  let v;
  try { v = judgeOffline('https://' + name + '/'); } catch { stats.judgeErrors++; return null; }
  stats.judgeMs += performance.now() - t0; stats.judged++;
  return v.verdict || 'none';
}

function processEntry(L, e, parsed = null) {
  let p, fc = null, notBefore = NaN;
  try { p = parsed || parseEntry(e); } catch { p = null; }
  if (p) {
    try { fc = fastCert(p.der); } catch { stats.fast.fallbacks++; }
    if (!fc || stats.fast.compared < 300) {
      // Node's full parser: the fallback, and the check of the fast reader on the first entries of every run
      try {
        const c = new crypto.X509Certificate(p.der);
        const m = c.issuer.match(/O=(.+)/) || c.issuer.match(/CN=(.+)/);
        const full = { names: (c.subjectAltName || '').split(', ').filter(x => x.startsWith('DNS:')).map(x => x.slice(4).trim().toLowerCase()), notBefore: Date.parse(c.validFrom), issuer: m ? m[1].trim().replace(/\\(.)/g, '$1') : 'unknown' };
        if (fc) { stats.fast.compared++; if (JSON.stringify(fc.names) !== JSON.stringify(full.names) || fc.notBefore !== full.notBefore || fc.issuer !== full.issuer) stats.fast.mismatches++; }
        else fc = full;
      } catch { /* unparseable: counted below */ }
    }
    if (fc) notBefore = fc.notBefore;
  }
  if (!Number.isFinite(notBefore)) { stats.parseErrors++; L.parseErrors++; return; }
  const seen = Date.now();
  stats.certs++; stats.byType[p.type]++;
  stats.logToWatch.push(seen - p.sct);
  if (p.type === 'precert' && p.sct - notBefore <= 2 * DAY_MS) {
    stats.backdate.push(p.sct - notBefore);
    stats.issuanceToWatchPrecert.push(seen - notBefore);
  }
  const issuer = fc.issuer;
  stats.issuers[issuer] = (stats.issuers[issuer] || 0) + 1;
  const names = [...new Set(fc.names.map(cleanName))].slice(0, 100);
  for (const name of names) {
    const reg = splitDomain(name).registrable;
    if (!reg) continue;
    stats.names++;
    const brand = brandOf(reg);
    if (brand) {
      stats.brandNames++; L.brandNames++;
      const verdict = judge(name);
      if (verdict === null) continue;
      stats.brandVerdicts[verdict] = (stats.brandVerdicts[verdict] || 0) + 1;
      if (verdict === 'phishing' || verdict === 'suspicious') {
        if (popular.has(reg)) stats.brandFlaggedPopular++;
        else {
          stats.alerts++; L.alerts++;
          stats.logToWatchAlerts.push(seen - p.sct);
          if (p.type === 'precert' && p.sct - notBefore <= 2 * DAY_MS) stats.issuanceToWatchAlerts.push(seen - notBefore);
          enqueue({ name, reg, brand, verdict, log: L.desc, kind: L.kind, loggedAt: new Date(p.sct).toISOString(), seenAt: new Date(seen).toISOString(), watchDelayS: +((seen - p.sct) / 1000).toFixed(1) });
        }
      }
    } else if (sampled(name)) {
      stats.sampleNames++;
      const verdict = judge(name);
      if (verdict === null) continue;
      stats.sampleVerdicts[verdict] = (stats.sampleVerdicts[verdict] || 0) + 1;
      if (verdict === 'phishing' || verdict === 'suspicious') stats.sampleFlagged++;
    }
  }
}

// ---- alert enrichment: DNS, network (Team Cymru origin ASN), domain age (RDAP). Four at a time, after the watch has
// read the entry, so it never slows the reading. Names and details go to the private file only.
const queue = [];
let running = 0;
const seenAlert = new Set();
function enqueue(a) {
  if (!ENRICH || seenAlert.has(a.name)) return;
  seenAlert.add(a.name);
  stats.enrich.queued++;
  queue.push(a);
  pump();
}
function pump() {
  while (running < 4 && queue.length) {
    const a = queue.shift();
    running++;
    enrichOne(a).catch(() => { stats.enrich.errors++; }).finally(() => { running--; pump(); });
  }
}
async function enrichOne(a) {
  const ips = await dns.promises.resolve4(a.name).catch(() => dns.promises.resolve4(a.reg).catch(() => []));
  const [d, ip] = await Promise.all([rdapDomain(a.reg).catch(() => null), ips[0] ? ipInfo(ips[0]).catch(() => null) : null]);
  const e = stats.enrich;
  e.done++;
  if (ips.length) { e.resolves++; e.ips[ips[0]] = (e.ips[ips[0]] || 0) + 1; } else e.noDns++;
  if (d?.ageDays != null) { e.ageDays.push(d.ageDays); if (d.ageDays < 30) e.under30d++; }
  if (ip?.asn) e.asns[ip.asn] = (e.asns[ip.asn] || 0) + 1;
  if (ip?.country) e.countries[ip.country] = (e.countries[ip.country] || 0) + 1;
  try {
    fs.mkdirSync(path.dirname(PRIVATE_OUT), { recursive: true });
    fs.appendFileSync(PRIVATE_OUT, JSON.stringify({ ...a, ips: ips.slice(0, 4), asn: ip?.asn || null, asName: ip?.asName || null, country: ip?.country || null,
      registrar: d?.registrar || null, created: d?.created || null, ageDays: d?.ageDays ?? null, status: d?.status || [] }) + NEWLINE);
  } catch { /* the private file is optional */ }
}

// Tiled log: read the checkpoint, then the data tiles that hold the new entries (a partial tile at the right edge).
async function pollTiled(L) {
  const cp = (await getBytes(L.base + 'checkpoint', 20000)).toString('utf8').split(NEWLINE);
  const size = Number.parseInt(cp[1], 10);
  if (!Number.isFinite(size)) throw new Error('bad checkpoint');
  if (L.next === null) { L.next = size; L.startSize = size; return; }
  if (size - L.next > MAX_BACKLOG) { L.skipped += size - L.next - MAX_BACKLOG; L.next = size - MAX_BACKLOG; }
  L.sequenced = size - L.startSize;
  const full = Math.floor(size / 256); // tiles 0 .. full-1 are complete
  while (L.next < size && Date.now() < deadline) {
    const idx = [];
    for (let i = Math.floor(L.next / 256); i < full && idx.length < TILE_PAR; i++) idx.push(i);
    // the partial tile at the right edge grows until it is full: fetch it only when nothing complete is waiting, and at
    // most every 15 s per log, so the same entries are not downloaded again and again
    if (!idx.length) {
      if (size % 256 === 0 || Date.now() - (L.lastPartial || 0) < 15000) break;
      L.lastPartial = Date.now();
      idx.push(full);
    }
    const tiles = await Promise.all(idx.map(i => {
      const width = Math.min(256, size - i * 256);
      return getBytes(L.base + 'tile/data/' + tilePath(i) + (width < 256 ? '.p/' + width : ''), 15000).then(b => ({ i, b })).catch(() => null);
    }));
    let progressed = false;
    for (const t of tiles) {
      if (!t) { L.errors++; break; }
      let leaves;
      try { leaves = tileLeaves(t.b); L.badTile = null; } catch {
        L.parseErrors++; stats.parseErrors++;
        L.badTile = L.badTile?.i === t.i ? { i: t.i, n: L.badTile.n + 1 } : { i: t.i, n: 1 };
        if (L.badTile.n >= 3) { const end = Math.min(size, (t.i + 1) * 256); L.skipped += end - L.next; L.next = end; L.badTile = null; progressed = true; continue; }
        break;
      }
      for (let k = 0; k < leaves.length; k++) {
        const index = t.i * 256 + k;
        if (index < L.next) continue;
        processEntry(L, null, leaves[k]);
        L.fetched++;
        L.next = index + 1;
        progressed = true;
      }
      if (L.next < Math.min(size, (t.i + 1) * 256)) break; // this tile ended early: ask again next round
    }
    if (!progressed) break;
  }
}

// Fetch the backlog in rounds of up to PAR batches at once. Batches are processed in order: a short batch moves the
// cursor to where the log actually stopped, and the batches after it are asked again in the next round.
async function pollLog(L) {
  if (L.kind === 'tiled') return pollTiled(L);
  const sth = await getJson(L.base + 'ct/v1/get-sth');
  const size = sth.tree_size;
  if (L.next === null) { L.next = size; L.startSize = size; return; }
  if (size - L.next > MAX_BACKLOG) { L.skipped += size - L.next - MAX_BACKLOG; L.next = size - MAX_BACKLOG; }
  L.sequenced = size - L.startSize;
  while (L.next < size && Date.now() < deadline) {
    // default (run 2, the best measured): fixed batches of BATCH entries. --adaptive (run 3, measured lower): the stride
    // is the length the log last returned, so the parallel batches stay contiguous
    const stride = ADAPTIVE ? Math.min(BATCH, L.stride || BATCH) : BATCH;
    const starts = [];
    for (let s = L.next, k = 0; k < PAR && s < size; k++, s += stride) starts.push(s);
    const bodies = await Promise.all(starts.map(st => getJson(L.base + `ct/v1/get-entries?start=${st}&end=${Math.min(size - 1, st + stride - 1)}`, 30000).catch(() => null)));
    let progressed = false;
    for (let k = 0; k < starts.length; k++) {
      if (starts[k] !== L.next) break;
      if (!bodies[k]) { L.errors++; break; }
      const es = bodies[k].entries || [];
      if (!es.length) break;
      for (const e of es) { processEntry(L, e); L.fetched++; }
      L.next += es.length;
      progressed = true;
      if (ADAPTIVE) L.stride = es.length < stride ? es.length : BATCH;
      if (es.length < stride) break;
    }
    if (!progressed) break;
  }
}

const q = (a, p) => { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };
const summ = a => { if (!a.length) return null; let mx = -Infinity; for (const x of a) if (x > mx) mx = x; return { n: a.length, median_s: +(q(a, 0.5) / 1000).toFixed(2), p90_s: +(q(a, 0.9) / 1000).toFixed(2), p99_s: +(q(a, 0.99) / 1000).toFixed(2), max_s: +(mx / 1000).toFixed(2) }; };
const t0 = Date.now();

function writeReport(final) {
  const top = Object.entries(stats.issuers).sort((x, y) => y[1] - x[1]).slice(0, 12).map(([issuer, certs]) => ({ issuer, certs }));
  const sequenced = logs.reduce((s, L) => s + L.sequenced, 0), fetched = logs.reduce((s, L) => s + L.fetched, 0);
  const minutes = (Date.now() - t0) / 60000;
  const sampleFlag = stats.sampleFlagged;
  const report = {
    protocol: 'project/docs/RESEARCH_LOG.md, "Live CT watch" and its amendments (24 and 25 Nov, including amendment 4: tiled logs and alert enrichment)',
    final, started: new Date(t0).toISOString(), now: new Date().toISOString(), minutes: +minutes.toFixed(2), poll_s: POLL_MS / 1000, batch: BATCH, par: PAR, max_backlog: MAX_BACKLOG, sample_rate: SAMPLE,
    logs_read: logs.map(L => ({ kind: L.kind, operator: L.operator, log: L.desc, sequenced: L.sequenced, fetched: L.fetched, skipped: L.skipped, coverage: L.sequenced ? +(L.fetched / L.sequenced).toFixed(4) : null, errors: L.errors, parse_errors: L.parseErrors, names_brand_gated: L.brandNames, alerts: L.alerts })),
    logs_not_read: notRead,
    coverage: { sequenced, fetched, share: sequenced ? +(fetched / sequenced).toFixed(4) : null, skipped: logs.reduce((s, L) => s + L.skipped, 0), entries_per_s: +(fetched / (minutes * 60)).toFixed(1),
      by_kind: Object.fromEntries(['rfc6962', 'tiled'].map(k => { const Ls = logs.filter(L => L.kind === k); const sq = Ls.reduce((s, L) => s + L.sequenced, 0), ft = Ls.reduce((s, L) => s + L.fetched, 0); return [k, { logs: Ls.length, sequenced: sq, fetched: ft, share: sq ? +(ft / sq).toFixed(4) : null }]; })) },
    enrichment: ENRICH ? (() => {
      const e = stats.enrich;
      const top = o => Object.entries(o).sort((x, y) => y[1] - x[1]).slice(0, 8).map(([k, n]) => ({ k, n }));
      const shared = Object.values(e.ips).filter(n => n >= 2);
      return { alerts_queued: e.queued, enriched: e.done, resolves: e.resolves, no_dns: e.noDns, errors: e.errors,
        domain_age_days: e.ageDays.length ? { n: e.ageDays.length, median: q(e.ageDays, 0.5), under_30_days: e.under30d } : null,
        top_networks_asn: top(e.asns), countries: top(e.countries),
        linked_groups: { ips_with_2_or_more_alerts: shared.length, alerts_in_them: shared.reduce((s, n) => s + n, 0) },
        private_file: 'names and details are written outside the repository only' };
    })() : null,
    entries: { certs: stats.certs, by_type: stats.byType, parse_errors: stats.parseErrors, names_seen: stats.names },
    brand_gate: { names_judged: stats.brandNames, verdicts: stats.brandVerdicts, flagged_popular_tranco: stats.brandFlaggedPopular, alerts: stats.alerts },
    generic_sample: { names_judged: stats.sampleNames, flagged: sampleFlag, share: stats.sampleNames ? +(sampleFlag / stats.sampleNames).toFixed(4) : null, share_95ci: wilson(sampleFlag, stats.sampleNames), verdicts: stats.sampleVerdicts },
    latency: { log_to_watch_all: summ(stats.logToWatch), log_to_watch_alerts: summ(stats.logToWatchAlerts), not_before_offset_precert: summ(stats.backdate), issuance_to_watch_precert: summ(stats.issuanceToWatchPrecert), issuance_to_watch_alerts: summ(stats.issuanceToWatchAlerts) },
    fast_reader_check: { compared_with_node_x509: stats.fast.compared, mismatches: stats.fast.mismatches, fallbacks: stats.fast.fallbacks },
    judge_ms_per_name: stats.judged ? +(stats.judgeMs / stats.judged).toFixed(4) : null, judge_errors: stats.judgeErrors,
    issuers_top: top,
    note: 'counts and times only; no name is written; alerts are judgements of the offline judge, not confirmed scams',
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + NEWLINE);
  return report;
}

console.log(`watching ${logs.length} usable, current production logs (${logs.filter(L => L.kind === 'tiled').length} tiled) (${MINUTES > 0 ? MINUTES + ' min' : 'until stopped'}); ${notRead.length} logs not read; ${PAR} batches of ${BATCH} per RFC 6962 log, ${TILE_PAR} tiles per tiled log`);
await Promise.all(logs.map(L => pollLog(L).catch(() => { L.errors++; })));
// each log on its own schedule: a slow log never holds up the others
async function watchLog(L) {
  while (Date.now() < deadline) {
    const started = Date.now();
    await pollLog(L).catch(() => { L.errors++; });
    const rest = POLL_MS - (Date.now() - started);
    if (rest > 0) await sleep(Math.min(rest, Math.max(0, deadline - Date.now())));
  }
}
const timer = setInterval(() => {
  writeReport(false);
  console.log(`${((Date.now() - t0) / 60000).toFixed(1)} min: certs ${stats.certs}, brand-gated names ${stats.brandNames}, alerts ${stats.alerts}`);
}, 60000);
// stop at the deadline; a download still in flight then is not waited for (more than 20 s)
await Promise.race([Promise.all(logs.map(watchLog)), sleep(Math.max(0, deadline - Date.now()) + 20000)]);
clearInterval(timer);
const r = writeReport(true);
console.log(JSON.stringify({ minutes: r.minutes, coverage: r.coverage, entries: r.entries, brand_gate: r.brand_gate, generic_sample: r.generic_sample, latency: r.latency, judge_ms_per_name: r.judge_ms_per_name, judge_errors: r.judge_errors }, null, 2));
process.exit(0);
