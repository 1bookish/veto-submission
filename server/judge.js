// Veto URL Judge: one verdict, one score and plain reasons for every URL in a list (a hidden test set, a feed,
// a police export). Layers, each one explainable:
//   1. official allowlist     an official UAE institution's domain is never flagged
//   2. restricted registries  gov.ae / ac.ae / mil.ae (and .gov / .edu / .mil): only real institutions can register
//   3. rulebook               look-alike letters, brand glued to words, punycode, "@" tricks, raw IPs (engine/url.js)
//   4. full-URL model         engine/urlml2-core.js: host + path + query + popularity, trained on dated public data
//   5. popularity guard       a top-10k site (not a hosting platform) needs much stronger evidence to be flagged
//   6. ONLINE (opt-in)        follow redirects and short links to the real destination, judge that too; domain age
//                             and registry holds (RDAP); does it resolve; known-phishing feeds; what the page asks for
// Offline mode sends nothing anywhere and takes ~1 ms per URL.

// Layers 1-5 are engine/judge-core.js, shared with the browser extension; this file adds the online layer and lists.
import { splitDomain } from '../engine/url.js';
import { parseUrl, refang, model2Info } from '../engine/urlml2.js'; // also points the shared scorer at the files on disk
import { judgeOffline, THRESHOLDS, sig } from '../engine/judge-core.js';
import { findInstitutions } from '../engine/extract.js';
import { matchForm } from '../engine/normalize.js';
import { fetchBytes } from './netguard.js';
import { rdapDomain } from './forensics.js';
import { feedHit, feedsInfo } from './feeds.js';
import dns from 'node:dns';

export { judgeOffline, THRESHOLDS, REASON_SOURCES } from '../engine/judge-core.js';

// ---- online layer ---------------------------------------------------------------------------
const resolver = new dns.promises.Resolver({ timeout: 2500, tries: 1 });
async function resolves(host) { try { await resolver.resolve4(host); return true; } catch (e) { return e.code === 'ENODATA' ? true : e.code === 'ENOTFOUND' ? false : null; } }
const SECRETS = /type\s*=\s*["']?password|name\s*=\s*["'](?:[^"']*[_-])?(?:pass(?:word)?|pin|otp|card(?:_?(?:number|no))?|cvv|cvc|iban)(?:[_-][^"']*)?["']/gi;

/** Online verdict: the offline one plus redirects / short links, DNS, RDAP age and holds, feeds and the page itself. */
export async function judgeOnline(input) {
  const t0 = performance.now();
  const base = judgeOffline(input);
  if (base.verdict === 'invalid' || base.layers?.official || base.layers?.restricted) return base;
  const extra = [];
  const u = parseUrl(input);
  const host = base.host;
  // 1. feeds (local cache refreshed with `npm run feeds`)
  const fh = feedHit(u.href, host);
  if (fh) extra.push(sig('feed', 0.97, `Listed as phishing by ${fh}.`, `مدرج كموقع احتيال في ${fh}.`));
  // 2. where does it really go? (short links, redirects, cloaked bounces), and what does the landing page ask?
  const [alive, r] = await Promise.all([resolves(u.hostname), fetchBytes(u.href, { maxBytes: 600_000, timeout: 7000 }).catch(e => ({ ok: false, error: String(e.message || e) }))]);
  let final = null;
  if (alive === false) extra.push(sig('dead', base.score >= 0.25 ? 0.35 : 0.1, 'The domain does not exist (anymore): scam domains are often taken down within days.', 'النطاق غير موجود (بعد الآن): تُحذف نطاقات الاحتيال غالباً خلال أيام.'));
  if (r.ok) {
    let fu; try { fu = new URL(r.finalUrl); } catch { fu = null; }
    if (fu && splitDomain(fu.hostname).registrable !== base.reg) {
      final = judgeOffline(fu.href);
      if (final.verdict !== 'invalid') extra.push(sig('lands_on', final.layers?.official ? 0 : final.score, `The link really leads to ${fu.hostname}${final.layers?.official ? ', an official site' : ` (${final.verdict})`}.`, `يقود الرابط فعلياً إلى ${fu.hostname}.`));
    }
    const html = r.bytes.toString('utf8');
    const title = ((/<title[^>]*>([^<]{0,160})/i.exec(html) || [])[1] || '').trim();
    const text = html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 4000);
    const secrets = (html.match(SECRETS) || []).length;
    const claims = findInstitutions(matchForm(`${title} ${text}`.split(host).join(' ')), `${title} ${text}`).filter(c => !c.inst.generic && !c.mention);
    const landReg = fu ? splitDomain(fu.hostname).registrable : base.reg;
    const pretends = claims.find(c => !c.inst.domains.includes(landReg));
    if (secrets && pretends) extra.push(sig('page_pretends', 0.85, `The page calls itself ${pretends.inst.name.en} and asks for passwords or card details, but it is not on ${pretends.inst.domains[0]}.`, `الصفحة تقدّم نفسها باسم ${pretends.inst.name.ar} وتطلب كلمات مرور أو بيانات بطاقة، لكنها ليست على ${pretends.inst.domains[0]}.`));
    else if (secrets && base.score >= 0.25) extra.push(sig('page_secrets', 0.4, 'The page asks for a password, PIN or card details.', 'الصفحة تطلب كلمة مرور أو رقماً سرياً أو بيانات بطاقة.'));
  } else if (/HTTP 4\d\d/.test(r.error || '') && base.score >= 0.3) extra.push(sig('gone', 0.15, `The page is gone (${r.error}).`, `الصفحة لم تعد موجودة (${r.error}).`));
  // 3. who registered it, when, and is the registry holding it (taken down for abuse)?
  if (base.score >= 0.15 || fh) {
    const d = await rdapDomain(base.reg).catch(() => null);
    if (d) {
      if ((d.status || []).some(st => /hold/i.test(st))) extra.push(sig('on_hold', 0.8, `The registry has put the domain on hold (${d.status.filter(st => /hold/i.test(st)).join(', ')}): usually a takedown for abuse.`, 'وضع السجل النطاق قيد التعليق: غالباً إزالة بسبب إساءة الاستخدام.'));
      if (d.ageDays != null && d.ageDays < 7) extra.push(sig('new_domain', 0.6, `Registered only ${d.ageDays} day(s) ago.`, `سُجّل قبل ${d.ageDays} يوم فقط.`));
      else if (d.ageDays != null && d.ageDays < 30) extra.push(sig('new_domain', 0.45, `Registered ${d.ageDays} days ago.`, `سُجّل قبل ${d.ageDays} يوماً.`));
      else if (d.ageDays != null && d.ageDays > 3650 && !fh) extra.push(sig('old_domain', -0.3, `Registered ${Math.floor(d.ageDays / 365)} years ago.`, `سُجّل قبل ${Math.floor(d.ageDays / 365)} سنة.`));
    }
  }
  let score = base.score;
  for (const x of extra) {
    if (x.w > 0) score = 1 - (1 - score) * (1 - x.w);
    else if (x.w < 0) score *= 1 + x.w;
  }
  if (final?.layers?.official && !fh) score = Math.min(score, 0.1);
  const out = { ...base, score: +score.toFixed(4), finalUrl: r.ok ? r.finalUrl : null, reasons: [...extra.filter(x => x.w !== 0), ...base.reasons].sort((x, y) => y.w - x.w).slice(0, 6), online: true };
  out.verdict = score >= THRESHOLDS.phishing ? 'phishing' : score >= THRESHOLDS.suspicious ? 'suspicious' : 'legitimate';
  out.ms = +(performance.now() - t0).toFixed(1);
  return out;
}

/** Metrics for labelled lists: "flagged" = phishing (strict) and phishing-or-suspicious (cautious). */
export function metrics(rows) {
  const labelled = rows.filter(r => r.label === 0 || r.label === 1);
  if (!labelled.length) return null;
  const calc = flag => {
    let tp = 0, fp = 0, fn = 0, tn = 0;
    for (const r of labelled) { const f = flag(r); if (f && r.label) tp++; else if (f) fp++; else if (r.label) fn++; else tn++; }
    const precision = tp / Math.max(1, tp + fp), recall = tp / Math.max(1, tp + fn);
    return { n: labelled.length, tp, fp, fn, tn, precision: +precision.toFixed(4), recall: +recall.toFixed(4), f1: +(2 * precision * recall / Math.max(1e-9, precision + recall)).toFixed(4),
      fpr: +(fp / Math.max(1, fp + tn)).toFixed(4), accuracy: +((tp + tn) / labelled.length).toFixed(4) };
  };
  // "invalid" rows (not a web address) count as not flagged; report how many so a format problem is visible
  return { strict: calc(r => r.verdict === 'phishing'), cautious: calc(r => r.verdict === 'phishing' || r.verdict === 'suspicious'),
    invalid: labelled.filter(r => r.verdict === 'invalid').length };
}

const POS = /^(1|phish|phishing|phishy|malicious|malware|scam|scams|fraud|fraudulent|bad|fake|true|yes|spam|unsafe|dangerous|harmful|positive)$/i;
const NEG = /^(0|legit|legitimate|benign|safe|good|clean|false|no|official|normal|ham|negative|genuine|trusted|(not|non)[\s_-]?(phish|phishing|malicious|scam|fraud|fraudulent))$/i;
const labelOf = v => { const s = String(v ?? '').trim().replace(/^["']|["']$/g, ''); return !s ? null : POS.test(s) ? 1 : NEG.test(s) ? 0 : null; };
const URLISH = /^(?:[a-z][a-z0-9+.\-]*:\/\/|www\.)\S+$|^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:[\/?#]\S*)?$/i;
const isUrlish = v => URLISH.test(refang(v));
const URL_HEAD = /^(url|urls|link|links|uri|href|domain|domains|host|hostname|website|site|address)$|url|link|domain|website/;
const LABEL_HEAD = /^(label|labels|class|type|status|result|target|verdict|category|y|ground_?truth|is_?phishing|phishing|is_?fraud|fraud|is_?malicious|malicious|is_?scam|scam)$|label|phish|fraud|malicious|class/;
/** Split one CSV line on `d`, honouring double quotes ("a,b" and "" escapes). */
function splitCsv(line, d) {
  const out = []; let cur = '', q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) { if (ch === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += ch; }
    else if (ch === '"' && !cur.trim()) { q = true; cur = ''; }
    else if (ch === d) { out.push(cur.trim()); cur = ''; }
    else cur += ch;
  }
  out.push(cur.trim());
  return out;
}
const countOutsideQuotes = (line, d) => { let n = 0, q = false; for (const ch of line) { if (ch === '"') q = !q; else if (ch === d && !q) n++; } return n; };
/**
 * Accepts a plain list (one URL per line, optional tab and label) or a delimited file (comma, semicolon, tab or pipe)
 * with or without a header. Columns are found by name first ("url", "Website URL", "is_fraud", ...), then by content,
 * so an organiser's file with unfamiliar column names is still read correctly. Defanged links are accepted.
 */
export function parseList(text) {
  const lines = String(text || '').replace(/^﻿/, '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (!lines.length) return [];
  const d = ['\t', ',', ';', '|'].map(x => [x, countOutsideQuotes(lines[0], x)]).sort((a, b) => b[1] - a[1])[0];
  const delim = d[1] > 0 ? d[0] : null;
  const plain = () => lines.map(l => { const [url, lab] = l.split('\t'); return { url: url.trim(), label: labelOf(lab) }; }).filter(r => r.url);
  if (!delim) return plain();
  const first = splitCsv(lines[0], delim);
  const header = !first.some(isUrlish) && first.some(x => /[a-z]/i.test(x));
  const body = (header ? lines.slice(1) : lines).map(l => splitCsv(l, delim));
  const sample = body.slice(0, 200);
  const width = Math.max(first.length, ...sample.map(c => c.length));
  const share = (col, test) => { const v = sample.map(c => c[col]).filter(x => x != null && x !== ''); return v.length ? v.filter(test).length / v.length : 0; };
  const names = header ? first.map(x => x.toLowerCase().replace(/[^a-z0-9_ ]/g, '').trim()) : [];
  let ui = header ? names.findIndex(x => URL_HEAD.test(x)) : -1;
  if (ui < 0) { // by content: the column that looks most like web addresses
    let best = 0;
    for (let k = 0; k < width; k++) { const s = share(k, isUrlish); if (s > best) { best = s; ui = k; } }
    if (best < 0.5) ui = -1;
  }
  if (ui < 0) return header ? [] : plain();
  let li = header ? names.findIndex((x, k) => k !== ui && LABEL_HEAD.test(x)) : -1;
  if (li < 0) { for (let k = 0; k < width; k++) if (k !== ui && share(k, v => labelOf(v) != null) >= 0.8) { li = k; break; } }
  if (!header && li < 0 && delim !== '\t') return plain(); // a comma inside a bare URL list is part of the URL
  const cols = header ? first.length : width;
  return body.map(c => {
    // an unquoted delimiter inside the URL makes extra fields: give them back to the URL column
    if (c.length > cols && cols > 0) { const extra = c.length - cols; c = [...c.slice(0, ui), c.slice(ui, ui + extra + 1).join(delim), ...c.slice(ui + extra + 1)]; }
    return { url: (c[ui] || '').trim(), label: li >= 0 ? labelOf(c[li]) : null };
  }).filter(r => r.url);
}

export async function judgeList(rows, { online = false, concurrency = 12, onProgress } = {}) {
  const out = new Array(rows.length);
  let next = 0, done = 0;
  await Promise.all(Array.from({ length: online ? concurrency : 1 }, async () => {
    while (next < rows.length) {
      const k = next++;
      const v = online ? await judgeOnline(rows[k].url).catch(() => judgeOffline(rows[k].url)) : judgeOffline(rows[k].url);
      out[k] = { ...v, label: rows[k].label ?? null };
      if (onProgress && ++done % 25 === 0) onProgress(done, rows.length);
    }
  }));
  return { results: out, metrics: metrics(out), model: model2Info() ? { version: model2Info().version, threshold: model2Info().threshold } : null, feeds: online ? feedsInfo() : null };
}
