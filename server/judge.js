// Veto URL Judge: one verdict, one score and plain reasons for every URL in a list (a hidden test set, a feed,
// a police export). Layers, each one explainable:
//   1. official allowlist     an official UAE institution's domain is never flagged
//   2. restricted registries  gov.ae / ac.ae / mil.ae (and .gov / .edu / .mil): only real institutions can register
//   3. rulebook               look-alike letters, brand glued to words, punycode, "@" tricks, raw IPs (engine/url.js)
//   4. full-URL model         engine/urlml2.js: host + path + query + popularity, trained on dated public data
//   5. popularity guard       a top-10k site (not a hosting platform) needs much stronger evidence to be flagged
//   6. ONLINE (opt-in)        follow redirects and short links to the real destination, judge that too; domain age
//                             and registry holds (RDAP); does it resolve; known-phishing feeds; what the page asks for
// Offline mode sends nothing anywhere and takes ~1 ms per URL.

import { analyzeUrl, splitDomain, officialFor, USER_CONTENT_HOSTS } from '../engine/url.js';
import { mlUrlScore2, parseUrl, refang, trancoRank, isPlatform, model2Info } from '../engine/urlml2.js';
import { findInstitutions } from '../engine/extract.js';
import { matchForm } from '../engine/normalize.js';
import { fetchBytes } from './netguard.js';
import { rdapDomain } from './forensics.js';
import { feedHit, feedsInfo } from './feeds.js';
import dns from 'node:dns';
import { INSTITUTIONS } from '../data/institutions.js';
import HOSTING from '../data/hosting-providers.js';

// Registries that only real public bodies can use. gob/gouv/govt/mil country zones and Brazil's jus.br were added on
// 24 Nov: no phishing in the dated history before 4 Oct or in the validation split; edu.xx and ac.xx were NOT added
// because hacked university sites do host phishing (10 and 2 cases in that history).
const RESTRICTED = /(^|\.)(gov|mil|ac|sch)\.ae$|(^|\.)(gov|mil|edu)$|(^|\.)(gov|gob|gouv|govt|mil)\.[a-z]{2}$|(^|\.)jus\.br$|(^|\.)(gc\.ca|gouv\.fr|gov\.uk|nhs\.uk|europa\.eu|un\.org|who\.int)$/;
const sig = (id, w, en, ar) => ({ id, w, en, ar });
const logit = p => Math.log(Math.max(1e-6, p) / Math.max(1e-6, 1 - p));
const sigmoid = z => 1 / (1 + Math.exp(-z));
export const THRESHOLDS = { phishing: 0.5, suspicious: 0.3 };
// Offline floor for a short link with a code: 0.3 = suspicious (the default). The validation split has 21 short links
// with a code, all phishing, and no legitimate short link with a code, so the false-alarm cost of a phishing floor is
// unmeasured. Set VETO_SHORT_LINK_FLOOR=0.5 to report them as phishing. The online check follows the link and judges the destination.
const SHORT_LINK_FLOOR = Number(process.env.VETO_SHORT_LINK_FLOOR || 0.3);
const GENERIC_TOKENS = new Set(['centralbank', 'police', 'emirates', 'finance', 'post', 'customs', 'courts', 'tax', 'bank', 'gov']);

// Public file buckets: anyone can create one, so a bad file often sits on a respectable storage domain.
// Evidence is the bucket name, the path and the query: well-known names, lure words, and a victim's e-mail
// address inside the link (phishing kits pre-fill the victim's login from it). Storage hosts only.
const STORAGE_HOST = /(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com$|(^|\.)backblazeb2\.com$|(^|\.)blob\.core\.windows\.net$|(^|\.)storage\.googleapis\.com$|(^|\.)r2\.dev$|(^|\.)digitaloceanspaces\.com$/;
const LURE = new Set(['review', 'waybill', 'invoice', 'payment', 'verify', 'verification', 'secure', 'login', 'signin', 'statement', 'voicemail', 'shared', 'document', 'documents', 'doc', 'docs', 'receipt', 'delivery', 'shipment', 'unlock', 'update']);
const STORAGE_BRAND = new Set(['hotmail', 'outlook', 'office', 'onedrive', 'sharepoint', 'docusign', 'adobe', 'dropbox', 'gmail', 'yahoo', 'paypal', 'dhl', 'fedex', 'ups', 'aramex', 'microsoft', 'google', 'apple', 'icloud', 'netflix', 'whatsapp', 'binance']);
let BRANDS = null;
function storageBrands() {
  if (!BRANDS) BRANDS = new Set([...STORAGE_BRAND, ...INSTITUTIONS.filter(i => !i.generic).flatMap(i => [...i.tokens, ...i.domains.map(d => d.split('.')[0])]).map(t => t.toLowerCase()).filter(t => /^[a-z]{4,}$/.test(t) && !GENERIC_TOKENS.has(t))]);
  return BRANDS;
}
const EMAIL = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;
function hasVictimEmail(u) {
  let s = `${u.search}${u.hash}`;
  for (let k = 0; k < 2; k++) { try { s = decodeURIComponent(s); } catch { break; } }
  if (EMAIL.test(s)) return true;
  for (const t of s.match(/[A-Za-z0-9+/_-]{12,}={0,2}/g) || []) {
    if (EMAIL.test(Buffer.from(t, 'base64').toString('utf8')) || EMAIL.test(Buffer.from(t, 'base64url').toString('utf8'))) return true;
  }
  return false;
}
function storageEvidence(u, host) {
  if (!STORAGE_HOST.test(host)) return { q: 0, kind: null, reasons: [] };
  const words = `${host} ${u.pathname} ${u.search} ${u.hash}`.toLowerCase().match(/[a-z]+/g) || [];
  const brands = [...new Set(words.filter(w => storageBrands().has(w)))];
  const lures = [...new Set(words.filter(w => LURE.has(w)))];
  const list = a => a.slice(0, 3).join(', ');
  let q = 0, kind = null, en = '', ar = '';
  if (hasVictimEmail(u)) {
    q = 0.9; kind = 'victim_email';
    en = "The link carries an e-mail address. Phishing kits use one to pre-fill the victim's login, and this file sits on a public storage bucket.";
    ar = 'الرابط يحمل عنوان بريد إلكتروني، وصفحات التصيّد تستعمله لملء بيانات دخول الضحية تلقائياً، والملف على حاوية تخزين عامة.';
  } else if (brands.length && lures.length) {
    q = 0.85; kind = 'brand_lure';
    en = `A public storage bucket (anyone can create one) combines a well-known name (${list(brands)}) with lure words (${list(lures)}).`;
    ar = `حاوية تخزين عامة (يمكن لأي شخص إنشاؤها) تجمع اسماً مشهوراً (${list(brands)}) مع كلمات إغراء (${list(lures)}).`;
  } else if (lures.length >= 2) {
    q = 0.4; kind = 'lures';
    en = `A public storage bucket whose name or path uses several lure words (${list(lures)}).`;
    ar = `حاوية تخزين عامة يستعمل اسمها أو مسارها عدة كلمات إغراء (${list(lures)}).`;
  } else if (brands.length) {
    q = 0.35; kind = 'brand';
    en = `A public storage bucket whose name or path contains a well-known name (${list(brands)}).`;
    ar = `حاوية تخزين عامة يظهر في اسمها أو مسارها اسم خدمة مشهورة (${list(brands)}).`;
  }
  return { q, kind, reasons: q ? [sig('storage', q, en, ar)] : [] };
}

/** Offline verdict for one URL (no network). */
export function judgeOffline(input, depth = 0) {
  const t0 = performance.now();
  const url = String(input || '').trim();
  const u = parseUrl(url);
  if (!u || !u.hostname || !u.hostname.includes('.')) return finish({ url, verdict: 'invalid', score: null, reasons: [sig('invalid', 0, 'Not a web address.', 'ليس عنواناً على الويب.')] }, t0);
  const host = u.hostname.toLowerCase().replace(/^www\d?\./, '');
  const reg = splitDomain(host).registrable;
  const off = USER_CONTENT_HOSTS.some(p => host === p || host.endsWith('.' + p)) ? null : officialFor(reg); // Google Sites etc. are anyone's pages
  const hop = (off || RESTRICTED.test(host)) && depth < 2 ? embeddedHop(u, host, reg, depth, t0) : null;
  if (hop) return hop;
  if (off) return finish({ url, host, verdict: 'legitimate', score: 0.01, reasons: [sig('official', 0, `Official ${off.name.en} website (${reg}).`, `موقع رسمي لـ${off.name.ar} (${reg}).`)], layers: { official: off.id } }, t0);
  if (RESTRICTED.test(host)) return finish({ url, host, verdict: 'legitimate', score: 0.03, reasons: [sig('restricted', 0, `A government or academic domain (${host.split('.').slice(-2).join('.')}): only real institutions can register these.`, 'نطاق حكومي أو أكاديمي: لا يسجّله إلا جهات حقيقية.')], layers: { restricted: true } }, t0);

  const a = analyzeUrl(u.href);
  const m = mlUrlScore2(u.href);
  const rank = trancoRank(reg);
  // A short link with a code (bit.ly/AbC12) hides its destination. Offline the judge cannot see where it leads, and
  // the shortener's own popularity says nothing about that destination, so it gets no popularity discount.
  const shortCode = a.shortener && (u.pathname.replace(/\/+$/, '').length > 1 || u.search.length > 1);
  // A subdomain on a popular domain that hands out subdomains to anyone (data/hosting-providers.js) is someone's
  // site, not the provider's: the provider's popularity does not vouch for it.
  const userSite = !!HOSTING[reg] && host !== reg && !STORAGE_HOST.test(host); // buckets have their own layer below
  const platform = isPlatform(host, reg) || shortCode || userSite;
  const reasons = [];
  // model, re-centred so that its validated threshold (false alarms <= 1 %) sits at 0.5
  const T = m?.threshold || 0.5;
  const s = m ? sigmoid(logit(m.p) - logit(T)) : 0;
  if (m && m.p >= T * 0.8) reasons.push(sig('ml_url2', s, `The URL model rates this address ${Math.round(m.p * 100)}% phishing-like${m.why.length ? ': ' + m.why.map(x => x.en).join(', ') : ''}.`,
    `نموذج الروابط يقدّر هذا العنوان احتيالياً بنسبة ${Math.round(m.p * 100)}%${m.why.length ? ': ' + m.why.map(x => x.ar).join('، ') : ''}.`));
  // rulebook signals: the strong ones count on their own, weak ones only next to a model that already leans phishing
  let r = 0;
  // brand words that are also ordinary words abroad ("centralbank.cy" is Cyprus's real central bank) only count as
  // impersonation when the model also leans phishing
  const genericBrand = a.brand && GENERIC_TOKENS.has(a.brand.token);
  for (const x of a.signals) {
    if (x.id === 'ml_url') continue; // the v1 name model is superseded here
    if (x.id === 'shortener' && shortCode) continue; // handled below, with its own floor
    // A brand name or near-miss in a domain that is itself among the 100,000 most visited sites (google.com.lb,
    // microsoftedgeinsider.com) is almost always the brand's own or a well-known site: it counts only next to the model.
    // Google's own country domains (google.com.lb, google.iq) are registered by Google itself.
    const popularOwnName = ((rank && rank <= 100000 && !platform) || /^google\.(com?\.)?[a-z]{2}$/.test(reg)) && ['brand_in_domain', 'lookalike_domain'].includes(x.id);
    const strong = (x.w >= 0.8 || ['lookalike', 'punycode_lookalike', 'at_trick', 'radar'].includes(x.id)) && !(x.id === 'brand_in_domain' && genericBrand) && !popularOwnName;
    if (!strong && s < 0.35) continue;
    r = 1 - (1 - r) * (1 - x.w * (strong ? 1 : 0.6));
    reasons.push(x);
  }
  // popularity guard: a top site that is not a hosting platform needs much stronger evidence
  let damp = 1;
  if (rank && rank <= 10000 && !platform) damp = 0.25;
  else if (rank && rank <= 100000 && !platform) damp = 0.6;
  if (damp < 1) reasons.push(sig('popular', 0, `Among the ${rank <= 10000 ? '10,000' : '100,000'} most visited sites in the world (Tranco rank ${rank.toLocaleString('en')}).`, `من أكثر المواقع زيارة في العالم (ترتيب Tranco ${rank}).`));
  const st = storageEvidence(u, host);
  reasons.push(...st.reasons);
  const raw = 1 - (1 - s * damp) * (1 - r * damp) * (1 - st.q);
  // A file on a public bucket is judged on its content: without a victim e-mail or a famous name with lure words,
  // the host alone cannot make it phishing (the model reads many bucket hostnames as phishing-like).
  const bucketCap = STORAGE_HOST.test(host) && st.kind !== 'victim_email' && st.kind !== 'brand_lure';
  if (bucketCap && raw >= THRESHOLDS.phishing) reasons.push(sig('storage_cap', 0, 'The address alone does not make a file on a public bucket phishing: no victim e-mail and no famous name with lure words was found in it.', 'عنوان الحاوية وحده لا يجعل الملف احتيالياً: لم يُعثر فيه على بريد ضحية، ولا على اسم مشهور مع كلمات إغراء.'));
  let score = bucketCap ? Math.min(raw, 0.49) : raw;
  if (shortCode) {
    score = Math.max(score, SHORT_LINK_FLOOR);
    reasons.push(sig('short_link', SHORT_LINK_FLOOR, `A short link (${reg}) hides the real address, and scammers use short links to slip past filters. Offline, the judge cannot see where it leads, so it is treated as at least suspicious until the online check expands it.`,
      `الرابط المختصر (${reg}) يخفي العنوان الحقيقي، ويستخدمه المحتالون لتجاوز أدوات الحماية. لا يمكن معرفة وجهته دون اتصال، لذا يُعامل كرابط مشبوه على الأقل حتى يكشف الفحص المباشر وجهته.`));
  }
  return finish({ url, host, reg, verdict: score >= THRESHOLDS.phishing ? 'phishing' : score >= THRESHOLDS.suspicious ? 'suspicious' : 'legitimate', score: +score.toFixed(4),
    reasons: reasons.sort((x, y) => y.w - x.w).slice(0, 5), layers: { model: m ? m.p : null, rules: +r.toFixed(3), rank: rank || null, platform, storage: st.kind } }, t0);
}

// Open redirects on trusted sites: a link such as google.com/url?q=<address> or a bank's /redirect?url=<address>
// sends the visitor to the address inside it. Judge that address too; if it is bad, the link is bad.
const EMBEDDED = /https?:\/\/[^\s&"'<>]+/gi;
function embeddedTargets(u) {
  let s = `${u.search}${u.hash}`;
  for (let k = 0; k < 2; k++) { try { s = decodeURIComponent(s); } catch { break; } }
  const found = new Set();
  for (const m of s.matchAll(EMBEDDED)) { const t = m[0].replace(/[),.;]+$/, ''); if (t.length > 12) found.add(t); }
  return [...found].slice(0, 3);
}
function embeddedHop(u, host, reg, depth, t0) {
  const judged = embeddedTargets(u).map(t => judgeOffline(t, depth + 1)).filter(r => r.host);
  if (!judged.length) return null;
  const worst = judged.reduce((a, b) => (b.score > a.score ? b : a));
  if (worst.verdict === 'legitimate' || worst.verdict === 'invalid') return null;
  const en = worst.verdict === 'phishing' ? 'phishing' : 'suspicious';
  const ar = worst.verdict === 'phishing' ? 'احتيالي' : 'مشبوه';
  return finish({ url: u.href, host, reg, verdict: worst.verdict, score: worst.score,
    reasons: [sig('redirect', worst.score, `This link is on ${host} but passes you on to ${worst.host}, which is judged ${en}.`,
      `هذا الرابط على ${host} لكنه يحوّلك إلى ${worst.host}، ويُقيَّم بأنه ${ar}.`), ...(worst.reasons || [])].slice(0, 5),
    layers: { redirect_to: worst.host, inner: worst.layers } }, t0);
}

function finish(res, t0) { res.ms = +(performance.now() - t0).toFixed(2); return res; }

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
