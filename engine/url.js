// Link forensics that run instantly on the device (no network): who a link really
// belongs to, whether it imitates a UAE institution, and what tricks it uses.

import { mlUrlScore } from './urlml.js';
import { INSTITUTIONS, NEUTRAL_DOMAINS } from '../data/institutions.js';
import RADAR from '../data/radar.js';
import { foldConfusables, scriptsOf } from './normalize.js';

// Veto Radar: domains that imitated a UAE institution in Certificate Transparency logs.
const RADAR_MAP = new Map((RADAR.domains || []).map(d => [d.registrable, d])); // only the strict, shipped list

// ---------- suffixes ----------
const MULTI_SUFFIX = new Set([
  'gov.ae', 'ac.ae', 'co.ae', 'net.ae', 'org.ae', 'sch.ae', 'mil.ae', 'pro.ae', 'name.ae',
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'co.in', 'net.in', 'org.in', 'com.sa', 'gov.sa', 'net.sa',
  'com.eg', 'com.pk', 'co.za', 'com.ng', 'com.tr', 'com.br', 'com.qa', 'com.kw', 'com.om', 'com.bh', 'co.jp', 'com.cn',
  'com.hk', 'com.sg', 'com.my', 'com.ph', 'co.id', 'com.ru'
]);
// Free / anonymous hosting where anyone can create a sub-domain in seconds.
export const FREE_HOSTING = new Set([
  'github.io', 'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app', 'web.app', 'firebaseapp.com', 'herokuapp.com',
  'blogspot.com', 'wixsite.com', 'weebly.com', '000webhostapp.com', 'glitch.me', 'repl.co', 'replit.app', 'ngrok.io',
  'ngrok-free.app', 'ngrok.app', 'trycloudflare.com', 'azurewebsites.net', 'appspot.com', 'r2.dev', 'onrender.com',
  'fly.dev', 'surge.sh', 'duckdns.org', 'webflow.io', 'framer.website', 'godaddysites.com', 'square.site', 'carrd.co',
  'mystrikingly.com', 's3.amazonaws.com', 'cloudfront.net', 'web.core.windows.net', 'firebasestorage.app', 'pythonanywhere.com', 'teachable.com',
  'azurestaticapps.net', 'railway.app', 'deno.dev', 'gitlab.io', 'bubbleapps.io', 'glide.page', 'lovable.app', 'replit.dev', 'wixstudio.io',
  'framer.app', 'hosted.app', 'run.app'
]);
// Platforms whose URLs carry a region label: <app>.<region>.hosted.app, the region is part of the suffix.
const WILDCARD_HOSTING = ['hosted.app', 'run.app'];
const SHORTENERS = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly', 'rb.gy', 't.ly', 'shorturl.at', 'tiny.cc',
  'rebrand.ly', 's.id', 'v.gd', 'bit.do', 'qrco.de', 'shorte.st', 'adf.ly', 'lnkd.in', 'buff.ly', 'tiny.one', 'short.gy',
  'urlz.fr', 'u.to', 'clck.ru', 'l.ead.me', 'shorturl.asia', 'surl.li', 'gg.gg', 'linktr.ee', 'tr.ee', 'msha.ke', 'qr.link'
]);
const IP_LOGGERS = new Set(['iplogger.org', 'iplogger.com', 'grabify.link', '2no.co', 'yip.su', 'blasze.com']);
const HIGH_RISK_TLDS = new Set(['top', 'xyz', 'icu', 'cyou', 'sbs', 'cfd', 'bond', 'click', 'buzz', 'rest', 'monster', 'quest', 'tk', 'ml', 'ga', 'cf', 'gq',
  'pw', 'su', 'gdn', 'cam', 'win', 'bid', 'loan', 'men', 'date', 'racing', 'review', 'stream', 'download', 'uno', 'lat', 'autos', 'boats',
  'hair', 'beauty', 'makeup', 'skin', 'homes', 'yachts', 'motorcycles', 'mom', 'lol', 'zip', 'mov']);
const MED_RISK_TLDS = new Set(['info', 'live', 'shop', 'online', 'site', 'store', 'fun', 'space', 'website', 'vip', 'work', 'support', 'club',
  'life', 'today', 'world', 'link', 'cc', 'best', 'ink', 'asia', 'digital', 'services', 'center', 'tech', 'pro', 'biz', 'cloud', 'help', 'one', 'cn', 'ru']);
const KNOWN_GTLDS = new Set(['com', 'net', 'org', 'gov', 'edu', 'mil', 'int', 'info', 'biz', 'io', 'co', 'ai', 'app', 'dev', 'me', 'tv', 'mobi',
  'name', 'asia', 'travel', 'aero', 'jobs', 'abudhabi', 'dubai', 'arab', 'news', 'media', 'blog', 'art', 'design', 'studio', 'photo', 'pics',
  'games', 'video', 'one', 'plus', 'run', 'zone', 'social', 'team', 'tools', 'host', 'hosting', 'press', 'wiki', 'chat', 'help', 'mail', 'ltd',
  'inc', 'llc', 'page', 'global', 'group', 'email', 'network', 'systems', 'solutions', 'agency', 'company', 'business', 'finance', 'financial',
  'money', 'bank', 'insure', 'cash', 'capital', 'fund', 'exchange', 'market', 'trading', 'gold', 'delivery', 'express', 'localhost',
  ...HIGH_RISK_TLDS, ...MED_RISK_TLDS]);
const DOWNLOAD_EXT = /\.(apk|xapk|apks|exe|msi|scr|bat|cmd|com|jar|dmg|pkg|ipa|vbs|ps1|hta|lnk|iso|img)(?:$|[?#])/i;
const ARCHIVE_EXT = /\.(zip|rar|7z|gz)(?:$|[?#])/i;
const SENSITIVE = /(log-?in|sign-?in|verif|update|secure|security|account|kyc|unlock|unblock|suspend|confirm|billing|refund|claim|prize|reward|fines?\b|payment|\bpay|otp|wallet|auth|validat|recover|reactivat|customs|parcel|deliver|track|invoice|bank|ebank|support|helpdesk|gift|bonus|card|emirates-?id|\beid\b)/i;
const AFFIXES = new Set(['secure', 'security', 'login', 'signin', 'verify', 'verification', 'update', 'online', 'support', 'service', 'services',
  'help', 'care', 'pay', 'payment', 'payments', 'bank', 'banking', 'uae', 'ae', 'dubai', 'abudhabi', 'auth', 'account', 'accounts', 'alert',
  'alerts', 'kyc', 'id', 'app', 'apps', 'mobile', 'portal', 'gov', 'official', 'refund', 'reward', 'rewards', 'gift', 'gifts', 'points', 'track',
  'tracking', 'delivery', 'post', 'parcel', 'fine', 'fines', 'customs', 'web', 'my', 'e', 'i', 'm', 'net', '24', '247', 'center', 'centre',
  'desk', 'team', 'info', 'pass', 'cards', 'card', 'check', 'confirm', 'unlock', 'block', 'new', 'now', 'go', 'get', 'claim', 'offer', 'offers', 'promo']);

// ---------- brand index ----------
const OFFICIAL = new Map();   // registrable domain -> institution
const BRANDS = [];            // { token, inst }
const OFFICIAL_SLDS = [];     // { sld, inst }
const STOP_TOKENS = new Set(['live', 'outlook', 'post', 'pay', 'one', 'go', 'my', 'id', 'web', 'app']);
for (const inst of INSTITUTIONS) {
  for (const d of inst.domains) {
    OFFICIAL.set(d, inst);
    const { sld } = splitDomain(d);
    if (sld && sld.length >= 3 && !STOP_TOKENS.has(sld)) OFFICIAL_SLDS.push({ sld, inst });
  }
  const toks = new Set([...(inst.tokens || []), ...OFFICIAL_SLDS.filter(o => o.inst === inst).map(o => o.sld)]);
  for (const t of toks) if (t && t.length >= 2 && !STOP_TOKENS.has(t)) BRANDS.push({ token: t.toLowerCase(), inst });
}

export const USER_CONTENT_HOSTS = ['sites.google.com', 'docs.google.com', 'drive.google.com', 'forms.gle', 'storage.googleapis.com', 'firebasestorage.googleapis.com',
  'script.google.com', 'googleusercontent.com', 'blogger.com', 'feedproxy.google.com', 'onedrive.live.com', '1drv.ms', 'sharepoint.com', 'forms.office.com', 'forms.microsoft.com',
  'dropbox.com', 'dropboxusercontent.com', 'notion.site', 'canva.site', 'my.canva.site', 'telegra.ph', 'linktr.ee', 'wordpress.com'];
export function officialFor(registrable) {
  return OFFICIAL.get(registrable) || null;
}

const CC_SECOND = new Set(['com', 'co', 'net', 'org', 'gov', 'gob', 'gouv', 'govt', 'edu', 'ac', 'mil']);
export function splitDomain(host) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  const labels = h.split('.');
  if (labels.length < 2) return { registrable: h, suffix: '', sld: h, sub: '' };
  let suffixLen = 1;
  for (const s of [...MULTI_SUFFIX, ...FREE_HOSTING]) {
    const n = s.split('.').length;
    if (n >= 2 && labels.length > n && labels.slice(-n).join('.') === s) suffixLen = Math.max(suffixLen, n);
  }
  for (const w of WILDCARD_HOSTING) {
    const n = w.split('.').length + 1;
    if (labels.length > n && labels.slice(-(n - 1)).join('.') === w) suffixLen = Math.max(suffixLen, n);
  }
  // Most country zones sell names one level below a generic label (example.com.lb, example.org.nz, example.co.kr).
  // The hand list above misses many of them, which made "com.lb" look like the site itself.
  if (suffixLen === 1 && labels.length >= 3 && /^[a-z]{2}$/.test(labels[labels.length - 1]) && CC_SECOND.has(labels[labels.length - 2])) suffixLen = 2;
  const suffix = labels.slice(-suffixLen).join('.');
  const sld = labels[labels.length - suffixLen - 1] || '';
  const registrable = labels.slice(-suffixLen - 1).join('.');
  const sub = labels.slice(0, -suffixLen - 1).join('.');
  return { registrable, suffix, sld, sub };
}

// ---------- punycode (RFC 3492) ----------
function adapt(delta, numPoints, firstTime) {
  let k = 0;
  delta = firstTime ? Math.floor(delta / 700) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  for (; delta > 455; k += 36) delta = Math.floor(delta / 35);
  return Math.floor(k + (36 * delta) / (delta + 38));
}
export function punyDecode(input) {
  const out = [];
  let i = 0, n = 128, bias = 72;
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; ++j) out.push(input.charCodeAt(j));
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const oldi = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (idx >= input.length) throw new Error('bad punycode');
      const c = input.charCodeAt(idx++);
      const digit = c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : 36;
      if (digit >= 36) throw new Error('bad punycode');
      i += digit * w;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      w *= 36 - t;
    }
    const len = out.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}
export function toUnicodeHost(host) {
  return host.split('.').map(l => {
    if (!l.startsWith('xn--')) return l;
    try { return punyDecode(l.slice(4)); } catch { return l; }
  }).join('.');
}

// ---------- string distance ----------
export function editDistance(a, b, max = 3) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      rowMin = Math.min(rowMin, d[i][j]);
    }
    if (rowMin > max) return max + 1;
  }
  return d[a.length][b.length];
}
const LEET = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i', '|': 'l' };
export const foldLook = s => foldConfusables(String(s).toLowerCase())
  .replace(/[0134578@$!|]/g, c => LEET[c] ?? c).replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/-/g, '');

// ---------- extraction ----------
const SCHEME_URL = /\b(?:https?|ftp):\/\/[^\s<>"'«»]+/gi;
const WWW_URL = /\bwww\.[^\s<>"'«»]+/gi;
const BARE_URL = /(?<![@\w.\-\/])(?:[a-z0-9¡-￿](?:[a-z0-9¡-￿\-]{0,61}[a-z0-9¡-￿])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9\-]{2,59})(?::\d{2,5})?(?:\/[^\s<>"'«»]*)?/gi;
const BARE_IP = /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\/[^\s<>"'«»]*/g;
const EMAIL = /[a-z0-9._%+\-]+@((?:[a-z0-9¡-￿\-]+\.)+[a-z]{2,24})/gi;
const SPECIAL_SCHEME = /\b(?:javascript|data|vbscript):[^\s]+/gi;

function trimUrl(u) {
  return u.replace(/[),.;:!?'"»\]}>،؟]+$/u, '');
}

export function extractLinks(text) {
  const found = [];
  const taken = [];
  const overlaps = (s, e) => taken.some(([a, b]) => s < b && e > a);
  const push = (raw, index, kind) => {
    const t = trimUrl(raw);
    if (!t || overlaps(index, index + t.length)) return;
    taken.push([index, index + t.length]);
    found.push({ raw: t, index, kind });
  };
  for (const re of [SCHEME_URL, SPECIAL_SCHEME, WWW_URL, BARE_IP]) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) push(m[0], m.index, 'url');
  }
  BARE_URL.lastIndex = 0;
  for (const m of text.matchAll(BARE_URL)) {
    const t = trimUrl(m[0]);
    const host = t.split(/[\/:?#]/)[0];
    const tld = host.split('.').pop().toLowerCase();
    if (!(tld.length === 2 || KNOWN_GTLDS.has(tld) || tld.startsWith('xn--'))) continue;
    if (/^\d+(\.\d+)+$/.test(host)) continue;
    push(m[0], m.index, 'url');
  }
  const emails = [];
  EMAIL.lastIndex = 0;
  for (const m of text.matchAll(EMAIL)) emails.push({ raw: m[0], domain: m[1].toLowerCase(), index: m.index });
  return { links: found.sort((a, b) => a.index - b.index), emails };
}

// ---------- analysis ----------
const sig = (id, w, en, ar, extra = {}) => ({ id, w, en, ar, ...extra });

export function brandMatch(hostLabels) {
  // hostLabels: array of label parts (split on '.' and '-')
  for (const { token, inst } of BRANDS) {
    for (const part of hostLabels) {
      if (!part) continue;
      if (part === token) return { inst, token, strength: token.length >= 5 ? 'strong' : 'weak' };
      if (token.length >= 8 && part.includes(token)) return { inst, token, strength: 'strong' };
      if (token.length >= 5 && (part.startsWith(token) || part.endsWith(token))) {
        const rest = part.startsWith(token) ? part.slice(token.length) : part.slice(0, part.length - token.length);
        if (AFFIXES.has(rest) || /^\d+$/.test(rest)) return { inst, token, strength: 'strong' };
      }
    }
  }
  return null;
}

function lookalike(sld, hostUnicode) {
  const raw = sld.toLowerCase();
  const folded = foldLook(raw);
  for (const { sld: o, inst } of OFFICIAL_SLDS) {
    if (o.length < 4) continue;
    const fo = foldLook(o);
    if (raw === o) continue;
    if (folded === fo) return { inst, kind: /[^\x00-\x7f]/.test(hostUnicode) ? 'homoglyph' : 'typo', target: o };
    const max = o.length >= 9 ? 2 : o.length >= 5 ? 1 : 0;
    if (max && editDistance(folded, fo, max) <= max) return { inst, kind: 'typo', target: o };
  }
  return null;
}

export function analyzeUrl(raw) {
  const out = { raw, href: raw, host: '', hostUnicode: '', registrable: '', sld: '', tld: '', scheme: '', port: '', path: '',
    official: null, lookalike: null, brand: null, neutral: false, shortener: false, freeHosting: false, signals: [], risk: 0 };
  if (/^(?:javascript|data|vbscript):/i.test(raw)) {
    out.scheme = raw.split(':')[0].toLowerCase();
    out.signals.push(sig('script_scheme', 0.9, 'This is not a web address. It runs code when opened.', 'هذا ليس عنوان موقع، بل كود يعمل عند فتحه.'));
    out.risk = 0.9;
    return out;
  }
  let u;
  const schemeGiven = /^[a-z][a-z0-9+.\-]*:\/\//i.test(raw);
  out.schemeGiven = schemeGiven;
  try {
    u = new URL(schemeGiven ? raw : 'http://' + raw);
  } catch {
    out.signals.push(sig('unparseable', 0.3, 'The link is malformed, a common trick to slip past filters.', 'الرابط مشوّه، حيلة شائعة لتجاوز الفلاتر.'));
    out.risk = 0.3;
    return out;
  }
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  out.href = u.href;
  out.host = host;
  out.hostUnicode = toUnicodeHost(host);
  out.scheme = u.protocol.replace(':', '');
  out.port = u.port;
  out.path = u.pathname + u.search;
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
  const { registrable, sld, suffix, sub } = splitDomain(host);
  out.registrable = registrable;
  out.sld = sld;
  out.tld = host.split('.').pop();
  // pages that ANYONE can publish on a big brand's domain (Google Sites, Docs, Forms, Firebase storage …) are not that
  // brand speaking: they are never "official"
  out.userContent = USER_CONTENT_HOSTS.some(p => host === p || host.endsWith('.' + p));
  out.official = out.userContent ? null : officialFor(registrable);
  out.neutral = !out.userContent && (NEUTRAL_DOMAINS.includes(registrable) || NEUTRAL_DOMAINS.includes(host));
  out.shortener = SHORTENERS.has(registrable) || SHORTENERS.has(host);
  out.freeHosting = FREE_HOSTING.has(suffix) || WILDCARD_HOSTING.some(w => suffix.endsWith('.' + w));
  const S = out.signals;

  if (u.username || u.password) {
    S.push(sig('userinfo_trick', 0.88, `The address hides its real destination after an “@”. It actually opens ${host}.`, `يخفي الرابط وجهته الحقيقية بعد علامة «@»، وهو يفتح فعلياً ${host}.`));
  }
  if (isIp) S.push(sig('ip_host', 0.75, 'The link uses a raw IP address instead of a name, real banks and government sites never do this.', 'الرابط يستخدم عنوان IP بدلاً من اسم موقع، البنوك والجهات الحكومية لا تفعل ذلك.'));
  const radar = !out.official && RADAR_MAP.get(registrable);
  if (radar) {
    out.radar = radar;
    S.push(sig('radar_hit', 0.6, `Veto Radar saw this domain get a security certificate on ${radar.firstSeen} while using ${radar.brand}'s name (unverified lead).`,
      `رصد «رادار فيتو» حصول هذا النطاق على شهادة أمان في ${radar.firstSeen} وهو يستخدم اسم ${radar.brandAr || radar.brand} (مؤشر غير مؤكد).`));
  }
  if (IP_LOGGERS.has(registrable)) S.push(sig('ip_logger', 0.85, 'This is an IP-logger link: opening it reveals your location and device to the sender.', 'هذا رابط لتسجيل عنوان IP: فتحه يكشف موقعك وجهازك للمرسل.'));

  if (!out.official && !isIp) {
    const mixed = out.hostUnicode !== host && out.hostUnicode.split('.').some(l => {
      const sc = scriptsOf(l);
      return sc.length > 1 || (sc.length === 1 && sc[0] !== 'latin' && sc[0] !== 'arabic');
    });
    const sldUnicode = toUnicodeHost(sld);
    const look = lookalike(sldUnicode, sldUnicode);
    if (look) {
      out.lookalike = look;
      const how = look.kind === 'homoglyph' ? 'swaps letters for look-alike characters from another alphabet' : 'is one or two letters away from the real name';
      const howAr = look.kind === 'homoglyph' ? 'يستبدل حروفاً بحروف متشابهة من أبجدية أخرى' : 'يختلف بحرف أو حرفين عن الاسم الحقيقي';
      S.push(sig('lookalike_domain', 0.93,
        `“${out.hostUnicode}” imitates ${look.inst.name.en} (${look.inst.domains[0]}). It ${how}.`,
        `«${out.hostUnicode}» يقلّد ${look.inst.name.ar} (${look.inst.domains[0]})، فهو ${howAr}.`, { inst: look.inst.id }));
    } else if (mixed) {
      S.push(sig('mixed_script_host', 0.85, `The address mixes letters from different alphabets (${out.hostUnicode}), a classic disguise.`, `العنوان يخلط حروفاً من أبجديات مختلفة (${out.hostUnicode})، تمويه معروف.`));
    }
    if (!look) {
      const parts = [...sub.split(/[.\-_]/), ...sld.split(/[\-_]/), sld];
      const b = brandMatch(parts.filter(Boolean));
      if (b && !(out.neutral && b.inst.type === 'platform')) {
        out.brand = b;
        const w = b.strength === 'strong' ? 0.87 : (SENSITIVE.test(host + out.path) ? 0.75 : 0.5);
        S.push(sig('brand_in_domain', w,
          `Uses the name “${b.token}” but ${registrable} is not an official ${b.inst.name.en} website.`,
          `يستخدم اسم «${b.token}» لكن ${registrable} ليس موقعاً رسمياً لـ${b.inst.name.ar}.`, { inst: b.inst.id }));
      }
    }
  }

  // Unknown short redirect links: a tiny domain + one short random-looking path segment (e.g. x.vc/aB3dZ).
  if (!out.shortener && !out.official && !out.neutral && sld.length <= 5 && /^\/[A-Za-z0-9_-]{3,12}\/?$/.test(u.pathname) &&
    /\d|[A-Z]/.test(u.pathname) && !u.search) {
    S.push(sig('redirector', 0.3, `Looks like a short redirect link (${registrable}). It hides where it really goes. Use X-ray to reveal it.`,
      `يبدو رابط تحويل مختصراً (${registrable}) يخفي وجهته الحقيقية. استخدم الأشعة لكشفها.`));
  }
  if (out.shortener) S.push(sig('shortener', 0.35, `Shortened link (${registrable}). It hides where it really goes. Use X-ray to reveal it.`, `رابط مختصر (${registrable}) يخفي وجهته الحقيقية. استخدم الأشعة لكشفها.`));
  if (out.freeHosting) S.push(sig('free_hosting', 0.55, `Hosted on a free website builder (${suffix}), anyone can create one in minutes. Real institutions use their own domain.`, `مستضاف على منصة مواقع مجانية (${suffix})، يمكن لأي شخص إنشاؤه في دقائق. الجهات الرسمية تستخدم نطاقها الخاص.`));
  if (!out.official && HIGH_RISK_TLDS.has(out.tld)) S.push(sig('risky_tld', 0.4, `Ends in “.${out.tld}”, a cheap domain ending heavily used in scam campaigns.`, `ينتهي بـ«.${out.tld}»، وهو امتداد رخيص يكثر استخدامه في الاحتيال.`));
  else if (!out.official && MED_RISK_TLDS.has(out.tld)) S.push(sig('odd_tld', 0.2, `Ends in “.${out.tld}”, unusual for banks or government in the UAE.`, `ينتهي بـ«.${out.tld}»، غير معتاد للبنوك والجهات الحكومية في الإمارات.`));
  if (DOWNLOAD_EXT.test(u.pathname)) {
    const ext = (u.pathname.match(DOWNLOAD_EXT) || [])[1];
    S.push(sig('download_file', 0.82, `The link downloads an app or program (.${ext}) directly. This is how banking malware gets installed. Only install apps from the official store.`, `الرابط ينزّل تطبيقاً أو برنامجاً (.${ext}) مباشرة، هكذا تُثبَّت برمجيات سرقة الحسابات. ثبّت التطبيقات من المتجر الرسمي فقط.`));
  } else if (ARCHIVE_EXT.test(u.pathname)) {
    S.push(sig('archive_file', 0.4, 'The link downloads a compressed file. It may contain malware.', 'الرابط ينزّل ملفاً مضغوطاً قد يحتوي على برمجية خبيثة.'));
  }
  if (u.port && !['80', '443'].includes(u.port)) S.push(sig('odd_port', 0.3, `Uses an unusual port (:${u.port}), real public sites almost never do.`, `يستخدم منفذاً غير معتاد (:${u.port}).`));
  if (schemeGiven && out.scheme === 'http' && SENSITIVE.test(host + out.path)) S.push(sig('no_tls', 0.3, 'Asks for sensitive actions over an unencrypted (http) connection.', 'يطلب إجراءات حساسة عبر اتصال غير مشفّر (http).'));
  if (!out.official && sub.split('.').filter(Boolean).length >= 3) S.push(sig('deep_subdomain', 0.2, 'Unusually long chain of sub-domains, used to push the real domain out of view on phones.', 'سلسلة طويلة من النطاقات الفرعية، تُستخدم لإخفاء النطاق الحقيقي على شاشة الهاتف.'));
  if (!out.official && (sld.match(/-/g) || []).length >= 2) S.push(sig('many_hyphens', 0.15, 'Domain stitched together with hyphens, typical of throw-away scam sites.', 'نطاق مركّب بعدة شرطات، شائع في مواقع الاحتيال المؤقتة.'));
  if (!out.official && !out.neutral && !out.shortener && SENSITIVE.test(host)) S.push(sig('sensitive_words', 0.15, 'The address itself is built around words like “verify”, “update” or “pay”.', 'العنوان نفسه مبني على كلمات مثل «تحقق» أو «تحديث» أو «ادفع».'));
  if (raw.length > 120 && /%[0-9a-f]{2}/i.test(raw)) S.push(sig('obfuscated', 0.15, 'Very long, encoded link, hides what it does.', 'رابط طويل جداً ومشفّر يخفي ما يفعله.'));

  // ML second opinion on the domain NAME (engine/urlml.js, trained on public phishing data). Never for
  // official, big-platform or IP hosts; moderate weights because it overlaps the rules above.
  if (!out.official && !out.neutral && !isIp) {
    const ml = mlUrlScore(host);
    if (ml) {
      out.ml = { p: ml.p, why: ml.why, brand: ml.brand };
      // Brand misuse found by the model (typo, glued, sub-domain) is strong evidence; a name that merely
      // "looks machine-made" is a nudge: alone it stays below the "unsafe link" line.
      let w = ml.p >= 0.9 ? (ml.brand ? 0.6 : 0.4) : ml.p >= 0.8 ? (ml.brand ? 0.45 : 0.25) : 0;
      if (out.freeHosting) w = Math.min(w, ml.brand ? 0.35 : 0.1); // the platform already explains most of it
      if (!S.length && !ml.brand) w = Math.min(w, 0.25);
      if (w) S.push(sig('ml_url', w,
        `Veto's link model rates this address ${Math.round(ml.p * 100)}% likely to be a phishing name${ml.why.length ? ': ' + ml.why.map(x => x.en).join(', ') : ''}.`,
        `يقدّر نموذج فيتو للروابط أن هذا العنوان اسم تصيّد بنسبة ${Math.round(ml.p * 100)}%${ml.why.length ? ': ' + ml.why.map(x => x.ar).join('، ') : ''}.`));
    }
  }

  out.risk = 1 - S.reduce((p, s) => p * (1 - s.w), 1);
  return out;
}

export function analyzeEmailDomain(domain) {
  const a = analyzeUrl('http://' + domain + '/');
  a.isEmail = true;
  return a;
}
