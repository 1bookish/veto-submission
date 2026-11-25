// Turns raw text into structured claims: who it says it is, what it asks for,
// how it pressures, which links / numbers / amounts / codes it contains.

import { matchForm, mixedScriptWords, escapeRe } from './normalize.js';
import { ACTIONS, TACTICS, SAFETY_PHRASES, isNegatedBefore, sentenceStart, sentenceEnd, protectDots } from './lexicon.js';
import { INSTITUTIONS } from '../data/institutions.js';
import { extractLinks, analyzeUrl, analyzeEmailDomain } from './url.js';

const AR = /[؀-ۿ]/;
const mk = a => AR.test(a)
  ? new RegExp(`(?:^|[^\\u0600-\\u06FF])[وفبلك]?${escapeRe(a)}(?![\\u0600-\\u06FF])`, 'u')
  : new RegExp(`(?<![a-z0-9])${escapeRe(a)}(?![a-z0-9])`, 'u');

const INST_MATCHERS = INSTITUTIONS.map(inst => ({
  inst,
  loose: inst.aliases.map(a => matchForm(a)).map(a => ({ a, re: mk(a) })),
  ctx: (inst.ctxAliases || []).map(a => matchForm(a)).map(a => ({ a, re: mk(a) })),
  strict: (inst.strict || []).map(a => ({ a, re: new RegExp(`(?<![A-Za-z0-9&])${escapeRe(a)}(?![A-Za-z0-9&])`, 'u') })),
  context: inst.context ? inst.context.map(c => matchForm(c)) : null
}));

export function findInstitutions(mt, rawText) {
  const out = [];
  for (const m of INST_MATCHERS) {
    let hit = null;
    for (const { a, re } of m.loose) {
      const r = re.exec(mt);
      if (r) { hit = { alias: a, index: r.index }; break; }
    }
    const ctxOk = !m.context || m.context.some(c => mt.includes(c));
    if (!hit && ctxOk) {
      for (const { a, re } of m.strict) {
        const r = re.exec(rawText);
        if (r) { hit = { alias: a, index: r.index, raw: true }; break; }
      }
      if (!hit) for (const { a, re } of m.ctx) {
        const r = re.exec(mt);
        if (r) { hit = { alias: a, index: r.index }; break; }
      }
    }
    if (hit) {
      // "payment of Rs 179 for Amazon", "a purchase at Carrefour": a merchant mention, not a sender claim
      const src = hit.raw ? rawText : mt;
      hit.mention = /\b(?:for|at|on|via|with|to|in)\s+$/i.test(src.slice(Math.max(0, hit.index - 8), hit.index));
      delete hit.raw;
      out.push({ inst: m.inst, ...hit });
    }
  }
  return out.sort((a, b) => (a.inst.generic - b.inst.generic) || (a.mention - b.mention) || (a.index - b.index));
}

const FOLLOW_UP = /(?:\b(?:send|share|give|read|forward|tell|text|whatsapp|type) (?:it|them|that|this|those)\b(?: (?:back )?(?:to|for) (?:me|us)\b)?|(?:^|\s)(?:ارسله|ارسلها|ابعثه|ابعثها|ابعته|ابعتها|اعطني اياه|عطني اياه|قوله لي)(?=$|\s|[,.!?]))/iu;

const snippet = (t, i, len) => {
  let s = Math.max(0, i - 14), e = Math.min(t.length, i + len + 14);
  while (s > 0 && s > i - 30 && !/\s/.test(t[s - 1])) s--;          // start on a word boundary
  while (e < t.length && e < i + len + 34 && !/\s/.test(t[e])) e++; // end on a word boundary
  return (s > 0 ? '…' : '') + t.slice(s, e).replace(/·/g, '.').trim() + (e < t.length ? '…' : '');
};

export function findActions(dt) {
  const hits = [];
  for (const [id, def] of Object.entries(ACTIONS)) {
    let hit = null;
    if (def.direct) {
      def.direct.lastIndex = 0;
      for (const m of dt.matchAll(def.direct)) {
        if (!def.noNegationCheck && isNegatedBefore(dt, m.index)) continue;
        hit = { id, index: m.index, evidence: snippet(dt, m.index, m[0].length), phrase: dt.substr(m.index, m[0].length).trim() };
        break;
      }
    }
    if (!hit && def.objects && def.verbs) {
      def.objects.lastIndex = 0;
      outer: for (const m of dt.matchAll(def.objects)) {
        const s = Math.max(sentenceStart(dt, m.index), m.index - 80);
        const objEnd = m.index + m[0].length;
        const e = Math.min(sentenceEnd(dt, objEnd), objEnd + 50);
        const win = dt.slice(s, e);
        def.verbs.lastIndex = 0;
        for (const v of win.matchAll(def.verbs)) {
          const vIdx = s + v.index;
          const first = Math.min(vIdx, m.index);
          if (isNegatedBefore(dt, vIdx + (/^[\s,.:;!?()"'«»\-]/.test(v[0]) ? 1 : 0)) || isNegatedBefore(dt, first)) continue;
          if (def.except && def.except.test(win)) continue;
          const last = Math.max(vIdx + v[0].length, objEnd);
          hit = { id, index: first, evidence: snippet(dt, first, last - first), phrase: dt.slice(first, last).trim() };
          break outer;
        }
        // "I sent you a code. Can you send it to me?", the request points back with "it".
        const nStart = sentenceEnd(dt, objEnd) + 1;
        if (nStart < dt.length) {
          const next = dt.slice(nStart, Math.min(sentenceEnd(dt, nStart + 1), nStart + 90));
          const f = FOLLOW_UP.exec(next);
          if (f && !isNegatedBefore(dt, nStart + f.index + 1)) {
            hit = { id, index: m.index, evidence: snippet(dt, m.index, nStart + f.index + f[0].length - m.index), phrase: dt.substr(m.index, m[0].length).trim() };
            break outer;
          }
        }
      }
    }
    if (hit) hits.push(hit);
  }
  return hits;
}

export function findTactics(dt) {
  const out = [];
  for (const [id, def] of Object.entries(TACTICS)) {
    def.re.lastIndex = 0;
    const m = def.re.exec(dt);
    if (m) out.push({ id, index: m.index, evidence: snippet(dt, m.index, m[0].length), phrase: dt.substr(m.index, m[0].length).trim() });
  }
  return out;
}

// ---------- numbers ----------
const PHONE_RE = /(?<![\d+])(?:(?:\+|00)\s?\d{1,3}[\s\-]?\(?\d{1,4}\)?(?:[\s\-]?\d{2,4}){1,4}|0\d{1,2}[\s\-]?\d{3}[\s\-]?\d{4}|(?:800|600)[\s\-]?\d{2,3}[\s\-]?\d{2,4})(?![\d])/g;
export function classifyPhone(rawNum) {
  let d = rawNum.replace(/[^\d+]/g, '');
  if (d.startsWith('00')) d = '+' + d.slice(2);
  let kind = 'unknown', national = d;
  if (d.startsWith('+971')) national = '0' + d.slice(4);
  else if (d.startsWith('+')) return { digits: d, kind: 'international', country: d.slice(1, 4) };
  const n = national.replace(/\D/g, '');
  if (/^05\d{8}$/.test(n)) kind = 'uae_mobile';
  else if (/^0[2-46-79]\d{7}$/.test(n)) kind = 'uae_landline';
  else if (/^0?800\d{2,7}$/.test(n)) kind = 'tollfree';
  else if (/^0?600\d{6}$/.test(n)) kind = 'shared_cost';
  return { digits: n.replace(/^0(?=[68]00)/, ''), kind };
}
export function findPhones(text) {
  const out = [];
  PHONE_RE.lastIndex = 0;
  for (const m of text.matchAll(PHONE_RE)) {
    const digits = m[0].replace(/\D/g, '');
    if (digits.length < 7 || digits.length > 15) continue;
    if (/^784\d{12}$/.test(digits)) continue; // Emirates ID
    out.push({ raw: m[0].trim(), index: m.index, ...classifyPhone(m[0]) });
  }
  return out;
}

const AMOUNT_RE = /(?:\b(aed|dhs?|dh|usd|sar|eur|gbp|inr|usdt)\s?|([$€£₹])\s?|(درهم)\s?)(\d[\d,]*(?:\.\d+)?)|(\d[\d,]*(?:\.\d+)?)\s?(aed|dhs?|dirhams?|usd|sar|eur|gbp|inr|usdt|درهم|دراهم)(?![a-z])/gi;
export function findAmounts(text) {
  const out = [];
  AMOUNT_RE.lastIndex = 0;
  for (const m of text.matchAll(AMOUNT_RE)) {
    const num = m[4] || m[5];
    const cur = (m[1] || m[2] || m[3] || m[6] || '').toUpperCase();
    const value = parseFloat(String(num).replace(/,/g, ''));
    if (!isFinite(value)) continue;
    const currency = /DH|AED|درهم|دراهم|DIRHAM/i.test(cur) ? 'AED' : cur === '$' ? 'USD' : cur === '€' ? 'EUR' : cur === '£' ? 'GBP' : cur === '₹' ? 'INR' : cur;
    out.push({ raw: m[0].trim(), value, currency, index: m.index });
  }
  return out;
}

const SENDER_PHONE = /^[\s+()\d\-]{7,}$/;
export function parseSender(sender) {
  const s = String(sender || '').trim();
  if (!s) return null;
  if (SENDER_PHONE.test(s)) return { raw: s, isPhone: true, ...classifyPhone(s) };
  const email = /@([a-z0-9.\-]+\.[a-z]{2,})/i.exec(s);
  if (email) return { raw: s, isEmail: true, domain: email[1].toLowerCase() };
  return { raw: s, isName: true, alnum: /^[A-Za-z0-9\-& ]{2,15}$/.test(s) };
}

export function extractAll(normText, opts = {}) {
  const mt = matchForm(normText);
  const dt = protectDots(mt);
  const { links, emails } = extractLinks(normText);
  const senderInfo = parseSender(opts.sender);
  let institutions = findInstitutions(mt, normText);
  if (senderInfo?.isName) {
    for (const c of findInstitutions(matchForm(senderInfo.raw), senderInfo.raw)) {
      if (!institutions.some(x => x.inst.id === c.inst.id)) institutions.push({ ...c, viaSender: true, index: -1 });
    }
  }
  if (senderInfo?.isEmail) {
    emails.push({ raw: senderInfo.raw, domain: senderInfo.domain, index: -1, fromSender: true });
  }
  return {
    mt, dt,
    institutions,
    actions: findActions(dt),
    tactics: findTactics(dt),
    safety: (SAFETY_PHRASES.lastIndex = 0, SAFETY_PHRASES.test(dt)),
    links: links.map(l => ({ ...l, report: analyzeUrl(l.raw) })),
    emails: emails.map(e => ({ ...e, report: analyzeEmailDomain(e.domain) })),
    phones: findPhones(normText),
    amounts: findAmounts(normText),
    mixedScript: mixedScriptWords(normText),
    sender: senderInfo
  };
}
