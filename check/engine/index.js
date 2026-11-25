// Veto engine, public API.
//   analyze({ text, sender, channel }) -> report        (pure, on-device, no network)
//   rescore(report, extraFindings)    -> report         (adds AI / X-ray findings; can only RAISE risk)
//
// Neuro-symbolic by design: pattern + language layers extract claims; the verdict is decided by
// explicit rules from the institutional rulebook, so every alert is explainable and cites a source.

import { normalizeText, detectLang } from './normalize.js';
import { extractAll } from './extract.js';
import { analyzeOtp } from './otp.js';
import { ACTIONS, TACTICS } from './lexicon.js';
import { PLAYBOOKS, pickPlaybook } from './playbooks.js';
import { INSTITUTIONS, TYPE_NEVER, UNIVERSAL_NEVER, RULE_SOURCES, REPORTING, KB_VERSION, SOURCES } from '../data/institutions.js';
import EVIDENCE from '../data/evidence.js';
import { contextFindings, triage, countryOf, maskNumber } from './context.js';

export { redact } from './redact.js';
export { triage, countryOf, maskNumber, claimedRelation, callerCheck } from './context.js';
export { analyzeUrl, extractLinks } from './url.js';
export { REPORTING, KB_VERSION, INSTITUTIONS, PLAYBOOKS };
export const ENGINE_VERSION = '0.1.0';

const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());
const sev = w => (w >= 0.85 ? 'critical' : w >= 0.6 ? 'high' : w >= 0.3 ? 'medium' : 'low');

const ACTION_WEIGHT = {
  share_card: 0.75, share_eid: 0.4, click_update_link: 0.45, install_apk: 0.8, share_screen: 0.6, pay_fee: 0.35,
  add_beneficiary: 0.6, pay_crypto: 0.6, keep_secret: 0.5, move_channel: 0.25, send_money_urgent: 0.45
};
const TACTIC_WEIGHT = {
  urgency: 0.2, threat_block: 0.35, threat_legal: 0.5, prize: 0.4, too_good: 0.6, job_offer: 0.25, job_task: 0.6, family_emergency: 0.4, delivery_pretext: 0.3,
  family_greeting: 0.15, refund_bait: 0.25, account_alert: 0.1, verification_pretext: 0.2, caller_pressure: 0.5,
  // softer scams: each alone is a caution (>= 0.3); with a money / code / link ask it climbs to high or scam
  advance_fee: 0.55, romance_story: 0.45, rental_deposit: 0.5, marketplace_buyer: 0.55, loan_fee: 0.5, recovery_scam: 0.55, blackmail: 0.7, visa_job_fee: 0.5
};
const GOV_TLDS = ['ae', 'abudhabi', 'dubai', 'xn--mgbaam7a8h'];

export function citeFor(instId, actionId) {
  for (const src of EVIDENCE.sources?.[instId] || []) {
    const st = (src.statements || []).find(s => s.actions.includes(actionId));
    if (st) return { title: src.title.split('|')[0].trim(), url: src.url, quote: st.quote, fetchedAt: src.fetchedAt };
  }
  const r = (RULE_SOURCES[actionId] || [])[0];
  return r ? { title: r.title, url: r.url } : null;
}

function finding(id, w, title, detail = null, extra = {}) {
  return { id, key: extra.key || `${id}:${title.en}`, w: Math.min(0.99, w), severity: sev(w), title, detail, ...extra };
}

export function analyze(input = {}) {
  const t0 = now();
  const rawText = typeof input === 'string' ? input : input.text || '';
  const channel = (typeof input === 'object' && input.channel) || 'unknown';
  const text = normalizeText(rawText);
  const ex = extractAll(text, { sender: input.sender });
  const otp = analyzeOtp(text, ex);
  const findings = [];
  const positives = [];

  const specific = ex.institutions.filter(c => !c.inst.generic);
  const generic = ex.institutions.filter(c => c.inst.generic);
  const primary = specific.find(c => !c.mention) || generic[0] || specific[0] || null;
  const senderClaim = primary && !primary.mention ? primary : null; // a merchant mention is not a claim to be them
  const A = new Set(ex.actions.map(a => a.id));
  const T = new Set(ex.tactics.map(t => t.id));
  const allLinksOfficial = ex.links.length > 0 && ex.links.every(l => l.report.official);

  // ---- 1. Policy contradictions (the core of Veto) ----
  for (const a of ex.actions) {
    const label = ACTIONS[a.id].label;
    if (a.id === 'approve_app_prompt' && ex.safety) continue; // legit "if this wasn't you, reject it"
    if (a.id === 'click_update_link' && allLinksOfficial) continue; // link goes to the real institution
    if (a.id === 'pay_fee' && (T.has('job_offer') || T.has('job_task'))) {
      findings.push(finding('law_violation', 0.88,
        { en: 'Asks you to pay for a job or work visa, UAE law forbids employers and agencies from charging you this.', ar: 'يطلب منك الدفع مقابل وظيفة أو تأشيرة عمل، والقانون الإماراتي يمنع أصحاب العمل والوكالات من تحميلك ذلك.' },
        { en: 'Article 6 of the UAE Labour Law (Federal Decree-Law 33 of 2021) bans charging workers recruitment or visa costs. A real employer pays them. MOHRE advice line: 80084.', ar: 'المادة 6 من قانون العمل الإماراتي (مرسوم بقانون اتحادي 33 لسنة 2021) تمنع تحميل العامل تكاليف الاستقدام أو التأشيرة. صاحب العمل الحقيقي يدفعها. خط وزارة الموارد البشرية: 80084.' },
        { action: a.id, evidence: a.evidence, phrase: a.phrase, cite: { title: SOURCES.labour_fees.title, url: SOURCES.labour_fees.url }, key: 'policy:job_fee' }));
      continue;
    }
    const claimed = [...specific, ...generic].find(c => (TYPE_NEVER[c.inst.type] || []).includes(a.id));
    if (claimed && !claimed.inst.generic) {
      const inst = claimed.inst;
      findings.push(finding('policy_violation', 0.97,
        { en: `${inst.name.en} never asks you to ${label.en}.`, ar: `طلب ${label.ar} يخالف سياسة ${inst.name.ar} المعلنة.` },
        { en: `The message claims to be ${inst.name.en} and asks you to ${label.en}. ${inst.name.en} has publicly committed never to do this, so whoever sent it is not ${inst.name.en}.`,
          ar: `الرسالة تدّعي أنها من ${inst.name.ar} وتطلب منك ${label.ar}، وهذا يخالف السياسة المعلنة لـ${inst.name.ar}، إذن المرسل ليس ${inst.name.ar}.` },
        { action: a.id, inst: inst.id, evidence: a.evidence, phrase: a.phrase, cite: citeFor(inst.id, a.id), key: `policy:${a.id}` }));
    } else if (UNIVERSAL_NEVER.includes(a.id) || claimed) {
      const who = claimed ? claimed.inst : null;
      findings.push(finding('universal_violation', claimed ? 0.93 : 0.9,
        { en: `Asks you to ${label.en}, no genuine bank, police or government entity ever does.`, ar: `يطلب منك ${label.ar}، ولا تطلب ذلك أي جهة حقيقية: لا بنك ولا شرطة ولا جهة حكومية.` },
        who ? { en: `It claims to be ${who.name.en}. Real ones never make this request.`, ar: `يدّعي أنه ${who.name.ar}. والجهات الحقيقية لا تطلب ذلك أبداً.` } : null,
        { action: a.id, evidence: a.evidence, phrase: a.phrase, cite: citeFor(null, a.id), key: `policy:${a.id}` }));
    } else {
      let w = ACTION_WEIGHT[a.id] ?? 0.4;
      let detail = null;
      if (a.id === 'share_eid' && primary) w = ['gov', 'police'].includes(primary.inst.type) ? 0.75 : primary.inst.type === 'bank' ? 0.6 : w;
      if (a.id === 'send_money_urgent' && !T.has('urgency') && !T.has('family_emergency') && !A.has('keep_secret') &&
        ex.amounts.length && ex.amounts.every(m => m.value <= 100)) w = 0.2;
      if (a.id === 'pay_fee' && ex.amounts.some(m => m.currency === 'AED' && m.value > 0 && m.value <= 30)) {
        w = 0.55;
        detail = { en: 'A tiny fee is the bait: the payment page is built to capture your full card details and code.', ar: 'الرسوم الصغيرة طُعم: صفحة الدفع مصممة لالتقاط بيانات بطاقتك ورمزك كاملة.' };
      }
      findings.push(finding('action', w, { en: `Asks you to ${label.en}.`, ar: `يطلب منك ${label.ar}.` }, detail,
        { action: a.id, evidence: a.evidence, phrase: a.phrase, cite: citeFor(primary?.inst.id, a.id), key: `action:${a.id}` }));
    }
  }

  // ---- 2. Links & e-mail domains ----
  let linkRisk = 0;
  const linkItems = [...ex.links.map(l => ({ ...l, isEmail: false })), ...ex.emails.map(e => ({ raw: e.raw, report: e.report, isEmail: true, fromSender: e.fromSender }))];
  linkItems.forEach((l, i) => {
    const r = l.report;
    const host = r.hostUnicode || r.host || l.raw;
    linkRisk = Math.max(linkRisk, r.risk);
    if (r.official) {
      positives.push({ en: `${l.isEmail ? 'E-mail address' : 'Link'} goes to an official ${r.official.name.en} domain (${r.registrable}).`, ar: `${l.isEmail ? 'عنوان البريد' : 'الرابط'} يعود لنطاق رسمي لـ${r.official.name.ar} (${r.registrable}).`, kind: 'official_link' });
    }
    if (r.signals.length) {
      const top = [...r.signals].sort((a, b) => b.w - a.w);
      findings.push(finding(l.isEmail ? 'email_domain' : 'link', Math.min(0.95, r.risk),
        r.risk >= 0.3
          ? { en: `${l.isEmail ? 'Suspicious sender address' : 'Unsafe link'}: ${host}`, ar: `${l.isEmail ? 'عنوان مرسل مشبوه' : 'رابط غير آمن'}: ${host}` }
          : { en: `Link to double-check: ${host}`, ar: `رابط يحتاج تحقّقاً: ${host}` },
        { en: top.map(s => s.en).join(' '), ar: top.map(s => s.ar).join(' ') },
        { link: i, href: r.href, key: `link:${r.registrable || l.raw}` }));
    }
    // claimed institution but link elsewhere
    if (senderClaim && !r.official && !r.neutral && !(r.lookalike || r.brand) && r.host) {
      const inst = senderClaim.inst;
      if (!inst.generic) {
        const govWrongTld = ['gov', 'police'].includes(inst.type) && !GOV_TLDS.includes(r.tld);
        findings.push(finding('impersonation_link', govWrongTld ? 0.88 : r.shortener ? 0.6 : 0.85,
          { en: `Claims to be ${inst.name.en}, but the ${l.isEmail ? 'e-mail comes from' : 'link goes to'} ${host}, not an official ${inst.name.en} ${l.isEmail ? 'address' : 'website'}.`,
            ar: `يدّعي أنه من ${inst.name.ar} لكن ${l.isEmail ? 'البريد يأتي من' : 'الرابط يذهب إلى'} ${host}، وهو ليس ${l.isEmail ? 'عنواناً' : 'موقعاً'} رسمياً لـ${inst.name.ar}.` },
          { en: `Official: ${inst.domains.join(', ') || '·'}.${govWrongTld ? ` UAE government websites end in .gov.ae or .ae. This one ends in .${r.tld}.` : ''}${r.shortener ? ' The short link hides the real destination, use X-ray.' : ''}`,
            ar: `المواقع الرسمية: ${inst.domains.join('، ') || '·'}.${govWrongTld ? ` مواقع الحكومة في الإمارات تنتهي بـ.gov.ae أو .ae، وهذا ينتهي بـ.${r.tld}.` : ''}${r.shortener ? ' الرابط المختصر يخفي الوجهة الحقيقية، استخدم الأشعة.' : ''}` },
          { inst: inst.id, link: i, key: `imp:${r.registrable}` }));
      } else if (['bank', 'police', 'gov'].includes(inst.type) && !r.official) {
        findings.push(finding('impersonation_link', 0.5,
          { en: `Claims to be ${inst.name.en} but links to an unknown website (${host}).`, ar: `يدّعي أنه ${inst.name.ar} لكنه يرسل رابطاً لموقع غير معروف (${host}).` }, null,
          { link: i, key: `impg:${r.registrable}` }));
      }
    }
  });

  // ---- 2b. The classic SMS-phishing shape: an account / payment / delivery / prize story + a link ----
  const unknownLinks = ex.links.filter(l => !l.report.official && !l.report.neutral);
  const PRETEXT = ['threat_block', 'account_alert', 'prize', 'refund_bait', 'verification_pretext', 'delivery_pretext'];
  const awareness = /\b(?:beware of|fraudsters?|scammers?)\b|احذر|يحذر|تحذر/.test(ex.mt); // "Beware of frauds. Do NOT share…"
  if (unknownLinks.length && !awareness && (A.has('click_update_link') || ex.tactics.some(t => PRETEXT.includes(t.id)))) {
    findings.push(finding('pretext_link', 0.6,
      { en: 'Pushes you to a link with an account, payment, delivery or prize story, the standard SMS-phishing pattern.',
        ar: 'يدفعك إلى رابط مع قصة عن حساب أو دفع أو طرد أو جائزة، وهو النمط المعتاد لرسائل التصيّد.' },
      { en: 'Real institutions tell you to open their app or type their address yourself.', ar: 'الجهات الحقيقية تطلب منك فتح تطبيقها أو كتابة عنوانها بنفسك.' },
      { key: 'pretext_link' }));
  }

  // ---- 3. Who sent it ----
  const snd = ex.sender;
  if (snd?.isPhone && primary && ['bank', 'regulator', 'gov', 'police', 'telecom', 'courier'].includes(primary.inst.type)) {
    const intl = snd.kind === 'international';
    if (channel === 'sms' && (snd.kind === 'uae_mobile' || intl)) {
      findings.push(finding('sender', intl ? 0.7 : 0.55,
        { en: `Claims to be ${primary.inst.name.en} but the SMS came from a ${intl ? 'foreign' : 'personal mobile'} number (${snd.raw}).`, ar: `يدّعي أنه من ${primary.inst.name.ar} لكن الرسالة وصلت من رقم ${intl ? 'أجنبي' : 'جوال شخصي'} (${snd.raw}).` },
        { en: 'Banks and government entities in the UAE send SMS from registered sender names (like “EmiratesNBD” or “ADPolice”), not from personal numbers.', ar: 'البنوك والجهات الحكومية في الإمارات ترسل الرسائل من أسماء مرسلين مسجّلة وليس من أرقام شخصية.' },
        { key: 'sender' }));
    } else if (['call', 'whatsapp'].includes(channel) && intl && !primary.inst.generic) {
      findings.push(finding('sender', 0.65,
        { en: `Claims to be ${primary.inst.name.en} from a foreign number (${snd.raw}).`, ar: `يدّعي أنه من ${primary.inst.name.ar} من رقم أجنبي (${snd.raw}).` },
        { en: 'Even a familiar-looking number proves nothing, caller ID can be faked. Hang up and call the official number yourself.', ar: 'حتى الرقم المألوف لا يثبت شيئاً، يمكن تزوير هوية المتصل. أنهِ المكالمة واتصل بالرقم الرسمي بنفسك.' },
        { key: 'sender' }));
    }
  }
  if (snd?.isName && primary && ex.institutions.some(c => c.viaSender && c.inst.id === primary.inst.id)) {
    positives.push({ en: `Sent from the registered sender name “${snd.raw}”.`, ar: `مرسلة من اسم المرسل المسجّل «${snd.raw}».`, kind: 'sender' });
  }

  // ---- 4. Phone numbers in the text ----
  const officialPhones = new Map();
  for (const inst of INSTITUTIONS) for (const p of inst.phones) officialPhones.set(p.n, inst);
  for (const p of ex.phones) {
    const offi = officialPhones.get(p.digits);
    if (offi) { positives.push({ en: `${p.raw} is ${offi.name.en}'s official number.`, ar: `${p.raw} هو الرقم الرسمي لـ${offi.name.ar}.`, kind: 'phone' }); continue; }
    if (primary && !primary.inst.generic && ['uae_mobile', 'international'].includes(p.kind)) {
      const off = primary.inst.phones[0];
      findings.push(finding('callback_number', 0.55,
        { en: `Gives a ${p.kind === 'international' ? 'foreign' : 'personal mobile'} number (${p.raw}) for ${primary.inst.name.en}.`, ar: `يعطي رقماً ${p.kind === 'international' ? 'أجنبياً' : 'جوالاً شخصياً'} (${p.raw}) على أنه لـ${primary.inst.name.ar}.` },
        { en: `That is not ${primary.inst.name.en}'s official line${off ? ` (${off.d})` : ''}.`, ar: `هذا ليس الرقم الرسمي لـ${primary.inst.name.ar}${off ? ` (${off.d})` : ''}.` },
        { key: `phone:${p.digits}` }));
    }
  }

  // ---- 5. Pressure tactics ----
  for (const tct of ex.tactics) {
    if (tct.id === 'family_greeting' && !A.has('send_money_urgent')) continue;
    findings.push(finding('tactic', TACTIC_WEIGHT[tct.id] ?? 0.2, TACTICS[tct.id].label, null, { tactic: tct.id, evidence: tct.evidence, phrase: tct.phrase, key: `tactic:${tct.id}` }));
  }

  // ---- 6. Evasion ----
  if (ex.mixedScript.length) {
    findings.push(finding('evasion', 0.7,
      { en: 'Disguises words with look-alike letters from another alphabet.', ar: 'يموّه الكلمات بحروف متشابهة من أبجدية أخرى.' },
      { en: `Words: ${ex.mixedScript.slice(0, 4).join(', ')}. Legitimate senders never do this. It is done to slip past spam filters.`, ar: `الكلمات: ${ex.mixedScript.slice(0, 4).join('، ')}. المرسلون الحقيقيون لا يفعلون ذلك، الهدف تجاوز فلاتر الرسائل المزعجة.` },
      { key: 'evasion' }));
  }

  const report = {
    input: { channel, sender: input.sender || null, lang: detectLang(text), length: rawText.length },
    claims: ex.institutions.map(c => ({ id: c.inst.id, name: c.inst.name, type: c.inst.type, generic: c.inst.generic, domains: c.inst.domains, phones: c.inst.phones, viaSender: !!c.viaSender })),
    actions: ex.actions.map(a => a.id),
    tactics: ex.tactics.map(t => t.id),
    links: linkItems.map(l => ({ raw: l.raw, isEmail: l.isEmail, ...l.report })),
    phones: ex.phones,
    amounts: ex.amounts,
    otp: otp && !A.has('share_otp') ? otp : otp ? { ...otp, requested: true } : null,
    findings,
    positives,
    _ctx: { actions: ex.actions, tactics: ex.tactics, institutions: ex.institutions, links: ex.links, mt: ex.mt,
      linkRisk: Math.max(linkRisk, ...findings.filter(f => f.id === 'impersonation_link').map(f => f.w)) }
  };
  // ---- 7. What the phone already knows (contacts, chat history, call state) ----
  const ctx = (typeof input === 'object' && input.context) || null;
  if (ctx) {
    const c = contextFindings(report, { sender: input.sender, ...ctx }, text);
    for (const x of c.findings) report.findings.push(finding(x.id, x.w, x.title, x.detail, { key: x.key }));
    report.positives.push(...c.positives);
    report.context = { country: countryOf(input.sender || ctx.sender), triage: triage(text, { sender: input.sender, ...ctx }), ...ctx, savedContacts: undefined };
  }
  finalize(report);
  report.meta = { ms: +(now() - t0).toFixed(2), engine: ENGINE_VERSION, kb: KB_VERSION, institutions: INSTITUTIONS.length, onDevice: true };
  return report;
}

function finalize(report) {
  const fs = report.findings;
  // de-duplicate by key, keep the strongest
  const byKey = new Map();
  for (const f of fs) if (!byKey.has(f.key) || byKey.get(f.key).w < f.w) byKey.set(f.key, f);
  report.findings = [...byKey.values()].sort((a, b) => b.w - a.w);
  let risk = 1 - report.findings.reduce((p, f) => p * (1 - f.w), 1);
  const hasCritical = report.findings.some(f => f.w >= 0.85);
  if (!hasCritical && report.positives.length) risk *= 0.6;
  report.risk = +risk.toFixed(3);
  const hasViolation = report.findings.some(f => /violation/.test(f.id));
  let verdict = risk >= 0.85 ? 'scam' : risk >= 0.6 ? 'high' : risk >= 0.3 ? 'caution' : 'clear';
  if (verdict === 'clear' && report.otp && !report.otp.requested) verdict = 'otp';
  report.verdict = verdict;
  const ctx = report._ctx;
  report.scamType = verdict === 'clear' || verdict === 'otp' ? null : pickPlaybook({ ...ctx, hasViolation, linkRisk: ctx.linkRisk });
  report.playbook = report.scamType ? PLAYBOOKS[report.scamType] : null;
  report.headline = HEADLINES[verdict];
  report.reason = report.findings[0]?.title || null;
  report.next = recommend(report);
}

const HEADLINES = {
  scam: { en: 'This is a scam.', ar: 'هذه عملية احتيال.' },
  high: { en: 'Very likely a scam.', ar: 'على الأرجح احتيال.' },
  caution: { en: 'Be careful, warning signs found.', ar: 'انتبه، توجد علامات تحذير.' },
  otp: { en: 'This is a one-time code. Never share it.', ar: 'هذا رمز تحقق لمرة واحدة. لا تشاركه أبداً.' },
  clear: { en: 'No scam signs found.', ar: 'لم نجد علامات احتيال.' }
};

function recommend(r) {
  const out = [];
  const A = new Set(r.actions);
  const primary = r.claims.find(c => !c.generic) || null;
  const bad = r.verdict === 'scam' || r.verdict === 'high';
  if (bad) out.push({ icon: 'stop', en: 'Stop. Do not reply, pay, click or share anything.', ar: 'توقّف. لا تردّ ولا تدفع ولا تضغط ولا تشارك أي شيء.' });
  if (['share_otp', 'share_pin', 'share_cvv', 'share_card', 'share_password', 'approve_app_prompt', 'approve_uaepass'].some(a => A.has(a)))
    out.push({ icon: 'lock', en: 'Never share codes, PINs or passwords, and never approve an app request you did not start.', ar: 'لا تشارك الرموز أو الأرقام السرية أو كلمات المرور، ولا توافق على طلب في التطبيق لم تبدأه أنت.' });
  if (primary && (bad || r.verdict === 'caution')) {
    const ph = primary.phones?.[0];
    out.push({ icon: 'phone', tel: ph ? ph.n : null, telLabel: ph ? ph.d.replace(/\s*\(.*\)$/, '') : null,
      en: `Check with ${primary.name.en} yourself${ph ? ` on ${ph.d}` : ''}, or the number on the back of your card / in their official app. Don’t call back the number that contacted you.`,
      ar: `تحقّق بنفسك مع ${primary.name.ar}${ph ? ` على ${ph.d}` : ''}، أو الرقم الموجود خلف بطاقتك أو في التطبيق الرسمي. لا تعاود الاتصال بالرقم الذي تواصل معك.` });
  }
  if (r.links.some(l => l.risk >= 0.3 && !l.isEmail)) out.push({ icon: 'link', en: 'Don’t open the link. If you already typed card details or a code on it, call your bank now to block the card.', ar: 'لا تفتح الرابط. إذا أدخلت بيانات بطاقة أو رمزاً فيه، اتصل ببنكك الآن لإيقاف البطاقة.' });
  if (A.has('install_remote') || A.has('share_screen')) out.push({ icon: 'device', en: 'Don’t install anything. If you already did: switch on airplane mode, uninstall the app, then call your bank from another phone.', ar: 'لا تثبّت أي شيء. إن فعلت: فعّل وضع الطيران واحذف التطبيق ثم اتصل ببنكك من هاتف آخر.' });
  if (bad) {
    out.push({ icon: 'money', en: 'Already sent money? Call your bank’s fraud line immediately, the first hour matters most.', ar: 'هل أرسلت مالاً؟ اتصل بخط الاحتيال في بنكك فوراً، الساعة الأولى هي الأهم.' });
    out.push({ icon: 'report', tel: '8002626', telLabel: 'Aman 800 2626', en: 'Report it: Abu Dhabi Police Aman 800 2626 (toll-free) or SMS 2828 · Dubai Police 901 / ecrime.ae.', ar: 'أبلغ: شرطة أبوظبي أمان 8002626 (مجاني) أو رسالة إلى 2828 · شرطة دبي 901 / ecrime.ae.' });
  }
  if (r.verdict === 'otp') {
    out.push({ icon: 'lock', en: 'Only type this code into the app or website YOU are using right now. Nobody, not your bank, not police, will ask you for it.', ar: 'اكتب هذا الرمز فقط في التطبيق أو الموقع الذي تستخدمه أنت الآن. لن يطلبه منك أحد، لا البنك ولا الشرطة.' });
    out.push({ icon: 'phone', en: 'Didn’t start this yourself? Someone is trying to get into your account, call your bank now.', ar: 'لم تبدأ هذه العملية بنفسك؟ هناك من يحاول دخول حسابك، اتصل ببنكك الآن.' });
  }
  if (r.verdict === 'clear' || r.verdict === 'caution') out.push({ icon: 'info', en: 'Veto never says “100% safe”. If anyone asks for a code, a payment or an app install, stop and call the institution yourself.', ar: 'فيتو لا يقول «آمن 100%» أبداً. إذا طلب منك أحد رمزاً أو دفعاً أو تثبيت تطبيق، توقّف واتصل بالجهة بنفسك.' });
  return out;
}

/** Merge extra findings (AI deep-check, X-ray), monotonic: can only add risk, never remove a finding. */
export function rescore(report, extra = []) {
  const merged = { ...report, findings: [...report.findings, ...extra.map(f => ({ ...f, w: Math.min(0.95, f.w), severity: sev(f.w) }))] };
  merged.positives = [...report.positives];
  finalize(merged);
  return merged;
}

export function publicReport(r) {
  const { _ctx, ...rest } = r;
  return rest;
}

// ---------------------------------------------------------------------------------------------
// Predictive scam-script tracker.
// Scam calls follow scripted stages (Wood et al., 2023: "scripted scam progressions"): a claim of
// authority, a manufactured problem, pressure / isolation, and only then the ask. Veto tracks the
// stages live and warns BEFORE the ask, while the victim still has time to hang up.
export const STAGES = [
  { id: 'hook', label: { en: 'Claims authority', ar: 'ادّعاء صفة' } },
  { id: 'problem', label: { en: 'Creates a problem', ar: 'اختلاق مشكلة' } },
  { id: 'pressure', label: { en: 'Pressure', ar: 'ضغط' } },
  { id: 'ask', label: { en: 'The ask', ar: 'الطلب' } }
];
const PROBLEM_T = ['threat_block', 'threat_legal', 'account_alert', 'prize', 'refund_bait', 'verification_pretext', 'family_emergency', 'job_offer', 'job_task', 'too_good', 'delivery_pretext'];
const PRESSURE_T = ['urgency', 'caller_pressure'];
const ASK_A = ['share_otp', 'share_pin', 'share_cvv', 'share_card', 'share_password', 'share_eid', 'approve_app_prompt', 'approve_uaepass', 'install_remote',
  'share_screen', 'install_apk', 'click_update_link', 'pay_fee', 'transfer_safe_account', 'add_beneficiary', 'pay_giftcard', 'pay_crypto', 'send_money_urgent'];

export function scriptStages(r) {
  const T = new Set(r.tactics), A = new Set(r.actions);
  const reached = {
    hook: r.claims.length > 0 || r.findings.some(f => f.id === 'contact_impersonation' || f.id === 'origin_mismatch'),
    problem: PROBLEM_T.some(t => T.has(t)),
    pressure: PRESSURE_T.some(t => T.has(t)) || A.has('keep_secret'),
    ask: ASK_A.some(a => A.has(a)) || r.findings.some(f => /violation/.test(f.id))
  };
  const early = ['hook', 'problem', 'pressure'].filter(s => reached[s]).length;
  // Warn before the ask: a claimed authority + a manufactured problem + pressure or a threat, with no
  // request yet. (A real bank's fraud-alert call has the first two but not the pressure.)
  const preAsk = !reached.ask && reached.hook && reached.problem &&
    (reached.pressure || T.has('threat_legal') || T.has('threat_block'));
  return { reached, preAsk, count: early + (reached.ask ? 1 : 0) };
}

export const PRE_ASK_WARNING = {
  en: 'This conversation is following a known scam script: a claim of authority, a problem, pressure. The next step is usually a request for a code, an app or a transfer. Do not share anything, hang up and call the institution yourself.',
  ar: 'تسير هذه المحادثة وفق سيناريو احتيال معروف: ادّعاء صفة، ثم مشكلة، ثم ضغط. الخطوة التالية عادةً طلب رمز أو تطبيق أو تحويل. لا تشارك أي شيء، أنهِ المكالمة واتصل بالجهة بنفسك.'
};

// ---------------------------------------------------------------------------------------------
// Scam-in-progress fusion (on-device session memory, never stored).
// The moment a scam completes is when a real one-time code meets a fake caller. Veto links the
// two: what the code unlocks (OTP Guard) x who is pressuring you for it (call / message analysis).
const FUSE_WINDOW_MS = 30 * 60 * 1000;
const CODE_ASKS = ['share_otp', 'approve_app_prompt', 'approve_uaepass'];
const suspicious = r => r.claims.length > 0 && (r.verdict === 'scam' || r.verdict === 'high' ||
  r.tactics.some(t => PRESSURE_T.includes(t) || PROBLEM_T.includes(t)) || r.actions.some(a => ASK_A.includes(a)));

/**
 * @param {object} report  the report just produced by analyze()
 * @param {{t:number, report:object}[]} recent  earlier reports from this session (memory only)
 */
export function fuse(report, recent = [], now = Date.now()) {
  const live = recent.filter(x => x.report !== report && now - x.t <= FUSE_WINDOW_MS);
  const extra = [];
  if (report.otp) {
    const ctx = [...live].reverse().find(x => suspicious(x.report));
    if (ctx) {
      const who = ctx.report.claims.find(c => !c.generic) || ctx.report.claims[0];
      const mins = Math.max(1, Math.round((now - ctx.t) / 60000));
      extra.push(finding('fusion', 0.96,
        { en: `This code arrived while someone claiming to be ${who.name.en} was pressuring you (${mins} min ago). This is how the scam completes.`,
          ar: `وصل هذا الرمز بينما كان شخص يدّعي أنه ${who.name.ar} يضغط عليك (قبل ${mins} دقيقة). هكذا يكتمل الاحتيال.` },
        { en: `The code is for ${report.otp.unlocks.en}. ${who.name.en} never asks for codes. Whoever wants it is the scammer.`,
          ar: `الرمز مخصص لـ${report.otp.unlocks.ar}. والجهات الحقيقية لا تطلب الرموز أبداً، ومن يريده هو المحتال.` },
        { key: 'fusion:otp', cite: citeFor(who.id, 'share_otp') }));
    }
  }
  if (report.actions.some(a => CODE_ASKS.includes(a))) {
    const otpCtx = [...live].reverse().find(x => x.report.otp);
    if (otpCtx) {
      const mins = Math.max(1, Math.round((now - otpCtx.t) / 60000));
      extra.push(finding('fusion', 0.97,
        { en: `They are asking for the code you received ${mins} min ago. It unlocks ${otpCtx.report.otp.unlocks.en}.`,
          ar: `يطلبون الرمز الذي وصلك قبل ${mins} دقيقة، وهو يتيح ${otpCtx.report.otp.unlocks.ar}.` },
        { en: otpCtx.report.otp.risk.en, ar: otpCtx.report.otp.risk.ar }, { key: 'fusion:ask' }));
    }
  }
  return extra.length ? rescore(report, extra) : report;
}
