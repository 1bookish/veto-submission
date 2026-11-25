// Java <-> engine bridge. Java calls window.K.* through WebView.evaluateJavascript and gets plain JSON back.
// Session memory (for "a code arrived while someone was pressuring you") lives here, in memory only,
// for 30 minutes, exactly like the web app. Nothing is stored or sent.
import { analyze, fuse, scriptStages, callerCheck, triage, maskNumber, countryOf, REPORTING, ENGINE_VERSION, KB_VERSION } from './engine/index.js';
import { outgoingCheck, contactsAudit, checkListing } from './engine/ledger.js';
import { decideForeground, callReport as buildCallReport } from './engine/callwatch.js';
import { smsLocal } from './engine/smsmodel.js';

const recent = [];
const WINDOW = 30 * 60 * 1000;
const remember = (report, source) => {
  const now = Date.now();
  while (recent.length && (now - recent[0].t > WINDOW || recent.length > 30)) recent.shift();
  recent.push({ t: now, report, source });
};

function slim(r) {
  let stages = null;
  try { stages = scriptStages(r); } catch (e) { /* optional */ }
  return {
    verdict: r.verdict, risk: r.risk, scamType: r.scamType || null,
    headline: r.headline || null, reason: r.reason || null,
    findings: [...(r.findings || [])].sort((a, b) => b.w - a.w).slice(0, 5)
      .map(f => ({ id: f.id, key: f.key, w: f.w, title: f.title, detail: f.detail || null })),
    positives: (r.positives || []).slice(0, 3).map(p => ({ en: p.en, ar: p.ar, kind: p.kind || null })),
    claims: (r.claims || []).filter(c => !c.generic).map(c => ({ id: c.id, name: c.name, type: c.type, phone: c.phones && c.phones[0] ? { n: c.phones[0].n, d: c.phones[0].d } : null })),
    // phone numbers written in the message: a scam's "call our security desk" number is remembered (on the phone)
    // so the Fake-Number Interceptor can stop the call if the user dials it later
    phones: (r.phones || []).slice(0, 5).map(p => p.digits || p.raw),
    otp: r.otp ? { unlocks: r.otp.unlocks, requested: !!r.otp.requested, risk: r.otp.risk || null } : null,
    triage: (r.context && r.context.triage) || null,
    links: (r.links || []).slice(0, 3).map(l => ({ host: l.hostUnicode || l.host, href: l.href || l.raw, official: !!l.official, risk: l.risk || 0 })),
    preAsk: !!(stages && stages.preAsk),
    // the known scam script, with "people are already doing this" and the one rule it breaks
    playbook: r.scamType && r.playbook ? { id: r.scamType,
      en: { title: r.playbook.en.title, tell: r.playbook.en.tell, common: r.playbook.en.common || '' },
      ar: { title: r.playbook.ar.title, tell: r.playbook.ar.tell, common: r.playbook.ar.common || '' } } : null
  };
}

window.K = {
  version: () => ({ engine: ENGINE_VERSION, kb: KB_VERSION }),
  /** Trust-gated attention: should this message be read at all? */
  triage: (text, ctx) => triage(text || '', ctx || {}),
  /** Full check of one message (input = {text, sender, channel, context}). */
  message(input, keep) {
    const r = fuse(analyze(input || {}), recent);
    if (keep !== false) remember(r, (input && input.channel) || 'chat');
    return slim(r);
  },
  /** Device event during a call (bank app opened / screen shared), no text needed. */
  device(ctx) { return slim(analyze({ text: '', channel: 'device', context: ctx || {} })); },
  caller: (number, o) => callerCheck(number || '', o || {}),
  /** Before an outgoing call: a number a scam gave you? (Fake-Number Interceptor) */
  outgoing: (number, o) => outgoingCheck(number || '', o || {}),
  /** Contacts saved under an institution's name with a number it does not publish. */
  contacts: list => contactsAudit(list || []),
  listing: l => checkListing(l || {}),
  /** Approval apps after an unknown call (UAE PASS, authenticator, digital ID), and the call report. */
  callwatch: p => decideForeground(p || {}),
  callReport: p => buildCallReport(p || {}),
  smsLocal: p => smsLocal(p && p.text),
  mask: n => ({ masked: maskNumber(n), country: countryOf(n) }),
  reporting: () => REPORTING
};
try { window.VetoNative && window.VetoNative.ready(); } catch (e) { /* not in the app */ }
