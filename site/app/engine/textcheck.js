// One check for a message someone received (SMS, WhatsApp, e-mail): the rulebook (engine/index.js), the URL Judge on
// every link in it (engine/judge-core.js), and the learned SMS model (engine/smsmodel.js). Used by the browser extension
// and the server. No network: the optional AI layer is added by the caller with engine/ai-merge.js.
//
// How the parts combine (all monotonic: a part can add a warning, never remove one):
//   - a link the URL Judge calls phishing adds a finding of weight max(0.6, its score), capped at 0.9: at least "high";
//     a suspicious link adds 0.3: at least "caution"
//   - the SMS model adds 0.35 when it flags the text: at most "caution" on its own (2.4 % false alarms in its nested
//     cross-validation, so it never turns a message red by itself)
//   - a message the rulebook cannot read (scope.js) is marked out of scope, so the caller can ask the AI layer
import { analyze, rescore } from './index.js';
import { judgeOffline } from './judge-core.js';
import { smsLocal } from './smsmodel.js';
import { scopeOf } from './scope.js';

export function checkMessage(text, { channel = 'unknown', sender } = {}) {
  const report = analyze({ text, channel, sender });
  const extra = [];
  const judged = [];
  for (const l of (report.links || []).filter(x => !x.isEmail).slice(0, 5)) {
    const j = judgeOffline(l.raw);
    if (j.verdict === 'invalid') continue;
    judged.push({ url: l.raw, host: j.host, verdict: j.verdict, score: j.score, reasons: j.reasons.slice(0, 3), official: !!j.layers?.official });
    const why = j.reasons.find(r => r.w > 0) || j.reasons[0];
    if (j.verdict === 'phishing') {
      extra.push({ id: 'link_judge', key: `judge:${j.host}`, w: Math.min(0.9, Math.max(0.6, j.score)),
        title: { en: `The link goes to ${j.host}, which the URL Judge rates a scam site${why ? ': ' + why.en : '.'}`, ar: `الرابط يقود إلى ${j.host}، ويقيّمه فاحص الروابط كموقع احتيال${why ? ': ' + why.ar : '.'}` }, detail: null });
    } else if (j.verdict === 'suspicious') {
      extra.push({ id: 'link_judge', key: `judge:${j.host}`, w: 0.3,
        title: { en: `The link goes to ${j.host}, which looks suspicious${why ? ': ' + why.en : '.'}`, ar: `الرابط يقود إلى ${j.host}، ويبدو مشبوهاً${why ? ': ' + why.ar : '.'}` }, detail: null });
    }
  }
  const sms = smsLocal(text);
  if (sms.flag) {
    extra.push({ id: 'sms_model', key: 'sms_model', w: 0.35,
      title: { en: 'Worded like known scam texts (the on-device model).', ar: 'صياغة الرسالة تشبه رسائل احتيال معروفة (النموذج على الجهاز).' }, detail: null });
  }
  const merged = extra.length ? rescore(report, extra) : report;
  const scope = scopeOf(text);
  return { ...merged, judgedLinks: judged, sms, scope };
}

/** Should the AI layer look at this message? Out of scope, or the parts disagree, or the user asked. */
export function wantsAi(result, { force = false } = {}) {
  if (force) return true;
  if (!result.scope.inScope) return true;
  if (result.sms.flag && (result.verdict === 'clear' || result.verdict === 'caution')) return true;
  return false;
}
