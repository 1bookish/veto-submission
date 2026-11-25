// On-device SMS check. smsmodel-data.js holds either a logistic regression on hashed words, word pairs and cues
// (tools/sms-cv.js --ship; protocol "SMS: nested cross-validation, with and without generated texts" in
// docs/RESEARCH_LOG.md) or the older Naive Bayes model (tools/build-sms-model.js). It runs on the phone: no text is sent
// anywhere. It can raise a caution card only; red stays with the rules.
import { SMS_MODEL } from './smsmodel-data.js';
import { smsTokens } from './smstokens.js';
import { smsFeatures } from './smsfeatures.js';

const HASHED = SMS_MODEL.kind === 'logistic-hashed';
const W = HASHED ? new Map(SMS_MODEL.w) : null;

// the model's score for one message: higher means more like a scam
export function smsScore(text) {
  if (HASHED) {
    let s = SMS_MODEL.bias;
    for (const j of smsFeatures(text)) {
      const v = W.get(j);
      if (v !== undefined) s += v;
    }
    return s;
  }
  let s = SMS_MODEL.prior;
  for (const w of smsTokens(text)) {
    if (Object.prototype.hasOwnProperty.call(SMS_MODEL.w, w)) s += SMS_MODEL.w[w];
  }
  return s;
}

export function smsLocal(text) {
  if (!text || !String(text).trim()) return { flag: false, score: null };
  const s = smsScore(text);
  return { flag: s >= SMS_MODEL.threshold, score: +s.toFixed(3) };
}
