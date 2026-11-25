// Hashed features for the on-device SMS model. The tokens come from smstokens.js (words, word pairs and three cues); each
// is hashed with 32-bit FNV-1a into 2^20 buckets, and a bucket counts once per message. The trainer (tools/sms-cv.js) and
// the phone use this one function, so they cannot differ.
import { smsTokens } from './smstokens.js';

export const SMS_BITS = 20;
const MASK = (1 << SMS_BITS) - 1;

export function fnv1a(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export function smsFeatures(text) {
  const out = [];
  const seen = new Set();
  for (const t of smsTokens(text)) {
    const j = fnv1a(t) & MASK;
    if (!seen.has(j)) { seen.add(j); out.push(j); }
  }
  return out;
}
