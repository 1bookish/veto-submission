// Tests for the on-device SMS check (engine/smsmodel.js). The shipped model must be the condition adopted by the logged
// nested cross-validation (data/sms-cv-report.json) with the median of its outer thresholds, and blank input must never
// be flagged. Protocol: docs/RESEARCH_LOG.md, "SMS: nested cross-validation, with and without generated texts".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SMS_MODEL } from '../engine/smsmodel-data.js';
import { smsLocal, smsScore } from '../engine/smsmodel.js';
import { smsTokens } from '../engine/smstokens.js';
import { smsFeatures, fnv1a, SMS_BITS } from '../engine/smsfeatures.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const report = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'sms-cv-report.json'), 'utf8'));

test('the shipped model is the adopted condition with the median outer threshold', () => {
  assert.equal(SMS_MODEL.kind, 'logistic-hashed');
  assert.equal(SMS_MODEL.bits, SMS_BITS);
  assert.equal(SMS_MODEL.condition, report.adopted);
  assert.equal(SMS_MODEL.threshold, report[report.adopted].median_threshold);
});

test('the measured false-alarm rate of the adopted condition is within the agreed 3 %', () => {
  assert.ok(report[report.adopted].false_alarm <= 0.03);
});

test('blank input is never flagged', () => {
  assert.deepEqual(smsLocal(''), { flag: false, score: null });
  assert.deepEqual(smsLocal('   '), { flag: false, score: null });
  assert.deepEqual(smsLocal(undefined), { flag: false, score: null });
});

test('a result is a boolean flag with a finite score', () => {
  const r = smsLocal('Your parcel is on hold, pay the fee at http://bit.ly/x1');
  assert.equal(typeof r.flag, 'boolean');
  assert.ok(Number.isFinite(r.score));
});

test('text with no tokens scores at the bias', () => {
  assert.equal(smsScore(''), SMS_MODEL.bias);
});

test('the score is the bias plus the weights of the hashed features present', () => {
  const text = 'Your account is suspended, verify now at https://x.top';
  const w = new Map(SMS_MODEL.w);
  let s = SMS_MODEL.bias;
  for (const j of smsFeatures(text)) if (w.has(j)) s += w.get(j);
  assert.equal(smsScore(text), s);
});

test('features are unique bucket numbers below 2^bits', () => {
  const f = smsFeatures('verify verify verify now now');
  assert.equal(new Set(f).size, f.length);
  for (const j of f) assert.ok(j >= 0 && j < (1 << SMS_BITS));
  assert.equal(fnv1a(''), 0x811c9dc5);
});

test('the score is deterministic for the same text', () => {
  const text = 'Your account is suspended, verify now';
  assert.equal(smsScore(text), smsScore(text));
});

test('tokens: words, word pairs and the three cues', () => {
  const t = smsTokens('Verify at https://x.top code 482913 تحقق');
  assert.ok(t.includes('verify'));
  assert.ok(t.includes('verify at'));
  assert.ok(t.includes('__LINK__'));
  assert.ok(t.includes('__LONGNUM__'));
  assert.ok(t.includes('__ARABIC__'));
  assert.ok(smsTokens('Your parcel is here').includes('your parcel'));
});
