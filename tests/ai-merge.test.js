// The AI merge can only add risk (server/ai-merge.js, the rule the web page applies after an AI deep check).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, fuse } from '../engine/index.js';
import { aiFindings, mergeAi } from '../server/ai-merge.js';

const SCAM = 'Your parcel is on hold. Pay the 12.50 AED fee at http://bit.ly/x1 within 24 hours';
const CALM = 'Hi, are we still meeting for lunch at 1 pm?';
const base = text => fuse(analyze({ text, channel: 'sms' }), []);

test('a risk of 0.9 with an asked action never lowers the risk or the verdict', () => {
  const report = base(SCAM);
  const merged = mergeAi(report, { requested_actions: ['share_otp'], tactics: ['urgency'], risk: 0.9, explanation_en: 'x', explanation_ar: 'y' });
  assert.ok(merged.risk >= report.risk, 'risk must not go down');
  assert.ok(aiFindings(report, { requested_actions: ['share_otp'], risk: 0.9 }).length >= 1);
});

test('a low AI risk with nothing asked adds no finding', () => {
  const report = base(CALM);
  assert.deepEqual(aiFindings(report, { requested_actions: [], tactics: [], risk: 0.1 }), []);
  assert.equal(mergeAi(report, { requested_actions: [], tactics: [], risk: 0.1 }).verdict, report.verdict);
});

test('an error or refusal from the AI changes nothing', () => {
  const report = base(SCAM);
  assert.deepEqual(aiFindings(report, { error: 'unparseable' }), []);
  assert.equal(mergeAi(report, { refused: true }).verdict, report.verdict);
});

test('the overall AI finding is capped at 0.7', () => {
  const report = base(CALM);
  const [overall] = aiFindings(report, { requested_actions: [], tactics: [], risk: 1 });
  assert.equal(overall.key, 'ai:overall');
  assert.ok(overall.w <= 0.7);
});
