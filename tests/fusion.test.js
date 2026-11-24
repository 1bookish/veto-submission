// Tests for the research-driven upgrades: predictive script tracker, scam-in-progress fusion,
// allowed-verification exceptions, and Radar matching.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, fuse, scriptStages } from '../engine/index.js';

test('script tracker warns BEFORE the ask (claim + problem + pressure, no request yet)', () => {
  const r = analyze({ channel: 'call', text: 'Good afternoon, this is Emirates NBD fraud department. We detected a suspicious transaction on your card. Please do not hang up.' });
  const st = scriptStages(r);
  assert.equal(st.reached.ask, false);
  assert.equal(st.preAsk, true);
});

test('a genuine fraud-alert call (no pressure) does not trigger the pre-ask warning', () => {
  const r = analyze({ channel: 'call', text: 'Hello, this is Emirates NBD. We noticed a suspicious transaction on your card. If it was not you, please call us on the number on the back of your card.' });
  assert.equal(scriptStages(r).preAsk, false);
});

test('fusion: an OTP that arrives during a fake bank call becomes a scam verdict', () => {
  const t0 = Date.now();
  const callR = analyze({ channel: 'call', text: 'This is ADCB card security, your account will be blocked today, do not hang up.' });
  const otpR = analyze({ channel: 'sms', sender: 'ADCB', text: 'ADCB: 771204 is your one-time password to add a beneficiary in ADCB Hayyak. Never share it.' });
  assert.equal(otpR.verdict, 'otp');
  const fused = fuse(otpR, [{ t: t0 - 120000, report: callR }], t0);
  assert.equal(fused.verdict, 'scam');
  assert.ok(fused.findings.some(f => f.id === 'fusion'));
});

test('fusion: a request for "the code" links back to the code received earlier', () => {
  const t0 = Date.now();
  const otpR = analyze({ channel: 'sms', text: 'Your code to add your card to Apple Pay is 552910. Do not share it.' });
  const askR = analyze({ channel: 'call', text: 'Sir, please read me the code you just received.' });
  const fused = fuse(askR, [{ t: t0 - 60000, report: otpR }], t0);
  const f = fused.findings.find(x => x.key === 'fusion:ask');
  assert.ok(f && /Apple Pay/.test(f.title.en));
});

test('fusion never fires on unrelated, old or benign context', () => {
  const t0 = Date.now();
  const benign = analyze({ text: 'Hi mum, I will be home late.' });
  const otpR = analyze({ text: 'Emirates NBD: 482913 is your OTP for a purchase of AED 250.00 at NOON.COM. Do not share it.', sender: 'EmiratesNBD' });
  assert.equal(fuse(otpR, [{ t: t0 - 60000, report: benign }], t0).verdict, 'otp');
  const scamCall = analyze({ channel: 'call', text: 'This is Emirates NBD, your card is blocked, do not hang up.' });
  assert.equal(fuse(otpR, [{ t: t0 - 3 * 3600000, report: scamCall }], t0).verdict, 'otp'); // 3 hours ago
});

test('banks may ask for the LAST 4 digits, not treated as a card-number request', () => {
  const r = analyze({ channel: 'call', text: 'Hello, this is Mashreq. For security, can you confirm the last 4 digits of your card number?' });
  assert.ok(!r.actions.includes('share_card'));
  const bad = analyze({ channel: 'call', text: 'Hello, this is Mashreq. Please confirm your full card number and expiry date.' });
  assert.ok(bad.actions.includes('share_card'));
});
