// Phone-context reasoning: contradictions between what a message claims and what the phone knows.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, triage, countryOf } from '../engine/index.js';

const contacts = [{ name: 'Mum', number: '+971 50 111 2233' }, { name: 'Ahmed (son)', number: '050 444 5566' }, { name: 'Dr. Sara', number: '+971 4 222 3333' }];

test('known-contact impersonation: "Hi Mum, new number" from a stranger while Mum is saved', () => {
  // the reader is greeted as Mum -> the sender claims to be her child; the saved son uses another number
  const r = analyze({ text: 'Hi Mum, this is my new number, my phone broke. Can you send me AED 2,000 urgently?', channel: 'whatsapp', sender: '+44 7700 900123',
    context: { inContacts: false, firstContact: true, savedContacts: contacts } });
  const f = r.findings.find(x => x.id === 'contact_impersonation');
  assert.ok(f, 'expected contact_impersonation');
  assert.match(f.title.en, /Ahmed \(son\)/);
  assert.equal(r.verdict, 'scam');
});

test('no impersonation when the message really comes from the saved number', () => {
  const r = analyze({ text: 'Hi Mum, I will be late, practice ran over.', channel: 'whatsapp', sender: '+971504445566',
    context: { inContacts: true, savedName: 'Ahmed (son)', priorMessages: 340, savedContacts: contacts } });
  assert.ok(!r.findings.some(x => x.id === 'contact_impersonation'));
  assert.equal(r.verdict, 'clear');
});

test('institution claimed from a foreign WhatsApp number', () => {
  const r = analyze({ text: 'Dubai Police: you have a pending case. Reply to settle it today.', channel: 'whatsapp', sender: '+92 300 1234567',
    context: { inContacts: false, verifiedSender: false } });
  const f = r.findings.find(x => x.id === 'origin_mismatch');
  assert.ok(f && /Pakistan/.test(f.title.en));
});

test("a stranger's first message that already asks for a click is amplified", () => {
  const base = { text: 'Your parcel is waiting, confirm the delivery here: parcel-uae.top/x', channel: 'sms', sender: '+971 55 000 1111' };
  const plain = analyze(base);
  const withCtx = analyze({ ...base, context: { inContacts: false, firstContact: true } });
  assert.ok(withCtx.risk > plain.risk);
  assert.ok(withCtx.findings.some(x => x.id === 'first_contact'));
});

test('coached scam in progress: a code arrives during a call with an unknown foreign number (no call audio)', () => {
  const r = analyze({ text: 'ADCB: 771204 is your one-time password to add a beneficiary. Never share it.', channel: 'sms', sender: 'ADCB',
    context: { onCall: { number: '+44 20 7946 0000', inContacts: false } } });
  assert.equal(r.verdict, 'scam');
  assert.ok(r.findings.some(x => x.key === 'call_context:otp'));
  const bank = analyze({ text: '', channel: 'other', context: { onCall: { number: '+971 4 123 4567', inContacts: false }, bankAppOpen: true } });
  assert.ok(bank.findings.some(x => x.key === 'call_context:bank'));
});

test('attention gating: trusted chats sleep, strangers are watched, hot words wake the pet', () => {
  const trusted = { inContacts: true, priorMessages: 200 };
  assert.equal(triage('See you at dinner tonight', trusted).mode, 'sleep');
  assert.equal(triage('Can you send me the code you just got?', trusted).mode, 'light');
  assert.equal(triage('Hello dear', { inContacts: false, firstContact: true }).mode, 'watch');
});

test('country lookup from phone numbers', () => {
  assert.equal(countryOf('+44 7700 900123').code, 'GB');
  assert.equal(countryOf('00971501112233').code, 'AE');
  assert.equal(countryOf('050 111 2233').code, 'AE');
  assert.equal(countryOf('+92 300 1234567').code, 'PK');
});
