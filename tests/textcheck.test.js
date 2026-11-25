// The message check shared by the browser extension and the server (engine/textcheck.js), the language scope that
// decides when the AI is asked (engine/scope.js), the AI answer cleaner (engine/ai-prompt.js), and the guard that keeps
// the shared engine free of Node-only code (the extension runs it in a browser).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import '../engine/urlml2.js'; // points the shared URL model at its files on disk
import { checkMessage, wantsAi } from '../engine/textcheck.js';
import { scopeOf } from '../engine/scope.js';
import { cleanAi, parseAiText, ACTION_IDS } from '../engine/ai-prompt.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('a message with a phishing link is at least "high", and the link is judged', () => {
  const r = checkMessage('Dear customer, your ADCB card is blocked. Verify now at https://adcb-secure-verify.top/login to avoid suspension.');
  assert.ok(['scam', 'high'].includes(r.verdict), r.verdict);
  assert.equal(r.judgedLinks[0].verdict, 'phishing');
});

test('an ordinary message is clear and in scope', () => {
  const r = checkMessage('Meeting moved to 3pm tomorrow, see you there.');
  assert.equal(r.verdict, 'clear');
  assert.equal(r.scope.inScope, true);
  assert.equal(wantsAi(r), false);
});

test('a message with an official link keeps the link marked official', () => {
  const r = checkMessage('Your statement is ready. Log in at https://www.adcb.com to view it.');
  assert.equal(r.judgedLinks[0].official, true);
});

test('language scope: English and Arabic are read by the rules; other languages go to the AI', () => {
  assert.equal(scopeOf('Your Emirates Post parcel is on hold. Pay the fee now').inScope, true);
  assert.equal(scopeOf('عزيزي العميل، تم إيقاف بطاقتك').inScope, true);
  assert.equal(scopeOf('آپ کا اکاؤنٹ بند کر دیا گیا ہے').lang, 'urdu_persian');
  assert.equal(scopeOf('Ваш аккаунт заблокирован, перейдите по ссылке').lang, 'other_script');
  assert.equal(scopeOf('Ang iyong account ay na-block. Pindutin ang link para ma-verify agad.').lang, 'latin_other');
  assert.equal(scopeOf('Aapka account block ho gaya hai, turant link pe click karo').inScope, false);
  assert.equal(wantsAi(checkMessage('آپ کا بینک اکاؤنٹ بند کر دیا گیا ہے، فوری طور پر لنک پر کلک کریں')), true);
});

test('the AI answer is cleaned: unknown ids dropped, risk clamped, strings capped', () => {
  const c = cleanAi({ requested_actions: [ACTION_IDS[0], 'hack_the_planet'], tactics: ['nope'], risk: 7, explanation_en: 'x'.repeat(5000), scam_type: 'weird' });
  assert.deepEqual(c.requested_actions, [ACTION_IDS[0]]);
  assert.deepEqual(c.tactics, []);
  assert.equal(c.risk, 1);
  assert.equal(c.scam_type, 'other');
  assert.ok(c.explanation_en.length <= 600);
  assert.deepEqual(cleanAi(null), { error: 'unparseable' });
});

test('the AI text answer is read even inside reasoning tags or code fences', () => {
  assert.equal(parseAiText('<think>hmm</think>```json\n{"risk": 0.9}\n```').risk, 0.9);
  assert.equal(parseAiText('no json here'), null);
});

test('the engine files the browser extension ships have no Node-only imports', () => {
  for (const f of ['judge-core.js', 'urlml2-core.js', 'textcheck.js', 'scope.js', 'ai-prompt.js', 'ai-merge.js', 'index.js', 'url.js', 'urlml.js', 'smsmodel.js', 'smsfeatures.js']) {
    const src = fs.readFileSync(path.join(ROOT, 'engine', f), 'utf8');
    assert.doesNotMatch(src, /from\s+['"]node:/, f);
  }
  // urlml.js keeps a Buffer fallback for runtimes without atob; the files written for the browser use none
  for (const f of ['judge-core.js', 'urlml2-core.js', 'textcheck.js', 'scope.js', 'ai-prompt.js', 'ai-merge.js']) {
    assert.doesNotMatch(fs.readFileSync(path.join(ROOT, 'engine', f), 'utf8'), /\bBuffer\./, f);
  }
});
