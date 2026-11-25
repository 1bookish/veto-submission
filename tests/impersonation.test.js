import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeChange, analyzeUrl } from '../engine/url.js';

test('a digit added to a real name is named', () => {
  assert.match(describeChange('microsoft1', 'microsoft').en, /adds the digit 1 to the real name/);
});
test('a digit used in place of a letter is named', () => {
  assert.match(describeChange('micr0soft', 'microsoft').en, /uses the digit 0 in place of the letter o/);
  assert.match(describeChange('paypa1', 'paypal').en, /uses the digit 1 in place of the letter l/);
  assert.match(describeChange('amaz0n', 'amazon').en, /uses the digit 0 in place of the letter o/);
});
test('a dropped letter, a repeated letter and a swap are named', () => {
  assert.match(describeChange('microsof', 'microsoft').en, /drops the letter t/);
  assert.match(describeChange('gooogle', 'google').en, /repeats the letter o/);
  assert.match(describeChange('microsooft', 'microsoft').en, /repeats the letter o/);
  assert.match(describeChange('microsotf', 'microsoft').en, /swaps two neighbouring letters/);
});
test('a hyphen added is named, and no change gives null', () => {
  assert.match(describeChange('micro-soft', 'microsoft').en, /adds a hyphen/);
  assert.equal(describeChange('microsoft', 'microsoft'), null);
});
test('the reason shown for a look-alike names the change', () => {
  const sig = analyzeUrl('https://microsoft1.com').signals.find(s => s.id === 'lookalike_domain');
  assert.ok(sig, 'a look-alike signal is present');
  assert.match(sig.en, /adds the digit 1 to the real name, a common trick/);
  assert.match(sig.ar, /يضيف الرقم 1 إلى الاسم الحقيقي/);
});
