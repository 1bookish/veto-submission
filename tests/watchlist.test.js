// The UAE brand watchlist and the two look-alike fixes (engine/url.js, data/uae-brands.js). Protocol and measured
// result: docs/RESEARCH_LOG.md, "UAE brand watchlist and two look-alike fixes".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl, watchedBrandFor } from '../engine/url.js';
import { UAE_BRANDS } from '../data/uae-brands.js';

test('a swapped pair of neighbouring letters is a look-alike', () => {
  const a = analyzeUrl('https://adnco.ae/');
  assert.equal(a.lookalike?.inst.id, 'brand:adnoc');
  assert.match(a.lookalike.change.en, /swaps two neighbouring letters/);
});

test('"www" glued to a brand counts as impersonation', () => {
  assert.equal(analyzeUrl('https://wwwadnoc.com/').brand?.strength, 'strong');
});

test('a brand with other words is flagged; the brand\'s own site is not', () => {
  assert.equal(analyzeUrl('https://emaar-uae.com/login').brand?.inst.id, 'brand:emaar');
  const own = analyzeUrl('https://www.adnoc.ae/en');
  assert.equal(own.lookalike, null);
  assert.equal(own.brand, null);
  assert.ok(watchedBrandFor('adnoc.ae'));
});

test('watched brands are never on the official allowlist', () => {
  for (const b of UAE_BRANDS) for (const d of b.domains) assert.equal(analyzeUrl(`https://${d}/`).official, null, d);
});

test('everyday-word brands never count as strong on their own', () => {
  assert.equal(analyzeUrl('https://tamara.net/').brand?.strength ?? 'none', 'weak');
  assert.equal(analyzeUrl('https://tubby.com/').lookalike, null);
});
