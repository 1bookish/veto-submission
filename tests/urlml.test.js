// The ML link model: trained weights load, official UAE domains stay low, brand misuse is caught and
// explained, and the model only ever reads the host name.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mlUrlScore, featurize, normHost, regPart } from '../engine/urlml.js';
import { analyzeUrl } from '../engine/url.js';
import { INSTITUTIONS } from '../data/institutions.js';
import { MODEL_REPORT } from '../data/urlml-model.js';

test('the trained model is present and was evaluated on unseen data', () => {
  assert.ok(MODEL_REPORT && MODEL_REPORT.weights > 1000, 'run npm run train:url');
  assert.ok(MODEL_REPORT.report.tranco_unseen_500k_510k.fpr['0.8'] < 0.01, 'false alarms on unseen real sites must stay under 1 %');
  assert.ok(MODEL_REPORT.report.uae_official.above_0_5.length === 0, 'no official UAE domain may score above 0.5');
});

test('host normalisation ignores scheme, www, port, path and query', () => {
  assert.equal(normHost('HTTPS://www.ADCB.com:443/en/login?x=1'), 'adcb.com');
  assert.equal(regPart('secure.login.example.co.uk'), 'example.co.uk');
  const a = featurize('https://adcb-verify.top/a/b?c=d').feats, b = featurize('adcb-verify.top').feats;
  assert.deepEqual([...a.entries()].sort(), [...b.entries()].sort(), 'the path must not change the features');
});

test('official UAE domains score low', () => {
  for (const d of [...new Set(INSTITUTIONS.flatMap(i => i.domains))]) assert.ok(mlUrlScore(d).p < 0.5, d);
});

test('brand misuse is caught and explained', () => {
  for (const h of ['emiratesnbd-secure-verify.top', 'paypal-account-verify.com', 'store.steamcommunite.com']) {
    const r = mlUrlScore(h);
    assert.ok(r.p >= 0.9, `${h} ${r.p}`);
    assert.equal(r.brand, true, h);
    assert.ok(r.why.length >= 1 && r.why[0].en && r.why[0].ar, 'explanations in both languages');
  }
});

test('alone, a merely odd-looking name never makes a link "unsafe"', () => {
  const a = analyzeUrl('http://tiny1.jio.com/abc');
  assert.ok(a.risk < 0.3, `risk ${a.risk}`);
  const b = analyzeUrl('https://www.emiratesnbd.com/en');
  assert.equal(b.ml, undefined, 'official domains are never scored');
});

test('letter-pattern features are never shown to a reader as letters', () => {
  for (const u of ['https://xk9q2vz7wplm.example-login.info/a', 'http://qzzxvbnm.top/x']) {
    for (const w of mlUrlScore(u)?.why || []) assert.ok(!/the letters/.test(w.en), w.en);
  }
});
