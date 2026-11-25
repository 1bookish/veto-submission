// The search, ads and Maps hunt (server/connectors.js) is tested with fake SerpApi answers only: no network, no credits.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { INSTITUTIONS } from '../data/institutions.js';
import { connectors, huntPlan, serpGoogle, serpSpent } from '../server/connectors.js';

const realFetch = globalThis.fetch;
const KEYS = ['SERPAPI_KEY', 'SERPAPI_BUDGET', 'BRAVE_API_KEY', 'GOOGLE_PLACES_KEY'];
const reply = body => ({ ok: true, status: 200, json: async () => body });
function fakeSerp(body) {
  globalThis.fetch = async url => (String(url).includes('engine=google_maps') ? reply({ local_results: [] }) : reply(body));
}
function setKeys(vals) {
  for (const k of KEYS) delete process.env[k];
  Object.assign(process.env, vals);
}

test.afterEach(() => { globalThis.fetch = realFetch; for (const k of KEYS) delete process.env[k]; });

test('a full hunt on 23 institutions needs 115 SerpApi searches, which is over the 100 free', () => {
  setKeys({ SERPAPI_KEY: 'test-key' });
  const plan = huntPlan(Array.from({ length: 23 }, (_, i) => ({ id: 'x' + i, name: { en: 'X', ar: 'X' } })));
  assert.equal(plan.serpApiSearches, 115);
  assert.equal(plan.fitsBudget, false);
  assert.equal(plan.hoursAtThatRate, 3);
});

test('20 institutions fit the 100-search budget exactly', () => {
  setKeys({ SERPAPI_KEY: 'test-key' });
  const plan = huntPlan(Array.from({ length: 20 }, (_, i) => ({ id: 'x' + i, name: { en: 'X', ar: 'X' } })));
  assert.equal(plan.serpApiSearches, 100);
  assert.equal(plan.fitsBudget, true);
});

test('Brave and Google Places take the search and Maps work, so SerpApi spends nothing', () => {
  setKeys({ SERPAPI_KEY: 'test-key', BRAVE_API_KEY: 'b', GOOGLE_PLACES_KEY: 'p' });
  const plan = huntPlan(Array.from({ length: 23 }, (_, i) => ({ id: 'x' + i, name: { en: 'X', ar: 'X' } })));
  assert.equal(plan.serpApiSearches, 0);
  assert.equal(plan.search, 'Brave');
  assert.equal(plan.maps, 'Google Places');
});

test('the budget stops the run before it spends another search', async () => {
  setKeys({ SERPAPI_KEY: 'test-key', SERPAPI_BUDGET: String(serpSpent() + 2) });
  fakeSerp({ organic_results: [] });
  await serpGoogle('first');
  await serpGoogle('second');
  await assert.rejects(() => serpGoogle('third'), /budget reached/);
});

test('an unofficial phone number in a search result is flagged; the answer is fake, not live', async () => {
  setKeys({ SERPAPI_KEY: 'test-key', SERPAPI_BUDGET: String(serpSpent() + 50) });
  const enbd = INSTITUTIONS.find(i => i.id === 'enbd');
  fakeSerp({ organic_results: [{ position: 1, title: 'Emirates NBD customer care', link: 'https://enbd-care-help.xyz/',
    snippet: 'Call our care line 800 123456 any time' }] });
  const found = await connectors.suspects([enbd], () => {});
  assert.ok(found.some(s => /search result/.test(s.how)), 'expected a suspect from a search result');
});
