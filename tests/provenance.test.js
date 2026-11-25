// Every reason says where it came from (rule, model, allowlist, popularity, bucket layer, online check, feed, input, AI).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { judgeOffline, REASON_SOURCES } from '../server/judge.js';

const PROBES = [
  'https://www.emiratesnbd.com/', 'https://emiratesnbd-secure-login.example.xyz/verify', 'https://bit.ly/abc12',
  'https://s3.amazonaws.com/bucket/file.html', 'not a url', 'http://185.1.2.3/login', 'https://www.google.com/url?q=https://example.org/',
  'https://000webhostapp.com/login.php', 'https://www.cnn.com/', 'hxxps://emiratesnbd[.]com/login',
];

test('every reason carries a valid source tag', () => {
  let total = 0;
  for (const u of PROBES) {
    const j = judgeOffline(u);
    for (const r of j.reasons) {
      total++;
      assert.ok(REASON_SOURCES.has(r.src), `reason "${r.id}" for ${u} has no valid source (${r.src})`);
    }
  }
  assert.ok(total > 0, 'the probes must produce reasons');
});

test('the model reason is tagged as the model, and the official-site reason as the allowlist', () => {
  const official = judgeOffline('https://www.emiratesnbd.com/');
  assert.ok(official.reasons.some(r => r.id === 'official' && r.src === 'allowlist'));
  const risky = judgeOffline('https://emiratesnbd-secure-login.example.xyz/verify');
  assert.ok(risky.reasons.some(r => r.id === 'ml_url2' && r.src === 'model'));
});
