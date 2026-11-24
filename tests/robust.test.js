// No-error behaviour under hostile and unusual input: seeded random strings, malformed and extreme URLs,
// broken list files, and a large list. Every call must return a well-formed answer and never throw.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { judgeOffline, judgeList, parseList } from '../server/judge.js';
import { mlUrlScore2 } from '../engine/urlml2.js';
import { analyzeUrl } from '../engine/url.js';

const VERDICTS = new Set(['phishing', 'suspicious', 'legitimate', 'invalid']);

// deterministic generator, so a failure can be reproduced
let seed = 20261124;
const rnd = () => { seed = (Math.imul(seed, 1103515245) + 12345) >>> 0; return seed / 4294967296; };
const pick = a => a[Math.floor(rnd() * a.length)];
const PIECES = ['http://', 'https://', 'www.', 'login', 'secure-', 'bank', 'emiratesnbd', 'adcb', '.com', '.ae', '.xyz', '.tk',
  '/', '//', '?', '&', '=', '%', '%2e', '@', ':', '#', '[', ']', '..', '-', '_', ' ', '\t', '\n', '\r', '\u0000', '﻿',
  'ـ', 'ب', 'م', '中文', 'é', '😀', 'xn--', '192.168.0.1', '[::1]', '0x7f', '%00', '\\', '"', "'", '<', '>', 'a'.repeat(300)];
const randomUrl = () => { let s = ''; const n = 1 + Math.floor(rnd() * 12); for (let i = 0; i < n; i++) s += pick(PIECES); return s; };

const EDGE = [
  '', ' ', 'http://', 'https://', '://', 'https://[::1]/', 'http://1.2.3.4/', 'http://0x7f.1/', 'javascript:alert(1)',
  'data:text/html,<script>alert(1)</script>', 'mailto:a@b.c', 'ftp://example.com/', 'file:///etc/passwd', '\u0000',
  'https://' + 'a'.repeat(5000) + '.com/', 'https://xn--e1afmkfd.xn--p1ai/', 'https://ـ.com/', 'http://user:pass@host.example/',
  'https://host.example:99999/', 'https://[bad/', 'https://\uD800/', 'https://exa mple.com/', 'https://example.com/%E0%A4%A',
  'http://' + '0'.repeat(200) + '.com', 'https://emiratesnbd.com.evil.example/login', 'HTTPS://EMIRATESNBD.COM/', 'hxxps://emiratesnbd[.]com/login',
  'https://sites.google.com/view/x', 'https://bit.ly/abc', 'https://s3.amazonaws.com/bucket/file.html?email=x@y.z',
];

test('the judge answers every random input with a well-formed verdict and never throws', () => {
  for (let i = 0; i < 3000; i++) {
    const u = randomUrl();
    const j = judgeOffline(u);
    assert.ok(VERDICTS.has(j.verdict), `bad verdict "${j.verdict}" for input ${i}`);
    // an input that is not a web address is not scored (score null); every other answer carries a score in [0, 1]
    if (j.verdict === 'invalid') assert.equal(j.score, null, `invalid input ${i} must not carry a score`);
    else assert.ok(Number.isFinite(j.score) && j.score >= 0 && j.score <= 1, `bad score for input ${i}`);
    assert.ok(Array.isArray(j.reasons), `reasons missing for input ${i}`);
  }
});

test('the URL model and the analyser never throw on random input', () => {
  for (let i = 0; i < 1500; i++) {
    const u = randomUrl();
    const m = mlUrlScore2(u);
    assert.ok(m === null || (typeof m.p === 'number' && m.p >= 0 && m.p <= 1));
    assert.doesNotThrow(() => analyzeUrl(u));
  }
});

test('edge and hostile URLs each get a well-formed verdict', () => {
  for (const u of EDGE) {
    const j = judgeOffline(u);
    assert.ok(VERDICTS.has(j.verdict), `bad verdict for ${JSON.stringify(u.slice(0, 60))}`);
    if (j.verdict === 'invalid') assert.equal(j.score, null, `invalid input must not carry a score: ${JSON.stringify(u.slice(0, 60))}`);
    else assert.ok(Number.isFinite(j.score), `bad score for ${JSON.stringify(u.slice(0, 60))}`);
  }
});

test('a broken or messy list file parses without throwing and keeps the good rows', () => {
  const messy = 'url,label\r\n"https://example.com/a,b",0\r\n﻿https://emiratesnbd.com/,0\n\n,,\n"unterminated,1\nhttp://x.example/\t1\n';
  let rows;
  assert.doesNotThrow(() => { rows = parseList(messy); });
  assert.ok(Array.isArray(rows) && rows.length >= 2);
});

test('a large list (20,000 URLs) is judged completely, without errors, in reasonable time', async () => {
  const urls = Array.from({ length: 20000 }, (_, i) => (i % 3 === 0 ? `https://site${i}.example.org/page?id=${i}` : randomUrl()));
  const t0 = Date.now();
  const out = await judgeList(urls.map(u => ({ url: u, label: null })), { online: false, concurrency: 1 });
  const seconds = (Date.now() - t0) / 1000;
  assert.equal(out.results.length, urls.length);
  assert.ok(out.results.every(r => VERDICTS.has(r.verdict)));
  assert.ok(seconds < 120, `20,000 URLs took ${seconds.toFixed(1)} s`);
});
