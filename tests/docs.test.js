// The README must quote the saved held-out report exactly: one source of truth for the headline numbers.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const read = f => fs.readFileSync(new URL(f, import.meta.url), 'utf8');
const pct = (x, d) => (100 * x).toFixed(d) + ' %';

test('README held-out row quotes the saved test report', () => {
  const report = JSON.parse(read('../data/judge-report.json'));
  const row = read('../README.md').split('\n').find(l => l.startsWith('| All held-out URLs |'));
  assert.ok(row, 'the held-out row is in the README');
  const s = report.all.strict;
  assert.ok(row.includes(pct(s.precision, 1)), 'precision ' + pct(s.precision, 1));
  assert.ok(row.includes(pct(s.recall, 1)), 'recall ' + pct(s.recall, 1));
  assert.ok(row.includes(pct(s.f1, 1)), 'F1 ' + pct(s.f1, 1));
  assert.ok(row.includes(pct(s.fpr, 2)), 'false alarms ' + pct(s.fpr, 2));
});

test('README cautious recall matches the saved test report', () => {
  const report = JSON.parse(read('../data/judge-report.json'));
  assert.ok(read('../README.md').includes('recall ' + pct(report.all.cautious.recall, 2)), 'cautious recall ' + pct(report.all.cautious.recall, 2));
});
