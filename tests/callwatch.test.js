// Approval watch and call report: the logic the phone uses for UAE PASS, authenticator and digital-ID apps,
// the storm alert, and the short report that closes after an unknown call. Replaces the planned tests
// (tests/planned/approval-apps.plan.test.js); these run in npm test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyApp, postCallAlert, approvalStorm, callContext, decideForeground, callReport, POST_CALL_MS } from '../engine/callwatch.js';

const MIN = 60 * 1000;

test('UAE PASS is an approval app', () => {
  assert.equal(classifyApp('UAE PASS', null).kind, 'approval');
});

test('authenticator apps are approval apps', () => {
  assert.equal(classifyApp('Google Authenticator', null).kind, 'approval');
  assert.equal(classifyApp('Microsoft Authenticator', null).kind, 'approval');
});

test('bank apps keep their current class', () => {
  assert.equal(classifyApp('Emirates NBD', null).kind, 'bank');
});

test('remote-control apps are flagged as remote', () => {
  assert.equal(classifyApp('AnyDesk', null).kind, 'remote');
});

test('ordinary apps are not flagged', () => {
  assert.equal(classifyApp('WhatsApp', null).kind, null);
  assert.equal(classifyApp('Chrome', null).kind, null);
});

test('an approval app 5 minutes after an unknown call ends raises an alert', () => {
  const r = postCallAlert([{ t: 0, type: 'call_end', unknown: true }, { t: 5 * MIN, type: 'app_front', label: 'UAE PASS' }], { windowMs: 10 * MIN });
  assert.equal(r.alert, true);
  assert.equal(r.reason, 'after_call');
  assert.equal(r.minutesAfter, 5);
});

test('the same app 15 minutes after an unknown call raises no alert', () => {
  const r = postCallAlert([{ t: 0, type: 'call_end', unknown: true }, { t: 15 * MIN, type: 'app_front', label: 'UAE PASS' }], { windowMs: 10 * MIN });
  assert.equal(r.alert, false);
});

test('a call from a saved contact does not open the window', () => {
  const r = postCallAlert([{ t: 0, type: 'call_end', unknown: false }, { t: 5 * MIN, type: 'app_front', label: 'UAE PASS' }], { windowMs: 10 * MIN });
  assert.equal(r.alert, false);
});

test('a bank app opened during an ongoing unknown call raises an alert', () => {
  const r = postCallAlert([{ t: 0, type: 'call_start', unknown: true }, { t: 1 * MIN, type: 'app_front', label: 'Emirates NBD' }]);
  assert.equal(r.alert, true);
  assert.equal(r.reason, 'during_call');
});

test('the approval watch uses the 10-minute window by default', () => {
  assert.equal(POST_CALL_MS, 10 * MIN);
  assert.equal(callContext([{ t: 0, type: 'call_end', unknown: true }], 9 * MIN).when, 'after');
  assert.equal(callContext([{ t: 0, type: 'call_end', unknown: true }], 11 * MIN), null);
});

test('three approval openings in 10 minutes are a storm', () => {
  const ev = [
    { t: 0, type: 'app_front', label: 'UAE PASS' },
    { t: 4 * MIN, type: 'app_front', label: 'UAE PASS' },
    { t: 9 * MIN, type: 'app_front', label: 'Google Authenticator' },
  ];
  assert.deepEqual(approvalStorm(ev), { storm: true, count: 3 });
});

test('two approval openings are not a storm, and openings spread over time are not either', () => {
  assert.equal(approvalStorm([{ t: 0, type: 'app_front', label: 'UAE PASS' }, { t: 1 * MIN, type: 'app_front', label: 'UAE PASS' }]).storm, false);
  const spread = [0, 6, 12].map(m => ({ t: m * MIN, type: 'app_front', label: 'UAE PASS' }));
  assert.equal(approvalStorm(spread).storm, false);
});

test('an approval app during an unknown call shows a card with a cool-down and two choices', () => {
  const d = decideForeground({ events: [{ t: 0, type: 'call_start', unknown: true }, { t: 2 * MIN, type: 'app_front', label: 'UAE PASS' }] });
  assert.equal(d.show, true);
  assert.equal(d.kind, 'approval');
  assert.equal(d.card.level, 'caution');
  assert.equal(d.card.cooldownS, 60);
  assert.deepEqual(d.card.choices.map(c => c.id), ['started', 'not_started']);
  assert.equal(d.card.choices[1].next.level, 'stop');
  assert.ok(d.card.choices[1].next.family.en.length > 0);
});

test('"I did not start it" leads to a stop card with bilingual guidance', () => {
  const d = decideForeground({ events: [{ t: 0, type: 'call_end', unknown: true }, { t: 3 * MIN, type: 'app_front', label: 'UAE PASS' }] });
  const next = d.card.choices[1].next;
  assert.match(next.title.en, /Do not approve/);
  assert.match(next.title.ar, /لا توافق/);
  assert.equal(next.reasons.length, 2);
});

test('a fourth approval request in a short time gives a storm card, not a normal card', () => {
  const ev = [0, 2, 4, 6].map(m => ({ t: m * MIN, type: 'app_front', label: 'UAE PASS' }));
  const d = decideForeground({ events: [{ t: -1, type: 'call_end', unknown: true }, ...ev] });
  assert.equal(d.kind, 'storm');
  assert.equal(d.card.level, 'stop');
});

test('an ordinary app during a call, or an approval app with no unknown call, shows nothing', () => {
  assert.equal(decideForeground({ events: [{ t: 0, type: 'call_start', unknown: true }, { t: MIN, type: 'app_front', label: 'WhatsApp' }] }).show, false);
  assert.equal(decideForeground({ events: [{ t: 0, type: 'app_front', label: 'UAE PASS' }] }).show, false);
});

test('the call report names the country, the background check and what happened', () => {
  const r = callReport({
    durationS: 134,
    number: '+44 ••• 1234',
    caller: { country: { name: { en: 'United Kingdom', ar: 'المملكة المتحدة' } }, signals: [] },
    events: [
      { t: 0, type: 'call_start', unknown: true },
      { t: 134000, type: 'call_end', unknown: true },
      { t: 134000 + 3 * MIN, type: 'app_front', label: 'UAE PASS' },
    ],
  });
  const en = r.lines.map(l => l.en).join(' | ');
  assert.match(en, /Call ended after 2 min 14 s/);
  assert.match(en, /From United Kingdom/);
  assert.match(en, /Background check: not in your reports/);
  assert.match(en, /UAE PASS opened 3 min after the call/);
  assert.ok(!/Nothing else happened/.test(en));
});

test('a quiet call ends with the "nothing else happened" line', () => {
  const r = callReport({ durationS: 20, caller: {}, events: [] });
  assert.match(r.lines.map(l => l.en).join(' | '), /Nothing else happened on this phone/);
});

test('codes and bank apps during a call are reported', () => {
  const r = callReport({ durationS: 60, caller: {}, events: [], codes: 2, bankOpened: true });
  const en = r.lines.map(l => l.en).join(' | ');
  assert.match(en, /2 one-time codes arrived/);
  assert.match(en, /A bank or remote-control app came to the front during the call/);
});

test('every line of a report has an English and an Arabic text', () => {
  const r = callReport({ durationS: 90, caller: { country: { name: { en: 'Pakistan', ar: 'باكستان' } } }, codes: 1, events: [] });
  for (const l of r.lines) {
    assert.ok(l.en.length > 0);
    assert.ok(l.ar.length > 0);
  }
});
