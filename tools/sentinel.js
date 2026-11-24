// npm run sentinel [-- --only enbd,adcb] [--kinds lookalike,ct,search,maps] [--xray 3]
// Runs a Veto Sentinel hunt from the command line (the same engine as the police console at /sentinel.html)
// and prints the most alarming suspects and the campaigns in the case file. State: var/sentinel.json.
import { sweep, overview, PRIORITY } from '../server/sentinel.js';
import { connectors, connectorsConfigured } from '../server/connectors.js';
import { xray } from '../server/xray.js';
import { recordCase, campaigns } from '../server/cases.js';

const args = process.argv.slice(2);
const arg = k => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
const insts = arg('--only') ? arg('--only').split(',') : PRIORITY;
const kinds = arg('--kinds') ? arg('--kinds').split(',') : ['lookalike', 'ct', 'search', 'maps'];
const xrayTop = Number(arg('--xray') || 0);
const on = connectorsConfigured();
console.log(`Veto Sentinel: ${insts.length} institutions · ${kinds.join(', ')} · search ${on.search ? 'on' : 'off'} · maps ${on.maps ? 'on' : 'off'} · x-ray top ${xrayTop}`);

const t0 = Date.now();
const job = await sweep({ insts, kinds, connectors, xray: { run: u => xray(u), record: (r, o) => recordCase(r, o) }, xrayTop, log: m => console.log('  ' + m) });
if (job.error) { console.error('failed:', job.error); process.exit(1); }
const o = overview();
console.log(`\nDone in ${Math.round((Date.now() - t0) / 1000)} s. Watching ${o.counts.total} names: ${o.counts.live} live, ${o.counts.noWeb} registered without a website, ${o.counts.parked} parked, ${o.counts.xrayed} X-rayed (${o.counts.dangerous} dangerous).\n`);
for (const s of o.suspects.slice(0, 25)) {
  console.log(`${String(Math.round((s.score || 0) * 100)).padStart(3)}%  ${s.host.padEnd(40)} ${String(s.status).padEnd(12)} ${(s.instName?.en || s.inst || '').slice(0, 26).padEnd(26)} ${s.sources.join('+')}${s.verdict ? '  x-ray: ' + s.verdict : ''}${s.armedAt ? '  ARMED' : ''}`);
}
const camps = campaigns();
if (camps.length) {
  console.log(`\nCampaigns in the case file:`);
  for (const c of camps.slice(0, 10)) console.log(`  ${c.id}  ${c.size} sites  ${c.members.map(m => m.host).join(', ')}\n        linked by: ${[...new Set(c.links.map(l => `${l.en} (${l.value})`))].slice(0, 4).join('; ')}`);
}
process.exit(0);
