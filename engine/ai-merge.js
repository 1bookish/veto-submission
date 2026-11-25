// The merge applied after an AI deep check, on the web page, in the browser extension and in the AI run
// (tools/eval-ai-run.js). The AI's requested actions and tactics that the rulebook did not already find become findings,
// and a risk of 0.5 or more adds one more finding (weight capped at 0.7). Findings only add, so the AI can raise a
// warning but cannot remove one. The measured result is the rule every surface applies.
import { rescore } from './index.js';
import { ACTIONS, TACTICS } from './lexicon.js';

export function aiFindings(report, ai = {}) {
  const have = new Set(report.actions || []);
  const haveTactics = new Set(report.tactics || []);
  const extra = [];
  for (const a of ai.requested_actions || []) {
    if (!have.has(a) && ACTIONS[a]) {
      extra.push({ id: 'ai', key: `ai:action:${a}`, w: 0.6, title: { en: `Asks you to ${ACTIONS[a].label?.en || a}.`, ar: ACTIONS[a].label?.ar || a }, detail: null });
    }
  }
  for (const tc of ai.tactics || []) {
    if (!haveTactics.has(tc) && TACTICS[tc]) {
      extra.push({ id: 'ai', key: `ai:tactic:${tc}`, w: 0.2, title: TACTICS[tc].label, detail: null });
    }
  }
  if (Number(ai.risk) >= 0.5) {
    extra.push({ id: 'ai', key: 'ai:overall', w: Math.min(0.7, Number(ai.risk)), title: { en: `The AI says: ${ai.explanation_en || ''}`, ar: ai.explanation_ar || '' }, detail: null });
  }
  return extra;
}

export function mergeAi(report, ai) {
  return rescore(report, aiFindings(report, ai));
}
