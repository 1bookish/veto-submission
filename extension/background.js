// Veto.ai browser extension, background worker. Every check runs here, on the user's computer, with the same engine as
// the Veto server: the URL Judge (engine/judge-core.js) for every website opened, and the message check
// (engine/textcheck.js: rulebook + URL Judge on each link + SMS model) for texts. Nothing leaves the computer unless the
// user turns on (a) online link checks through their own Veto server, or (b) the AI layer (their Veto server or their
// own Groq key). Message text sent to the AI is redacted first (engine/redact.js).
import { setUrlml2Source } from './engine/urlml2-core.js';
import { judgeOffline } from './engine/judge-core.js';
import { checkMessage, wantsAi } from './engine/textcheck.js';
import { mergeAi } from './engine/ai-merge.js';
import { SYSTEM_JSON, userTurn, cleanAi, parseAiText } from './engine/ai-prompt.js';
import { redact } from './engine/redact.js';

const DEFAULTS = {
  server: 'http://localhost:8787', // the user's own Veto server (npm start); optional
  online: true,                    // online link checks through that server, for links that are not clearly safe
  aiAuto: true,                    // ask the AI for messages the rules cannot read, or when the parts disagree
  groqKey: '', groqModel: 'qwen/qwen3.8-27b',
  scanMessages: true,              // check messages on WhatsApp Web, Google Messages, Telegram, Gmail and Outlook
  warnPages: true,                 // show a warning on scam and suspicious sites
  lang: 'en',
  trusted: [],                     // sites the user chose to trust
};
async function settings() {
  try { return { ...DEFAULTS, ...(await chrome.storage.local.get(Object.keys(DEFAULTS))) }; } catch { return { ...DEFAULTS }; }
}

// ---- model files: loaded once per worker start --------------------------------------------------------------------
async function gunzipText(file) {
  const res = await fetch(chrome.runtime.getURL(file));
  if (!res.ok) throw new Error(`${file}: HTTP ${res.status}`);
  return new Response(res.body.pipeThrough(new DecompressionStream('gzip'))).text();
}
let ready = null;
let initMs = null;
function init() {
  if (!ready) {
    const t0 = performance.now();
    ready = (async () => {
      const [modelText, tranco] = await Promise.all([gunzipText('data/urlml2-model.json.gz'), gunzipText('data/tranco-top100k.txt.gz')]);
      const model = JSON.parse(modelText);
      setUrlml2Source({ model: () => model, tranco: () => tranco });
      initMs = Math.round(performance.now() - t0);
      return true;
    })().catch(e => { console.warn('Veto.ai: model files could not be loaded; the rulebook still runs', e); return false; });
  }
  return ready;
}
init();

// ---- the user's Veto server (optional) ------------------------------------------------------------------------------
let health = { at: 0, ok: false, ai: false };
async function serverHealth(s) {
  if (Date.now() - health.at < 60_000) return health;
  try {
    const r = await fetch(`${s.server}/api/health`, { signal: AbortSignal.timeout(1500) });
    const j = r.ok ? await r.json() : null;
    health = { at: Date.now(), ok: !!j?.ok, ai: !!j?.ai, console: !!j?.console };
  } catch { health = { at: Date.now(), ok: false, ai: false }; }
  return health;
}

// ---- websites ----------------------------------------------------------------------------------------------------------
const pageCache = new Map(); // url -> result, for ten minutes
const tabResult = new Map(); // tabId -> result for the page now open
const SKIP = /^(localhost|127\.0\.0\.1|\[::1\])$/;

function hostOf(url) { try { return new URL(url).hostname.toLowerCase().replace(/^www\d?\./, ''); } catch { return ''; } }

async function judgePage(url) {
  const hit = pageCache.get(url);
  if (hit && Date.now() - hit.at < 600_000) return hit.r;
  await init();
  const r = judgeOffline(url);
  r.checkedAt = Date.now();
  pageCache.set(url, { at: Date.now(), r });
  if (pageCache.size > 500) pageCache.delete(pageCache.keys().next().value);
  return r;
}

// online check through the user's own Veto server: redirects, short links, page content, domain age, feeds
async function onlineCheck(url, base, s) {
  if (!s.online || base.layers?.official || base.layers?.restricted || base.verdict === 'invalid') return null;
  if (base.score < 0.1) return null; // clearly safe offline: no need to ask
  const h = await serverHealth(s);
  if (!h.ok) return null;
  try {
    const r = await fetch(`${s.server}/api/v1/judge?url=${encodeURIComponent(url)}&online=1`, { signal: AbortSignal.timeout(12_000) });
    if (!r.ok) return null;
    const j = await r.json();
    j.checkedAt = Date.now();
    return j;
  } catch { return null; }
}

const BADGE = { phishing: ['!', '#c62a1f'], suspicious: ['?', '#b54708'], official: ['✓', '#067a4f'] };
function setBadge(tabId, r) {
  const k = !r ? null : r.verdict === 'phishing' ? 'phishing' : r.verdict === 'suspicious' ? 'suspicious' : r.layers?.official || r.layers?.restricted ? 'official' : null;
  chrome.action.setBadgeText({ tabId, text: k ? BADGE[k][0] : '' }).catch(() => {});
  if (k) chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE[k][1] }).catch(() => {});
}

async function checkTab(tabId, url) {
  if (!/^https?:/i.test(url || '')) { tabResult.delete(tabId); setBadge(tabId, null); return null; }
  const host = hostOf(url);
  if (!host || SKIP.test(host)) { tabResult.delete(tabId); setBadge(tabId, null); return null; }
  const s = await settings();
  const trusted = s.trusted.includes(host);
  const r = await judgePage(url);
  const view = { ...r, trusted };
  tabResult.set(tabId, view);
  setBadge(tabId, trusted ? null : r);
  tell(tabId, view, s);
  onlineCheck(url, r, s).then(on => {
    if (!on) return;
    const cur = tabResult.get(tabId);
    if (!cur || cur.url !== r.url) return; // the tab moved on
    const better = { ...on, trusted, online: true };
    pageCache.set(url, { at: Date.now(), r: better });
    tabResult.set(tabId, better);
    setBadge(tabId, trusted ? null : better);
    if (on.verdict !== r.verdict) tell(tabId, better, s);
  });
  return view;
}
function tell(tabId, r, s) {
  if (!s.warnPages || r.trusted) return;
  if (r.verdict !== 'phishing' && r.verdict !== 'suspicious') return;
  chrome.tabs.sendMessage(tabId, { type: 'veto:page', result: slim(r), lang: s.lang }).catch(() => {});
}
const slim = r => ({ url: r.url, host: r.host, verdict: r.verdict, score: r.score, online: !!r.online, finalUrl: r.finalUrl || null,
  reasons: (r.reasons || []).filter(x => x.w > 0 || x.id === 'official' || x.id === 'popular').slice(0, 4).map(x => ({ id: x.id, w: x.w, en: x.en, ar: x.ar, src: x.src })) });

chrome.webNavigation.onCommitted.addListener(d => { if (d.frameId === 0) checkTab(d.tabId, d.url); });
chrome.webNavigation.onHistoryStateUpdated.addListener(d => { if (d.frameId === 0) checkTab(d.tabId, d.url); });
chrome.tabs.onRemoved.addListener(tabId => tabResult.delete(tabId));
// The browser clears a tab's badge when a page commits, and the page script may ask before the verdict is ready: send both
// again once the page has loaded (the page script draws one warning at most).
async function refresh(d) {
  if (d.frameId !== 0) return;
  const r = tabResult.get(d.tabId);
  if (!r || r.url !== d.url) return;
  setBadge(d.tabId, r.trusted ? null : r);
  tell(d.tabId, r, await settings());
}
chrome.webNavigation.onDOMContentLoaded.addListener(refresh);
chrome.webNavigation.onCompleted.addListener(refresh);

// ---- messages --------------------------------------------------------------------------------------------------------
async function askAi(text, channel, s) {
  const red = redact(text).text;
  const h = await serverHealth(s);
  if (h.ok && h.ai) {
    const r = await fetch(`${s.server}/api/ai`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: red, channel }), signal: AbortSignal.timeout(45_000) });
    const j = await r.json();
    if (!r.ok || j.error || j.refused) throw new Error(j.message || j.error || (j.refused ? 'refused' : `HTTP ${r.status}`));
    return { ...cleanAi(j), provider: 'Veto server (Claude)' };
  }
  if (s.groqKey) {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${s.groqKey}` }, signal: AbortSignal.timeout(30_000),
      body: JSON.stringify({ model: s.groqModel, temperature: 0, max_tokens: 700, response_format: { type: 'json_object' },
        messages: [{ role: 'system', content: SYSTEM_JSON }, { role: 'user', content: userTurn(red, channel) }] }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error?.message || `HTTP ${r.status}`);
    const parsed = parseAiText(j.choices?.[0]?.message?.content);
    if (!parsed) throw new Error('the AI answer was not readable');
    return { ...cleanAi(parsed), provider: `Groq (${s.groqModel})` };
  }
  return null;
}

async function checkText(text, { channel = 'web', ai = 'auto' } = {}) {
  await init();
  const s = await settings();
  const t = String(text || '').slice(0, 8000);
  let r = checkMessage(t, { channel });
  let aiInfo = null;
  const want = ai === 'force' || (ai === 'auto' && s.aiAuto && wantsAi(r));
  if (want) {
    try {
      const out = await askAi(t, channel, s);
      if (out) { r = { ...mergeAi(r, out), judgedLinks: r.judgedLinks, sms: r.sms, scope: r.scope }; aiInfo = out; }
      else aiInfo = { off: true };
    } catch (e) { aiInfo = { error: String(e.message || e).slice(0, 200) }; }
  }
  return {
    verdict: r.verdict, risk: r.risk, headline: r.headline,
    findings: (r.findings || []).slice(0, 5).map(f => ({ id: f.id, w: f.w, en: f.title?.en, ar: f.title?.ar })),
    next: (r.next || []).slice(0, 4).map(n => ({ en: n.en, ar: n.ar })),
    links: r.judgedLinks || [], sms: r.sms, scope: r.scope, ai: aiInfo,
    claims: (r.claims || []).filter(c => !c.generic).slice(0, 2).map(c => c.name),
  };
}

// a pasted single link is a website check, not a message
const LINK_ONLY = /^\s*(?:hxxps?|https?|h\*\*ps?)?(?::\/\/|\[:\]\/\/)?[^\s/]+\.[^\s]{2,}\s*$/i;
async function checkAnything(input, opts) {
  const s = String(input || '').trim();
  if (LINK_ONLY.test(s) && !/\s/.test(s)) {
    await init();
    const r = judgeOffline(s);
    if (r.verdict !== 'invalid') return { kind: 'url', ...slim(r), layers: r.layers };
  }
  return { kind: 'text', ...(await checkText(s, opts)) };
}

let lastCheck = null;
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    if (msg?.type === 'veto:checkText') return checkText(msg.text, { channel: msg.channel || sender.tab?.url && hostOf(sender.tab.url) || 'web', ai: msg.ai || 'auto' });
    if (msg?.type === 'veto:check') { lastCheck = { input: String(msg.input || '').slice(0, 300), result: await checkAnything(msg.input, { channel: 'pasted', ai: msg.ai || 'auto' }) }; return lastCheck.result; }
    if (msg?.type === 'veto:tab') {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) return null;
      const r = tabResult.get(tab.id) || await checkTab(tab.id, tab.url);
      return r ? { ...slim(r), trusted: !!r.trusted, official: !!(r.layers?.official || r.layers?.restricted) } : null;
    }
    if (msg?.type === 'veto:last') return lastCheck;
    if (msg?.type === 'veto:status') { const s = await settings(); const h = await serverHealth(s); return { modelLoaded: await init(), initMs, server: h.ok, serverAi: h.ai, groq: !!s.groqKey, settings: { ...s, groqKey: s.groqKey ? '••••' : '' } }; }
    if (msg?.type === 'veto:trust' && msg.host) {
      const s = await settings();
      await chrome.storage.local.set({ trusted: [...new Set([...s.trusted, msg.host])] });
      if (sender.tab) setBadge(sender.tab.id, null);
      return true;
    }
    if (msg?.type === 'veto:leave' && sender.tab) {
      await chrome.tabs.goBack(sender.tab.id).catch(() => chrome.tabs.update(sender.tab.id, { url: 'chrome://newtab/' }));
      return true;
    }
    if (msg?.type === 'veto:pageResult' && sender.tab) {
      // the page asks for itself, so a missed navigation event (for example in the first second after install) costs nothing
      let r = tabResult.get(sender.tab.id);
      if (!r || r.url !== sender.tab.url) r = await checkTab(sender.tab.id, sender.tab.url);
      const s = await settings();
      return r && !r.trusted && s.warnPages && (r.verdict === 'phishing' || r.verdict === 'suspicious') ? { result: slim(r), lang: s.lang } : null;
    }
    if (msg?.type === 'veto:scanOn') { const s = await settings(); return { on: s.scanMessages, lang: s.lang }; }
    return null;
  })().then(reply, e => reply({ error: String(e.message || e) }));
  return true;
});

// ---- right-click: check a selection or a link -------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'veto-text', title: 'Check this text with Veto.ai', contexts: ['selection'] });
    chrome.contextMenus.create({ id: 'veto-link', title: 'Check this link with Veto.ai', contexts: ['link'] });
  });
});
const VERDICT_WORD = { scam: 'Scam', high: 'Very likely a scam', caution: 'Be careful', otp: 'One-time code: never share it', clear: 'No scam signs found',
  phishing: 'Scam site', suspicious: 'Suspicious site', legitimate: 'No scam signs found' };
chrome.contextMenus.onClicked.addListener(async info => {
  const input = info.menuItemId === 'veto-link' ? info.linkUrl : info.selectionText;
  if (!input) return;
  const result = await checkAnything(input, { channel: 'selection', ai: 'auto' });
  lastCheck = { input: String(input).slice(0, 300), result };
  const first = result.kind === 'url' ? result.reasons?.[0]?.en : result.findings?.[0]?.en;
  chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon-192.png', title: `Veto.ai: ${VERDICT_WORD[result.verdict] || result.verdict}`,
    message: (first || 'Open Veto.ai for details.').slice(0, 220), priority: ['scam', 'high', 'phishing'].includes(result.verdict) ? 2 : 0 });
  try { await chrome.action.openPopup?.(); } catch { /* not available in this Chrome: the notification is enough */ }
});
