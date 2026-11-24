// npm run ingest [-- enbd fab], "teach" Veto an institution's rules from its own website.
//
// Instead of fine-tuning a model on dense legal T&Cs (which rarely say what a call-centre will
// or won't do, can't be cited and go stale), Veto reads each institution's PUBLIC security /
// fraud-awareness pages, keeps the sentences where the institution commits to what it will never
// ask for ("We will never ask for your OTP…"), maps them to the rulebook's action ids, and writes
// data/evidence.js. Every alert can then quote the institution's own words with a link.
// Re-run it to pick up policy changes (diff the file in git to see what changed).

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { POLICY_SOURCES } from './policy-sources.js';
import { INSTITUTIONS } from '../data/institutions.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

// What a sentence is about -> rulebook action ids
const OBJECTS = {
  share_otp: /\botps?\b|one[\s-]?time (?:password|passcode|code|pin)|verification code|authentication code|رمز التحقق|كلمة المرور لمرة واحدة/i,
  share_pin: /\bpins?\b|الرقم السري/i,
  share_cvv: /\bcvv2?\b|\bcvc\b|security code|الرمز الأمني/i,
  share_card: /card (?:number|details|information)|expiry date|رقم البطاقة|بيانات البطاقة/i,
  share_password: /password|passcode|log-?in details|credentials|user ?name|كلمة المرور|كلمة السر/i,
  install_remote: /remote (?:access|control|desktop)|anydesk|teamviewer|screen[\s-]?shar|تحكم عن بعد/i,
  share_screen: /screen[\s-]?shar/i,
  transfer_safe_account: /safe account|secure account|(?:transfer|move) (?:your )?(?:funds|money|balance) to (?:a |another |a new )/i,
  add_beneficiary: /beneficiar/i,
  install_apk: /\bapk\b|unofficial (?:app|store|source)|third[\s-]?party (?:app|store)/i,
  click_update_link: /\blinks?\b|attachments?|رابط/i,
  approve_app_prompt: /approv\w* (?:a |any |the )?(?:request|transaction|notification)|push notification/i,
  share_eid: /emirates id|passport|الهوية/i,
  pay_giftcard: /gift ?cards?/i
};
// "We never ask…" (a commitment about the institution) vs "never share…" (advice to the customer)
const COMMIT = /\b(?:will never|would never|shall never|never|will not|won't|shall not|does not|doesn't)\b[^.]{0,60}\b(?:ask|request|call|contact|require|seek|approach)\w*/i;
const WE = /\b(?:we|our|bank|the bank|banks|bank staff|staff|employees|representatives?|official authorities|government organi[sz]ations|emirates nbd|mashreq|adcb|fab|adib|emirates islamic|standard chartered|police)\b/i;
const ADVICE = /\b(?:never|do not|don't|avoid|refrain from)\b[^.]{0,40}\b(?:share|disclose|give|reveal|provide|tell|install|download|click|enter|approve|transfer)\w*/i;
const AR_COMMIT = /(?:لن|لا)\s+(?:\S+\s+){0,3}(?:يطلب|نطلب|تطلب|يتصل|نتصل|يرسل|نرسل)/;
const AR_ADVICE = /(?:لا|عدم|تجنب)\s+(?:\S+\s+){0,2}(?:تشارك|تفصح|تعطي|مشاركة|الإفصاح|تثبت)/;
const PHONE = /(?<![\d+])(?:\+971[\s-]?|0)?(?:600|800)[\s-]?\d{2,3}[\s-]?\d{2,4}(?!\d)|(?<![\d+])(?:\+971[\s-]?\(?0?\)?|0)[2-79][\s-]?\d{3}[\s-]?\d{4}(?!\d)/g;

function htmlToText(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<(?:br|\/p|\/li|\/h\d|\/div|\/tr)\b[^>]*>/gi, '\n').replace(/<li\b[^>]*>/gi, '\n• ').replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&#39;|&rsquo;|&lsquo;/g, "'").replace(/&quot;|&ldquo;|&rdquo;/g, '"')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)).replace(/[ \t]+/g, ' ').replace(/\n\s*\n+/g, '\n');
}

async function fetchText(url) {
  try {
    const r = await fetch(url, { headers: { 'user-agent': UA, accept: 'text/html', 'accept-language': 'en-AE,en;q=0.9' }, signal: AbortSignal.timeout(20000), redirect: 'follow' });
    const html = await r.text();
    const text = htmlToText(html);
    if (r.ok && text.length > 1500 && !/access denied|captcha|request blocked/i.test(text.slice(0, 2000))) return { text, method: 'fetch', status: r.status };
  } catch { /* fall through */ }
  // Some bank sites render client-side or block plain HTTP clients: use the installed browser.
  const { chromium } = await import('playwright-core');
  let browser;
  for (const channel of process.platform === 'win32' ? ['msedge', 'chrome', undefined] : [undefined, 'chrome']) {
    try { browser = await chromium.launch({ channel, headless: true }); break; } catch { /* next */ }
  }
  if (!browser) throw new Error('no browser available for rendering');
  try {
    const page = await (await browser.newContext({ userAgent: UA, locale: 'en-AE' })).newPage();
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
    const text = await page.evaluate(() => document.body.innerText);
    return { text, method: 'browser' };
  } finally { await browser.close(); }
}

function extract(text) {
  const sentences = text.split(/(?<=[.!?؟])\s+|\n+/).map(s => s.replace(/^[•\-\s]+/, '').trim()).filter(s => s.length > 20 && s.length < 400);
  const out = [];
  for (const s of sentences) {
    const isCommit = (COMMIT.test(s) && WE.test(s)) || AR_COMMIT.test(s);
    const isAdvice = ADVICE.test(s) || AR_ADVICE.test(s);
    if (!isCommit && !isAdvice) continue;
    const actions = Object.entries(OBJECTS).filter(([, re]) => re.test(s)).map(([id]) => id);
    if (!actions.length) continue;
    if (!out.some(o => o.quote === s)) out.push({ quote: s, kind: isCommit ? 'commitment' : 'advice', actions });
  }
  // commitments first: they prove what the institution itself will never do
  return out.sort((a, b) => (a.kind === 'commitment' ? 0 : 1) - (b.kind === 'commitment' ? 0 : 1));
}

const only = process.argv.slice(2).filter(a => !a.startsWith('-'));
const file = path.join(ROOT, 'data', 'evidence.js');
let previous = { sources: {} };
try { previous = (await import('../data/evidence.js')).default; } catch { /* first run */ }
const result = { generatedAt: new Date().toISOString(), sources: { ...previous.sources } };

for (const [id, urls] of Object.entries(POLICY_SOURCES)) {
  if (only.length && !only.includes(id)) continue;
  const inst = INSTITUTIONS.find(i => i.id === id);
  const entries = [];
  for (const url of urls) {
    process.stdout.write(`- ${inst?.name.en || id}: ${url}\n`);
    try {
      const { text, method } = await fetchText(url);
      const statements = extract(text).slice(0, 25);
      const phones = [...new Set((text.match(PHONE) || []).map(p => p.replace(/\D/g, '').replace(/^971/, '0').replace(/^0(?=[68]00)/, '')))];
      const title = (text.split('\n').find(l => l.trim().length > 8) || url).trim().slice(0, 90);
      entries.push({ url, title: `${inst?.name.en || id}, ${title}`, fetchedAt: new Date().toISOString().slice(0, 10), method, statements, phones });
      console.log(`    ${method}: ${statements.length} policy sentences (${statements.filter(s => s.kind === 'commitment').length} commitments), phones: ${phones.join(', ') || '·'}`);
      for (const s of statements.slice(0, 3)) console.log(`      [${s.kind}] ${s.actions.join(',')}: ${s.quote.slice(0, 140)}`);
    } catch (e) {
      console.log(`    failed: ${String(e.message || e).split('\n')[0]}`);
    }
  }
  if (entries.length) result.sources[id] = entries;
}

// confirm KB phone numbers that appear on the institution's own pages
const confirmed = [];
for (const [id, entries] of Object.entries(result.sources)) {
  const inst = INSTITUTIONS.find(i => i.id === id);
  const seen = new Set(entries.flatMap(e => e.phones));
  for (const p of inst?.phones || []) if (seen.has(p.n)) confirmed.push(`${id}:${p.n}`);
}
result.confirmedPhones = confirmed;

await fs.writeFile(file, `// Generated by tools/ingest-policy.js on ${result.generatedAt}. Do not edit by hand, re-run \`npm run ingest\`.
// Sentences are quoted from each institution's own public security / fraud-awareness pages.
export default ${JSON.stringify(result, null, 2)};
`);
console.log(`\nWrote ${path.relative(ROOT, file)}, ${Object.keys(result.sources).length} institutions, ${Object.values(result.sources).flat().reduce((n, e) => n + e.statements.length, 0)} policy sentences. KB phone numbers confirmed on official pages: ${confirmed.join(', ') || 'none'}`);
