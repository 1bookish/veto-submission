// npm run test:extension  (after npm run build:extension)
// Loads build/extension into a real Edge or Chrome (no window), and checks what a user would see. Every site here is
// served by the test itself (request interception), so no real scam site is ever contacted:
//   1. a look-alike bank site gets the full-screen scam warning and a red badge
//   2. the bank's official site gets no warning and a green badge
//   3. on a WhatsApp Web page, a scam message gets a label and an ordinary message does not
//   4. the popup checks a pasted scam text and a pasted link
// Screenshots go to build/extension-test/.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EXT = path.join(ROOT, 'build', 'extension');
const SHOTS = path.join(ROOT, 'build', 'extension-test');
if (!fs.existsSync(path.join(EXT, 'manifest.json'))) { console.error('run npm run build:extension first'); process.exit(1); }
fs.mkdirSync(SHOTS, { recursive: true });

const PAGES = {
  'adcb-secure-verify.top': '<title>ADCB Login</title><h1>ADCB Online Banking</h1><form><input name="username"><input type="password" name="password"><button>Login</button></form>',
  'www.adcb.com': '<title>ADCB</title><h1>Abu Dhabi Commercial Bank</h1><p>Welcome.</p>',
  'web.whatsapp.com': `<title>WhatsApp</title><div id="app">
    <div class="message-in"><div class="copyable-text" data-pre-plain-text="[09:12, 25/11/2026] +971 50 000 0000: "><span>Dear customer, your Emirates NBD card is blocked. Update your details now at http://enbd-card-verify.top/login or it will be cancelled today.</span></div></div>
    <div class="message-in"><div class="copyable-text" data-pre-plain-text="[09:15, 25/11/2026] Sara: "><span>Are we still meeting for lunch at 1pm tomorrow? I booked the table.</span></div></div>
  </div>`,
};

const results = [];
const check = (name, ok, detail = '') => { results.push({ name, ok }); console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? '  (' + detail + ')' : ''}`); };

const userDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veto-ext-'));
let ctx = null;
for (const channel of process.env.EXT_CHANNEL ? [process.env.EXT_CHANNEL] : ['msedge', 'chrome', undefined]) {
  try {
    ctx = await chromium.launchPersistentContext(userDir, { channel, headless: true, args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`] });
    const sw = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker', { timeout: 8000 });
    console.log(`browser: ${channel || 'chromium'}; extension worker: ${sw.url()}`);
    break;
  } catch (e) {
    console.log(`${channel || 'chromium'}: ${String(e.message || e).split('\n')[0]}`);
    if (ctx) await ctx.close().catch(() => {});
    ctx = null;
  }
}
if (!ctx) { console.error('no browser could load the extension'); process.exit(1); }
const sw = ctx.serviceWorkers()[0];
const extId = new URL(sw.url()).host;
// pages only: the extension's own worker (its model files, the optional AI call) is never intercepted
const serve = route => {
  const u = new URL(route.request().url());
  const body = PAGES[u.hostname];
  if (body) return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: `<!doctype html><meta charset="utf-8">${body}` });
  if (u.protocol === 'chrome-extension:') return route.continue();
  return route.fulfill({ status: 404, body: '' });
};
const newPage = async () => { const p = await ctx.newPage(); await p.route('**/*', serve); return p; };
const badgeOf = async url => sw.evaluate(async u => { const tabs = await chrome.tabs.query({}); const t = tabs.find(x => x.url === u); return t ? chrome.action.getBadgeText({ tabId: t.id }) : null; }, url);
const wait = ms => new Promise(r => setTimeout(r, ms));

// 1. look-alike bank site
const p1 = await newPage();
const tLoad = Date.now();
await p1.goto('http://adcb-secure-verify.top/login');
// the first page after the browser starts can arrive before the model files finish loading: wait for the verdict
for (let i = 0; i < 50 && !(await p1.evaluate(() => !!document.querySelector('veto-warning'))); i++) await wait(200);
console.log('first verdict after', Date.now() - tLoad, 'ms (includes loading the model files)');
check('look-alike site: full-screen warning shown', await p1.evaluate(() => !!document.querySelector('veto-warning')));
check('look-alike site: red badge', (await badgeOf('http://adcb-secure-verify.top/login')) === '!', `badge "${await badgeOf('http://adcb-secure-verify.top/login')}"`);
await p1.screenshot({ path: path.join(SHOTS, '1-lookalike-warning.png') });

// 2. official site
const p2 = await newPage();
await p2.goto('https://www.adcb.com/');
await wait(1500);
check('official site: no warning', await p2.evaluate(() => !document.querySelector('veto-warning')));
check('official site: green badge', (await badgeOf('https://www.adcb.com/')) === '✓', `badge "${await badgeOf('https://www.adcb.com/')}"`);

// 3. WhatsApp Web messages
const p3 = await newPage();
await p3.goto('https://web.whatsapp.com/');
await wait(3000);
const labels = await p3.evaluate(() => [...document.querySelectorAll('[data-veto-label]')].map(x => x.textContent));
check('WhatsApp: the scam message is labelled', labels.length === 1 && /scam/i.test(labels[0] || ''), labels.join(' | ').slice(0, 160));
check('WhatsApp: the ordinary message is not labelled', labels.length <= 1);
await p3.screenshot({ path: path.join(SHOTS, '3-whatsapp-labels.png') });

// 4. popup: a pasted text and a pasted link
const p4 = await ctx.newPage();
await p4.setViewportSize({ width: 400, height: 760 });
await p4.goto(`chrome-extension://${extId}/popup.html`);
await p4.fill('#input', 'Your Emirates Post parcel is on hold. Pay the 12.50 AED redelivery fee today at http://emiratespost-redelivery.top/pay or it will be returned.');
await p4.click('#check');
await p4.waitForSelector('#result:not([hidden])', { timeout: 10000 });
const textResult = await p4.textContent('#result');
check('popup: pasted scam text is flagged', /Scam|Very likely/.test(textResult), textResult.slice(0, 120));
await p4.screenshot({ path: path.join(SHOTS, '4-popup-text.png') });
await p4.fill('#input', 'https://www.adcb.com/en/personal/');
await p4.click('#check');
await wait(800);
const linkResult = await p4.textContent('#result');
check('popup: pasted official link is official', /Official site/.test(linkResult), linkResult.slice(0, 100));
await p4.click('#lang');
await wait(300);
const st = await p4.evaluate(() => new Promise(r => chrome.runtime.sendMessage({ type: 'veto:status' }, r)));
console.log('model files loaded:', st.modelLoaded, 'in', st.initMs, 'ms');
check('popup: Arabic switch', /افحص/.test(await p4.textContent('#check')));
await p4.screenshot({ path: path.join(SHOTS, '4-popup-arabic.png') });
await p4.click('#lang');

// 5. optional: the AI layer translates and checks a message the rules cannot read. Runs only when a key is given in the
// environment (VETO_TEST_GROQ_KEY); the key is put in this throwaway browser profile only and never written to a file.
if (process.env.VETO_TEST_GROQ_KEY) {
  await sw.evaluate(k => chrome.storage.local.set({ groqKey: k, aiAuto: true }), process.env.VETO_TEST_GROQ_KEY);
  await p4.fill('#input', 'آپ کا بینک اکاؤنٹ بند کر دیا گیا ہے۔ فوری طور پر اپنا کارڈ نمبر اور پن اس لنک پر بھیجیں ورنہ آپ کی رقم ضائع ہو جائے گی');
  await p4.click('#check');
  await p4.waitForFunction(() => !document.getElementById('check').disabled, null, { timeout: 45000 });
  const aiResult = await p4.textContent('#result');
  check('AI: an Urdu scam message is translated and flagged', /Translation/.test(aiResult) && /Scam|Very likely|Be careful/.test(aiResult), aiResult.slice(0, 200));
  await p4.screenshot({ path: path.join(SHOTS, '5-popup-ai-urdu.png') });
}

await ctx.close();
fs.rmSync(userDir, { recursive: true, force: true });
const failed = results.filter(r => !r.ok).length;
console.log(`\n${results.length - failed} of ${results.length} checks passed; screenshots in build/extension-test/`);
process.exit(failed ? 1 : 0);
