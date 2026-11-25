// node tools/test-phone-engine.js  (after node tools/build-android.js)
// Loads the phone's engine page (android/build/assets/www/bridge.html, the same files the APK carries) in Edge or Chrome
// without a window, and calls the bridge the way the app does: no phone needed. It catches a module that fails to load
// on the phone (a missing file, a Node-only import) before anyone installs the APK.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WWW = path.join(ROOT, 'android', 'build', 'assets', 'www');
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json', '.css': 'text/css', '.png': 'image/png' };
let browser = null;
for (const channel of ['msedge', 'chrome', undefined]) { try { browser = await chromium.launch({ channel, headless: true }); break; } catch { /* next */ } }
if (!browser) { console.error('no browser'); process.exit(1); }
const page = await browser.newPage();
const errors = [];
page.on('pageerror', e => errors.push(String(e.message || e)));
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
await page.route('http://veto.phone/**', route => {
  const rel = decodeURIComponent(new URL(route.request().url()).pathname).replace(/^\/+/, '');
  const file = path.join(WWW, rel);
  if (!file.startsWith(WWW) || !fs.existsSync(file)) return route.fulfill({ status: 404, body: '' });
  return route.fulfill({ status: 200, contentType: TYPES[path.extname(file)] || 'application/octet-stream', body: fs.readFileSync(file) });
});
await page.goto('http://veto.phone/bridge.html');
await page.waitForFunction(() => window.K && typeof window.K.smsLocal === 'function', null, { timeout: 15000 });
const checks = [];
const ok = (name, pass, detail = '') => { checks.push(pass); console.log(`${pass ? 'ok  ' : 'FAIL'}  ${name}${detail ? '  (' + detail + ')' : ''}`); };
const scamText = 'Dear customer, your account is suspended. Verify your card details now at http://enbd-verify.top/login or it will be closed today.';
const sms = await page.evaluate(t => window.K.smsLocal({ text: t }), scamText);
ok('phone SMS model answers', sms && typeof sms.flag === 'boolean' && Number.isFinite(sms.score), JSON.stringify(sms));
const blank = await page.evaluate(() => window.K.smsLocal({ text: '' }));
ok('blank text is never flagged', blank && blank.flag === false);
const keys = await page.evaluate(() => Object.keys(window.K));
ok('bridge exposes its calls', keys.length > 3, keys.slice(0, 12).join(', '));
ok('no script errors while loading', errors.length === 0, errors.slice(0, 2).join(' | '));
await browser.close();
const failed = checks.filter(x => !x).length;
console.log(`${checks.length - failed} of ${checks.length} checks passed`);
process.exit(failed ? 1 : 0);
