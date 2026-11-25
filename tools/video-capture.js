// node tools/video-capture.js  (after npm run build:extension)
// Captures the REAL extension on demo pages for the demo video: the pages are written here (fictional scam sites and a
// demo chat), and every warning and label on them is drawn by the built extension itself, with no editing.
// Output: build/video/shots/*.png
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EXT = path.join(ROOT, 'build', 'extension');
const OUT = path.join(ROOT, 'build', 'video', 'shots');
fs.mkdirSync(OUT, { recursive: true });

const BANK = `<title>Online Banking | Secure Login</title>
<style>body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;color:#1d2433}
header{background:#c8102e;color:#fff;padding:18px 48px;font-size:22px;font-weight:700;letter-spacing:.5px}
main{display:flex;justify-content:center;padding:70px 16px}
.card{background:#fff;border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,.08);padding:36px 40px;width:380px}
h1{font-size:22px;margin:0 0 6px} p{color:#5b6475;margin:0 0 22px;font-size:14px}
label{display:block;font-size:13px;margin:14px 0 6px;color:#3a4252} input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #cfd6e0;border-radius:6px;font-size:15px}
button{margin-top:22px;width:100%;padding:12px;background:#c8102e;color:#fff;border:0;border-radius:6px;font-size:16px;font-weight:600}</style>
<header>ADCB &nbsp;·&nbsp; Personal Internet Banking</header>
<main><div class="card"><h1>Verify your account</h1><p>Your card has been temporarily blocked. Log in to restore access.</p>
<label>Customer ID</label><input value="">
<label>Password</label><input type="password">
<label>Card number</label><input>
<button>Continue</button></div></main>`;

const I = {
  chats: '<svg viewBox="0 0 24 24" width="24" height="24"><path fill="currentColor" d="M4 4h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H8l-4 4V6a2 2 0 0 1 2-2z" opacity=".9"/></svg>',
  calls: '<svg viewBox="0 0 24 24" width="22" height="22"><path fill="none" stroke="currentColor" stroke-width="1.8" d="M5 4h3l2 5-2 1a11 11 0 0 0 6 6l1-2 5 2v3a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2z"/></svg>',
  status: '<svg viewBox="0 0 24 24" width="22" height="22"><circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-dasharray="4 2.5"/><circle cx="12" cy="12" r="4" fill="currentColor"/></svg>',
  channels: '<svg viewBox="0 0 24 24" width="22" height="22"><path fill="none" stroke="currentColor" stroke-width="1.8" d="M12 3a9 9 0 1 1-6.4 15.4L3 21l.8-3.6A9 9 0 0 1 12 3z"/><circle cx="12" cy="12" r="2.5" fill="currentColor"/></svg>',
  comm: '<svg viewBox="0 0 24 24" width="22" height="22"><circle cx="8" cy="9" r="3" fill="currentColor"/><circle cx="16" cy="9" r="3" fill="currentColor"/><path fill="currentColor" d="M2 19c0-3 3-5 6-5s6 2 6 5zm10 0c0-2 1-3 2-4 3 0 8 1 8 4z"/></svg>',
  newc: '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M11 5h2v6h6v2h-6v6h-2v-6H5v-2h6z"/></svg>',
  dots: '<svg viewBox="0 0 24 24" width="22" height="22"><circle cx="12" cy="5" r="1.8" fill="currentColor"/><circle cx="12" cy="12" r="1.8" fill="currentColor"/><circle cx="12" cy="19" r="1.8" fill="currentColor"/></svg>',
  search: '<svg viewBox="0 0 24 24" width="20" height="20"><circle cx="10.5" cy="10.5" r="6.5" fill="none" stroke="currentColor" stroke-width="2"/><path stroke="currentColor" stroke-width="2" d="M15.5 15.5 21 21"/></svg>',
  video: '<svg viewBox="0 0 24 24" width="24" height="24"><rect x="2" y="6" width="13" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><path fill="currentColor" d="M16 10l5-3v10l-5-3z"/></svg>',
  clip: '<svg viewBox="0 0 24 24" width="24" height="24"><path fill="none" stroke="currentColor" stroke-width="1.8" d="M8 12l6.5-6.5a3.5 3.5 0 0 1 5 5L11 19a5.5 5.5 0 0 1-8-8l7-7"/></svg>',
  emoji: '<svg viewBox="0 0 24 24" width="24" height="24"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.8"/><circle cx="9" cy="10" r="1.2" fill="currentColor"/><circle cx="15" cy="10" r="1.2" fill="currentColor"/><path fill="none" stroke="currentColor" stroke-width="1.8" d="M8 14c2 2.5 6 2.5 8 0"/></svg>',
  mic: '<svg viewBox="0 0 24 24" width="24" height="24"><rect x="9" y="3" width="6" height="11" rx="3" fill="currentColor"/><path fill="none" stroke="currentColor" stroke-width="1.8" d="M5 11a7 7 0 0 0 14 0M12 18v3"/></svg>',
  ticks: '<svg viewBox="0 0 18 11" width="16" height="11"><path fill="none" stroke="#53bdeb" stroke-width="1.6" d="M1 6l3 3 6-7M7 9l1 1 7-8"/></svg>',
};
const doodle = encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180" viewBox="0 0 180 180"><g fill="none" stroke="#ffffff" stroke-opacity=".045" stroke-width="2" stroke-linecap="round"><circle cx="30" cy="30" r="11"/><path d="M70 20l12 12M82 20L70 32"/><rect x="120" y="18" width="26" height="18" rx="4"/><path d="M20 90q15-18 30 0t30 0"/><circle cx="125" cy="85" r="6"/><path d="M110 120h28v20h-28zM115 120v-6h18v6"/><path d="M40 140l10-16 10 16z"/><path d="M150 150c6-10 18-10 22 0"/><path d="M80 150a8 8 0 1 0 16 0a8 8 0 1 0-16 0"/><path d="M95 60l6 10 10 2-8 7 2 10-10-5-10 5 2-10-8-7 10-2z"/></g></svg>');
const avatar = (txt, bg) => `<div class="av" style="background:${bg}">${txt}</div>`;
const item = (av, name, last, time, opts = {}) => `<div class="chatitem${opts.active ? ' active' : ''}">${av}<div class="ci"><div class="r1"><b>${name}</b><em class="${opts.unread ? 'g' : ''}">${time}</em></div><div class="r2"><span>${opts.tick ? I.ticks + ' ' : ''}${last}</span>${opts.unread ? `<i class="badge">${opts.unread}</i>` : ''}</div></div></div>`;
const msg = (who, time, text, out = false) => `<div class="row ${out ? 'out' : 'in'}"><div class="bubble ${out ? 'message-out' : 'message-in'}"><div class="copyable-text" data-pre-plain-text="[${time}, 25/11/2026] ${who}: "><span>${text}</span></div><div class="t">${time}${out ? ' ' + I.ticks : ''}</div></div></div>`;
const waPage = (headName, headSub, headAv, body) => `<title>WhatsApp</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:"Segoe UI",Helvetica,Arial,sans-serif;background:#0b0c0c;height:100vh;display:flex;color:#e9edef;font-size:14.5px}
.rail{width:64px;background:#1d1f1f;display:flex;flex-direction:column;align-items:center;padding:14px 0;gap:22px;color:#aebac1;border-right:1px solid #2a2c2c}
.rail .on{background:#2e2f2f;border-radius:50%;width:40px;height:40px;display:grid;place-items:center;color:#e9edef}
.rail .sp{flex:1}.rail .me{width:30px;height:30px;border-radius:50%;background:linear-gradient(135deg,#3b5b7a,#1f2f40)}
.side{width:420px;background:#161717;border-right:1px solid #2a2c2c;display:flex;flex-direction:column}
.stop{display:flex;align-items:center;justify-content:space-between;padding:18px 20px 10px}.stop h1{font-size:22px;margin:0;font-weight:600}
.stop .ic{display:flex;gap:18px;align-items:center;color:#aebac1}.stop .nc{background:#21c063;color:#0b0c0c;border-radius:10px;width:34px;height:34px;display:grid;place-items:center}
.search{margin:4px 16px 10px;background:#2e2f2f;border-radius:22px;height:40px;display:flex;align-items:center;gap:14px;padding:0 16px;color:#8696a0}
.chips{display:flex;gap:8px;padding:0 16px 10px}.chips span{border:1px solid #3a3c3c;border-radius:16px;padding:5px 13px;color:#aebac1;font-size:13.5px}.chips span.on{background:#103529;border-color:#103529;color:#d9fdd3}
.chatitem{display:flex;gap:13px;padding:10px 14px;margin:0 8px;border-radius:12px;align-items:center}.chatitem.active{background:#2e2f2f}
.av{width:49px;height:49px;border-radius:50%;flex:none;display:grid;place-items:center;font-weight:600;font-size:17px;color:#fff}
.ci{flex:1;min-width:0;border-bottom:1px solid #222424;padding-bottom:10px}.r1,.r2{display:flex;justify-content:space-between;align-items:center;gap:8px}
.r1 b{font-weight:500;font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.r1 em{font-style:normal;font-size:12px;color:#8696a0}.r1 em.g{color:#21c063}
.r2 span{color:#8696a0;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:flex;align-items:center;gap:3px}
.badge{font-style:normal;background:#21c063;color:#0b0c0c;font-size:12px;font-weight:700;border-radius:12px;min-width:20px;height:20px;display:grid;place-items:center;padding:0 6px}
.main{flex:1;display:flex;flex-direction:column;background:#0b141a url("data:image/svg+xml,${doodle}");min-width:0}
.head{height:64px;background:#161717;display:flex;align-items:center;gap:14px;padding:0 18px;border-bottom:1px solid #222424}
.head .av{width:42px;height:42px;font-size:15px}.head .nm{flex:1}.head .nm b{display:block;font-weight:500;font-size:16px}.head .nm small{color:#8696a0;font-size:13px}
.head .hi{display:flex;gap:26px;color:#aebac1;align-items:center}
.msgs{flex:1;padding:18px 56px;display:flex;flex-direction:column;justify-content:flex-end;gap:5px;overflow:hidden}
.row{display:flex}.row.out{justify-content:flex-end}
.bubble{max-width:58%;padding:7px 10px 20px;border-radius:8px;line-height:1.42;color:#e9edef;position:relative;font-size:14.5px}
.message-in{background:#242626;border-top-left-radius:2px}.message-out{background:#144d37;border-top-right-radius:2px}
.t{position:absolute;right:9px;bottom:4px;font-size:11px;color:#8696a0;display:flex;gap:3px;align-items:center}
.lnk{color:#53bdeb;text-decoration:underline}
.day{align-self:center;background:#1d1f1f;color:#8696a0;font-size:12.5px;padding:5px 12px;border-radius:8px;margin:8px 0 6px}
.note{align-self:center;background:#1d1f1f;color:#ffd279;font-size:12px;padding:6px 12px;border-radius:8px;margin-bottom:6px;max-width:70%;text-align:center}
.foot{height:66px;background:#161717;display:flex;align-items:center;gap:16px;padding:0 18px;color:#aebac1}
.foot .in{flex:1;background:#2e2f2f;border-radius:24px;height:44px;display:flex;align-items:center;gap:14px;padding:0 16px;color:#8696a0}
</style>
<div class="rail"><div class="on">${I.chats}</div>${I.calls}${I.status}${I.channels}${I.comm}<div class="sp"></div><div class="me"></div></div>
<div class="side"><div class="stop"><h1>WhatsApp</h1><div class="ic">${I.dots}<div class="nc">${I.newc}</div></div></div>
<div class="search">${I.search}<span>Search or start a new chat</span></div>
<div class="chips"><span class="on">All</span><span>Unread</span><span>Favourites</span><span>Groups</span></div>
${item(avatar('S', '#7e57c2'), 'Sara · TalentHub Dubai', 'Send me your Emirates ID and the OTP…', '09:10', { active: true, unread: 3 })}
${item(avatar('M', '#00897b'), 'Mum ❤️', 'Do not forget the bread on the way 🍞', '08:47', { tick: true })}
${item(avatar('OK', '#5c6bc0'), 'Omar Khalid', 'See you at 1pm 👍', '08:30')}
${item(avatar('PT', '#ef6c00'), 'Project team · MCE', 'Aisha: slides are in the drive', 'Yesterday')}
${item(avatar('☎', '#546e7a'), '+971 52 *** **41', 'آپ کا بینک اکاؤنٹ بند کر دیا گیا…', 'Yesterday', { unread: 1 })}
${item(avatar('DF', '#8d6e63'), 'Dubai Football Club', 'Training moved to 7pm', 'Yesterday')}
${item(avatar('NB', '#3949ab'), 'Noura Bakr', 'Photo', 'Monday', { tick: true })}
</div>
<div class="main"><div class="head">${headAv}<div class="nm"><b>${headName}</b><small>${headSub}</small></div><div class="hi">${I.video}${I.search}${I.dots}</div></div>
<div class="msgs">${body}</div>
<div class="foot">${I.clip}<div class="in">${I.emoji}<span style="flex:1">Type a message</span></div>${I.mic}</div></div>`;
const WA = waPage('Sara · TalentHub Dubai', 'click here for contact info', avatar('S', '#7e57c2'), `<div class="day">Today</div>
<div class="note">🔒 Messages are end-to-end encrypted. This number is not in your contacts.</div>
${msg('Sara', '09:02', 'Hi! 😊 I got your number from the UAE jobs group. Are you looking for part-time work from home?')}
${msg('You', '09:05', 'Maybe, what is it?', true)}
${msg('Sara', '09:06', 'Simple online tasks, only 30 minutes a day. Most people earn AED 800 to 1,500 daily. I can send you the details.')}
${msg('You', '09:07', 'Ok send', true)}
${msg('Sara', '09:09', 'Register here to get your first task: <span class="lnk">https://talenthub-dubai-task.top/join</span> and pay the AED 99 activation fee today, the offer closes tonight!')}
${msg('Sara', '09:10', 'Send me your Emirates ID and the OTP you receive so I can activate your account faster.')}`);

const PAGES = { 'adcb-secure-verify.top': BANK, 'web.whatsapp.com': WA };
const env = fs.existsSync(path.join(ROOT, '..', 'veto-team', 'project', 'config', 'groq.env')) ? fs.readFileSync(path.join(ROOT, '..', 'veto-team', 'project', 'config', 'groq.env'), 'utf8') : '';
const GROQ = (env.match(/GROQ_API_KEY=(\S+)/) || [])[1] || '';

const userDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veto-video-'));
const ctx = await chromium.launchPersistentContext(userDir, { channel: 'msedge', headless: true, viewport: { width: 1280, height: 760 }, deviceScaleFactor: 2,
  args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`] });
const sw = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker');
const extId = new URL(sw.url()).host;
if (GROQ) await sw.evaluate(k => chrome.storage.local.set({ groqKey: k, aiAuto: true }), GROQ);
const serve = route => {
  const u = new URL(route.request().url());
  const body = PAGES[u.hostname];
  if (body) return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: `<!doctype html><meta charset="utf-8">${body}` });
  return route.fulfill({ status: 404, body: '' });
};
const wait = ms => new Promise(r => setTimeout(r, ms));
async function shot(url, name, ms = 3000) {
  const p = await ctx.newPage(); await p.route('**/*', serve);
  await p.goto(url); await wait(ms);
  await p.screenshot({ path: path.join(OUT, name) });
  return p;
}
await shot('http://adcb-secure-verify.top/login', 'pc-scam-site.png', 2500);
const wa = await shot('https://web.whatsapp.com/', 'pc-whatsapp.png', 4000);
const rects = await wa.evaluate(() => [...document.querySelectorAll('[data-veto-label]')].map(x => { const r = x.getBoundingClientRect(); return [Math.round(r.left), Math.round(r.top), Math.round(r.right), Math.round(r.bottom)]; }));
const bank = await (await ctx.pages())[1]?.evaluate?.(() => 0);
console.log('label rects', JSON.stringify(rects));
// popup: a pasted Urdu scam message, translated and judged by the AI layer
const pp = await ctx.newPage();
await pp.setViewportSize({ width: 400, height: 760 });
await pp.goto(`chrome-extension://${extId}/popup.html`);
await pp.fill('#input', 'آپ کا بینک اکاؤنٹ بند کر دیا گیا ہے۔ فوری طور پر اپنا کارڈ نمبر اور پن اس لنک پر بھیجیں ورنہ آپ کی رقم ضائع ہو جائے گی');
await pp.click('#check');
await pp.waitForFunction(() => !document.getElementById('check').disabled, null, { timeout: 45000 });
await wait(400);
await pp.screenshot({ path: path.join(OUT, 'popup-urdu.png') });
// popup: the bilingual verdict on a pasted scam link
await pp.fill('#input', 'http://emiratespost-redelivery.top/pay?id=AE48213');
await pp.click('#check'); await wait(800);
await pp.click('#lang'); await wait(300);
await pp.screenshot({ path: path.join(OUT, 'popup-arabic.png') });
await ctx.close();
console.log('shots in', OUT, fs.readdirSync(OUT).join(', '));
