// X-ray, part 2: what does this page WANT from you, and WHERE does it send what you type?
//
//  • Watcher script, injected before any page code: records tricks a scam page plays (copying a
//                      command to your clipboard, asking for notifications, going full-screen, vibrating,
//                      trapping the back button, probing for a crypto wallet). It also neutralises them.
//  • Canary trap. Veto types obviously FAKE details (test card 4111…, a random marker word) into
//                      the page inside the sealed browser, presses the button, and watches the network.
//                      Any request that carries the fake data is caught and BLOCKED, so nothing ever
//                      reaches the criminals, but we learn where it was going: a Telegram bot, a Discord
//                      webhook, a Google Apps Script, the page's own server…
//                      (Telegram bot tokens were found in 42.9 % of 732 live phishing kits, arXiv 2608.07451;
//                       Forescout counted 4,145 bot tokens on 9,100 phishing domains in 2025.)
//  • Intent summary, one plain sentence: "This page wants your card number, CVV and the code your
//                      bank sends you, enough to spend your money."
// Pure functions here (unit-tested); the browser plumbing lives in xray.js.

import { splitDomain } from '../engine/url.js';

export const WATCHER = `(() => {
  const K = { ev: [] };
  try { Object.defineProperty(window, '__veto', { value: K, enumerable: false }); } catch (e) { return; }
  const log = (t, d) => { try { if (K.ev.length < 80) K.ev.push({ t, d: String(d == null ? '' : d).slice(0, 300) }); } catch (e) {} };
  // Phishing kits hide from scanners that admit to being automated, so the chamber doesn't admit it.
  try { Object.defineProperty(Navigator.prototype, 'webdriver', { configurable: true, get: () => false }); } catch (e) {}
  try { const c = navigator.clipboard; if (c) { c.writeText = s => { log('clipboard', s); return Promise.resolve(); }; c.write = () => { log('clipboard', '[binary]'); return Promise.resolve(); }; } } catch (e) {}
  try { const ex = Document.prototype.execCommand; Document.prototype.execCommand = function (cmd, ...a) {
    if (/^(copy|cut)$/i.test(cmd)) { let s = ''; try { const a2 = document.activeElement; s = (a2 && 'value' in a2 && a2.value) || String(getSelection()); } catch (e) {} log('clipboard', s); return true; }
    return ex.call(this, cmd, ...a); }; } catch (e) {}
  try { if (window.Notification) Notification.requestPermission = () => { log('notify'); return Promise.resolve('denied'); }; } catch (e) {}
  try { Element.prototype.requestFullscreen = function () { log('fullscreen'); return Promise.reject(new Error('blocked by Veto')); }; Element.prototype.webkitRequestFullscreen = Element.prototype.requestFullscreen; } catch (e) {}
  try { navigator.vibrate = () => { log('vibrate'); return false; }; } catch (e) {}
  try { Object.defineProperty(window, 'ethereum', { configurable: true, get() { log('wallet'); return undefined; } }); } catch (e) {}
  try { const ps = History.prototype.pushState; let n = 0; History.prototype.pushState = function (...a) { if (++n === 3) log('backtrap', n); return ps.apply(this, a); }; } catch (e) {}
  try { const ae = EventTarget.prototype.addEventListener; EventTarget.prototype.addEventListener = function (t, ...a) {
    if (this === window && (t === 'beforeunload' || t === 'popstate')) log('leavetrap', t); return ae.call(this, t, ...a); }; } catch (e) {}
  try { if (navigator.mediaDevices) navigator.mediaDevices.getUserMedia = () => { log('camera'); return Promise.reject(new Error('blocked by Veto')); }; } catch (e) {}
  try { if (navigator.geolocation) navigator.geolocation.getCurrentPosition = (ok, err) => { log('location'); if (err) err({ code: 1, message: 'denied' }); }; } catch (e) {}
  try { const AC = window.AudioContext || window.webkitAudioContext; if (AC) { const o = AC.prototype.createOscillator; AC.prototype.createOscillator = function () { log('beep'); return o.call(this); }; } } catch (e) {}
})();`;

// ---------- fields ----------
export function classifyField(f) {
  const s = `${f.name} ${f.id} ${f.ph} ${f.label} ${f.ac}`.toLowerCase();
  const out = [];
  const isOtp = /one-time-code/.test(f.ac) || /\botp\b|one.?time|verification code|sms code|رمز التحقق|activation code/.test(s);
  if (isOtp) out.push('otp');
  if (f.type === 'password' || (!isOtp && /pass(word|code)?|pwd|كلمة المرور|كلمة السر/.test(s))) out.push('password');
  if (/cc-number/.test(f.ac) || /card.?(no|num)|cardnumber|\bpan\b|رقم البطاقة|card number/.test(s)) out.push('card');
  if (/cc-csc/.test(f.ac) || /\bcvv|\bcvc|\bcsc\b|security code|الرمز الامني|الرمز الأمني/.test(s)) out.push('cvv');
  if (/cc-exp/.test(f.ac) || /expir|expiry|mm\s?\/\s?yy|valid thru|تاريخ الانتهاء/.test(s)) out.push('expiry');
  if (/\bpin\b|atm.?pin|الرقم السري/.test(s)) out.push('pin');
  if (/emirates.?id|\beid\b|\b784|id number|الهوية/.test(s)) out.push('eid');
  if (/\biban\b/.test(s)) out.push('iban');
  if (/seed|recovery phrase|secret phrase|mnemonic|12.?word|24.?word/.test(s)) out.push('seed');
  return out;
}
export function fillClass(f) {
  const c = classifyField(f)[0];
  if (c) return c;
  const s = `${f.name} ${f.id} ${f.ph} ${f.label} ${f.ac}`.toLowerCase();
  if (f.type === 'email' || /e-?mail/.test(s)) return 'email';
  if (f.type === 'tel' || /phone|mobile|\btel\b|هاتف|جوال/.test(s)) return 'phone';
  if (/name|الاسم/.test(s)) return 'name';
  return 'text';
}

// ---------- canary trap ----------
export const newRun = () => 'kq' + Math.random().toString(36).slice(2, 8);
export function canaryValues(run) {
  return {
    card: '4111 1111 1111 1111', cvv: '737', expiry: '12/29', otp: '482915', pin: '4827', password: `Kc-${run}-pw`,
    eid: '784-1900-0000000-0', iban: 'AE070000000000000000000', seed: `veto canary ${run} test words only`,
    email: `${run}@example.invalid`, phone: '0500000000', name: `Kc ${run}`, text: run
  };
}
const flat = s => s.replace(/[\s\-+.]|%20|%2B|%2D/gi, '');
/** Does this request URL / body carry any of the fake values Veto typed? (raw, URL-encoded, spaced, base64) */
export function carriesCanary(raw, run) {
  if (!raw) return false;
  let t = String(raw).slice(0, 200000);
  try { t += ' ' + decodeURIComponent(t.replace(/\+/g, ' ')); } catch { /* not URL-encoded */ }
  for (const m of t.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g)?.slice(0, 40) || []) {
    try { t += ' ' + Buffer.from(m.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('latin1'); } catch { /* ignore */ }
  }
  const f = flat(t);
  return t.includes(run) || f.includes('4111111111111111') || f.includes('7841900000000000');
}

const SINKS = [
  { kind: 'telegram', host: /^api\.telegram\.org$/i, path: /^\/bot/i, en: 'a Telegram bot, a criminal’s private chat', ar: 'بوت تيليجرام، محادثة خاصة بالمحتال' },
  { kind: 'discord', host: /(^|\.)discord(app)?\.com$/i, path: /^\/api\/(v\d+\/)?webhooks\//i, en: 'a Discord webhook, a criminal’s chat server', ar: 'رابط ويب هوك في ديسكورد، خادم محادثة للمحتال' },
  { kind: 'apps_script', host: /^script\.google(usercontent)?\.com$/i, path: /^\/macros\//i, en: 'a Google Apps Script (a hidden spreadsheet)', ar: 'سكربت جوجل (جدول بيانات مخفي)' },
  { kind: 'form_service', host: /(^|\.)(formspree\.io|getform\.io|formsubmit\.co|web3forms\.com|usebasin\.com|formcarry\.com|submit-form\.com|api\.emailjs\.com|staticforms\.xyz)$/i, en: 'a form-to-email service (straight to an inbox)', ar: 'خدمة تحوّل النموذج إلى بريد إلكتروني' },
  { kind: 'cloud_db', host: /(\.firebaseio\.com|^firestore\.googleapis\.com|\.supabase\.co)$/i, en: 'a cloud database', ar: 'قاعدة بيانات سحابية' },
  { kind: 'tunnel', host: /(^|\.)(webhook\.site|pipedream\.net|requestbin\.com|ngrok-free\.app|ngrok\.io|ngrok\.app|trycloudflare\.com|loca\.lt|serveo\.net)$/i, en: 'a temporary tunnel / webhook', ar: 'نفق أو رابط مؤقت' }
];
const maskBot = p => { const m = /\/bot(\d+):/i.exec(p); return m ? `bot${m[1]}:••••` : 'bot••••'; };

/** Where is this request going? */
export function classifySink(rawUrl, pageRegistrable) {
  let u;
  try { u = new URL(rawUrl); } catch { return null; }
  for (const s of SINKS) {
    if (s.host.test(u.hostname) && (!s.path || s.path.test(u.pathname))) {
      return { kind: s.kind, host: u.hostname, en: s.en, ar: s.ar, ...(s.kind === 'telegram' ? { bot: maskBot(u.pathname) } : {}) };
    }
  }
  const reg = splitDomain(u.hostname).registrable;
  if (reg && reg === pageRegistrable) return { kind: 'own_server', host: u.hostname, en: 'the page’s own server', ar: 'خادم الصفحة نفسها' };
  return { kind: 'other_site', host: u.hostname, en: `another website (${u.hostname})`, ar: `موقع آخر (${u.hostname})` };
}

/** Exfiltration endpoints written into the page's code (found even if never triggered). */
export function scanCode(text) {
  const out = [];
  const add = (kind, evidence) => {
    if (out.some(o => o.kind === kind)) return;
    const sk = SINKS.find(x => x.kind === kind);
    out.push({ kind, evidence, en: sk?.en, ar: sk?.ar });
  };
  const s = String(text || '');
  const tok = /api\.telegram\.org\/bot(\d{6,12}):[A-Za-z0-9_-]{20,}/.exec(s);
  if (tok) add('telegram', `bot${tok[1]}:•••• (bot token in the page code)`);
  else if (/api\.telegram\.org\/bot|["'`]sendMessage["'`].{0,80}chat_id|chat_id.{0,80}sendMessage/s.test(s)) add('telegram', 'Telegram bot API call in the page code');
  const dw = /discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks\/(\d+)/.exec(s);
  if (dw) add('discord', `webhook ${dw[1]}`);
  if (/script\.google\.com\/macros\/s\/[\w-]{20,}/.test(s)) add('apps_script', 'script.google.com/macros/…');
  const fs = /(formspree\.io|getform\.io|formsubmit\.co|web3forms\.com|api\.emailjs\.com)/.exec(s);
  if (fs) add('form_service', fs[1]);
  return out;
}

// ---------- tricks the page played ----------
const CMD_RE = /(powershell|pwsh|cmd(\.exe)?\s*\/c|mshta|rundll32|regsvr32|certutil|bitsadmin|curl\s+[^|]*\|\s*(ba)?sh|wget\s+[^|]*\|\s*(ba)?sh|iex\s*\(|invoke-expression|\bsh\s+-c)/i;
export const SCARE_RE = /(virus(es)?\s+(detected|found)|(is|are|been|was)\s+infected|infected\s+with|(phone|device|android|samsung|iphone|system)\s+(is|has been|was)\s+(hacked|infected|damaged|compromised)|battery\s+(is\s+)?(damaged|corrupted)|remove\s+(the\s+)?virus(es)?|clean\s+(your\s+)?(phone|device)\s+now|call\s+(apple|microsoft|google|samsung|windows)\s+support|فيروس|مصاب\s+ب|تم\s+اختراق|اختراق\s+هاتفك|نظّف\s+هاتفك|تنظيف\s+الجهاز)/i;
const REMOTE_RE = /(anydesk|teamviewer|quick\s?support|rustdesk|airdroid|ultraviewer|supremo|ammyy|splashtop|zoho\s?assist|remote\s?(access|control|desktop)\s+app)/i;
const WALLET_RE = /(connect\s+(your\s+)?wallet|seed\s+phrase|recovery\s+phrase|secret\s+phrase|metamask|trust\s?wallet|walletconnect|claim\s+(your\s+)?(airdrop|tokens))/i;
const FEE_RE = /((re-?delivery|customs|delivery|shipping|clearance|processing|unlock|release|activation|verification|small)\s+(fee|charge)|pay\s+(aed|dhs?|usd|\$)\s?\d|(aed|dhs?)\s?\d+[.,]\d{2}\b|رسوم\s+(التوصيل|الشحن|الجمارك|التفعيل))/i;
const PUSH_RE = /(click|press|tap)\s+[“"']?allow[”"']?\s+(to|if)|اضغط\s+[«"]?سماح/i;

export function pageTricks({ events = [], text = '', links = [], dialogs = 0 }) {
  const has = t => events.some(e => e.t === t);
  const clip = events.find(e => e.t === 'clipboard' && e.d);
  const chat = links.filter(l => /^(https?:)?\/\/(wa\.me|api\.whatsapp\.com|chat\.whatsapp\.com|t\.me|telegram\.me)\//i.test(l)).slice(0, 3);
  return {
    clipboardCommand: clip && CMD_RE.test(clip.d) ? clip.d.slice(0, 160) : null,
    clipboard: !!clip,
    scare: SCARE_RE.test(text),
    scareTricks: ['vibrate', 'fullscreen', 'backtrap', 'leavetrap', 'beep'].filter(has).concat(dialogs >= 2 ? ['dialogs'] : []),
    remote: (REMOTE_RE.exec(text) || links.map(l => REMOTE_RE.exec(l)).find(Boolean) || [])[1] || null,
    wallet: WALLET_RE.test(text) || (has('wallet') && /wallet|crypto|token|nft|airdrop/i.test(text)),
    fee: FEE_RE.test(text),
    push: has('notify') && (PUSH_RE.test(text) || /robot|verify|continue|captcha/i.test(text)),
    notify: has('notify'),
    chat,
    camera: has('camera'), location: has('location')
  };
}

// ---------- "what this page wants" ----------
const WANT = {
  install: (apk, trojan) => [`to install an app${apk ? ` (“${apk}”)` : ''} on your phone${trojan ? ' that has a banking trojan’s powers' : ''}`, `أن تثبّت تطبيقاً${apk ? ` («${apk}»)` : ''} على هاتفك${trojan ? ' بصلاحيات حصان طروادة مصرفي' : ''}`],
  card: (a) => [`your card number${a.has('expiry') ? ', expiry date' : ''}${a.has('cvv') ? ' and CVV' : ''}`, `رقم بطاقتك${a.has('expiry') ? ' وتاريخ انتهائها' : ''}${a.has('cvv') ? ' ورمز CVV' : ''}`],
  otp: () => ['the one-time code your bank texts you', 'رمز التحقق الذي يرسله البنك إليك'],
  pin: () => ['your ATM PIN', 'رقمك السري للبطاقة'],
  password: () => ['your login password', 'كلمة مرور حسابك'],
  eid: () => ['your Emirates ID number', 'رقم هويتك الإماراتية'],
  iban: () => ['your IBAN', 'رقم الآيبان'],
  seed: () => ['your crypto wallet’s secret recovery phrase', 'العبارة السرية لمحفظتك الرقمية'],
  remote: (name) => [`you to install a remote-control app (${name}) so they can watch your screen`, `أن تثبّت تطبيق تحكّم عن بُعد (${name}) ليشاهدوا شاشتك`],
  wallet: () => ['you to connect your crypto wallet (so they can drain it)', 'أن تربط محفظتك الرقمية (لإفراغها)'],
  scare: () => ['to scare you with a FAKE virus warning', 'إخافتك بتحذير فيروس مزيّف'],
  clipboard: () => ['to slip a hidden command into your clipboard', 'دسّ أمر خفي في الحافظة لديك'],
  push: () => ['permission to send you notifications (for scam pop-ups later)', 'إذناً بإرسال إشعارات إليك (لنوافذ احتيال لاحقاً)'],
  chat: () => ['to move you into a private WhatsApp / Telegram chat', 'نقلك إلى محادثة خاصة على واتساب أو تيليجرام']
};

export function pageIntent({ asks = new Set(), apk = null, downloads = [], tricks = {}, exfil = [], codeSinks = [] }) {
  const parts = [];
  const push = (id, pair) => parts.push({ id, en: pair[0], ar: pair[1] });
  if (tricks.scare) push('scare', WANT.scare());
  if (downloads.length || apk) push('install_app', WANT.install(apk?.label || downloads[0]?.file, apk?.trojanProfile));
  if (asks.has('card')) push('card', WANT.card(asks));
  if (asks.has('otp')) push('otp', WANT.otp());
  if (asks.has('pin')) push('pin', WANT.pin());
  if (asks.has('password')) push('password', WANT.password());
  if (asks.has('eid')) push('eid', WANT.eid());
  if (asks.has('iban')) push('iban', WANT.iban());
  if (asks.has('seed')) push('seed', WANT.seed());
  if (tricks.remote) push('remote', WANT.remote(tricks.remote));
  if (tricks.wallet && !asks.has('seed')) push('wallet', WANT.wallet());
  if (tricks.clipboardCommand) push('clipboard', WANT.clipboard());
  if (tricks.push) push('push', WANT.push());
  if (tricks.chat?.length) push('chat', WANT.chat());
  if (!parts.length) return null;

  const fee = tricks.fee && asks.has('card');
  const money = asks.has('card') && (asks.has('cvv') || asks.has('otp')) || asks.has('pin');
  const takeover = asks.has('otp') && (asks.has('password') || asks.has('eid'));
  const join = (xs, and) => xs.length < 2 ? xs[0] : xs.slice(0, -1).join(', ') + ` ${and} ` + xs[xs.length - 1];
  const tailEn = money ? ', enough to spend your money' : takeover ? ', enough to take over your account' : '';
  const tailAr = money ? '، وهذا يكفي لصرف أموالك' : takeover ? '، وهذا يكفي للاستيلاء على حسابك' : '';
  const listEn = join(parts.slice(0, 4).map(p => p.en), 'and'), listAr = join(parts.slice(0, 4).map(p => p.ar), 'و');
  const en = fee ? `It asks for a small “fee”, but what this page really wants is ${listEn}${tailEn}.` : `This page wants ${listEn}${tailEn}.`;
  const ar = fee ? `تطلب «رسوماً» صغيرة، لكن ما تريده هذه الصفحة فعلاً هو ${listAr}${tailAr}.` : `هذه الصفحة تريد ${listAr}${tailAr}.`;
  const dest = exfil.find(e => !['own_server', 'other_site'].includes(e.kind)) || exfil[0] || null;
  const code = !dest && codeSinks[0];
  return {
    goals: (fee ? ['fee'] : []).concat(parts.map(p => p.id)), en, ar,
    sendsTo: dest ? { kind: dest.kind, host: dest.host, en: `What you type is sent to ${dest.en}. Veto caught it with fake details and blocked it.`,
      ar: `ما تكتبه يُرسل إلى ${dest.ar}. اكتشف فيتو ذلك ببيانات مزيّفة ومنع الإرسال.` }
      : code ? { kind: code.kind, en: `The page’s code contains ${code.en} (${code.evidence}).`, ar: `شيفرة الصفحة تحتوي على ${code.ar}.` } : null
  };
}
