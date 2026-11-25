// Veto.ai Live Check: the shared engine (engine/judge-core.js, engine/textcheck.js) in the browser. No network calls
// except loading this page's own model files.
import { setUrlml2Source } from './engine/urlml2-core.js';
import { judgeOffline } from './engine/judge-core.js';
import { checkMessage } from './engine/textcheck.js';

const $ = id => document.getElementById(id);
let lang = 'en';
const EX = {
  police: '【Dubai Police】Your ETC toll has been converted into a fine due to payment failure and is currently unpaid. Please log in to the official website to check the details and pay immediately to avoid additional fees. Official website: https://cutt.ly/vrx69lP5?NoH=MzOKi9',
  job: 'Hi! I got your number from the UAE jobs group. Simple online tasks, AED 800 to 1,500 daily. Register here to get your first task: https://talenthub-dubai-task.top/join and pay the AED 99 activation fee today. Then send me the OTP you receive so I can activate your account.',
  bank: 'http://adcb-secure-verify.top/login',
  otp: 'Your verification code is 482913. Do not share this code with anyone. It expires in 5 minutes.',
  list: 'https://www.adcb.com/en/personal/\nhttp://emiratesnbd-secure-login.xyz/verify\nhttps://u.ae/en/information-and-services\nhxxps://salik-fine-pay[.]com/fine\nhttps://adnco.ae/\nhttps://www.emiratespost.ae/\nbit.ly/4gNyTTh\nhttps://wwwadnoc.com/rewards',
  official: 'https://www.adcb.com/en/personal/accounts/',
};
const T = {
  check: { en: 'Check', ar: 'افحص' }, other: { en: 'عربي', ar: 'English' }, links: { en: 'Links in it', ar: 'الروابط فيه' }, todo: { en: 'What to do', ar: 'ماذا تفعل' },
  sms: { en: 'On-device text model', ar: 'نموذج النصوص على الجهاز' }, flags: { en: 'flags it', ar: 'يصنّفها مشبوهة' }, noflag: { en: 'does not flag it', ar: 'لا يصنّفها مشبوهة' },
  batch: { en: 'links judged', ar: 'روابط تم فحصها' }, copy: { en: 'Copy as CSV', ar: 'نسخ بصيغة CSV' },
};
const V = { scam: ['red', 'Scam', 'احتيال'], high: ['red', 'Very likely a scam', 'على الأرجح احتيال'], caution: ['amber', 'Be careful', 'انتبه'],
  otp: ['blue', 'One-time code: never share it', 'رمز لمرة واحدة: لا تشاركه'], clear: ['green', 'No scam signs found', 'لا علامات احتيال'],
  phishing: ['red', 'Scam site', 'موقع احتيالي'], suspicious: ['amber', 'Suspicious', 'مشبوه'], legitimate: ['green', 'No scam signs found', 'لا علامات احتيال'],
  official: ['green', 'Official site', 'موقع رسمي'], invalid: ['blue', 'Not a web address', 'ليس عنواناً'] };
const t = k => T[k][lang];
const h = (tag, attrs = {}, ...kids) => { const e = document.createElement(tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : String(c)); return e; };
const pill = k => { const [c, en, ar] = V[k] || V.invalid; return h('span', { class: `pill ${c}` }, lang === 'ar' ? ar : en); };
const urlKey = r => (r.layers?.official || r.layers?.restricted ? 'official' : r.verdict);

const ready = (async () => {
  const [model, tranco] = await Promise.all([fetch('data/urlml2-model.json').then(r => r.json()), fetch('data/tranco-top100k.txt').then(r => r.text())]);
  setUrlml2Source({ model: () => model, tranco: () => tranco });
})();
ready.then(() => { $('status').textContent = ''; run(); }, () => { $('status').textContent = 'The link model could not load; the rules still run.'; });

const LINK = /^\s*\S+\.\S{2,}\s*$/;
let last = null;
function run() {
  const input = $('input').value.trim();
  if (!input) return;
  const lines = input.split(/\n+/).map(s => s.trim()).filter(Boolean);
  if (lines.length > 1 && lines.every(l => LINK.test(l) && !/\s/.test(l))) last = { kind: 'batch', rows: lines.slice(0, 500).map(u => judgeOffline(u)) };
  else if (lines.length === 1 && LINK.test(input) && !/\s/.test(input)) last = { kind: 'url', r: judgeOffline(input) };
  else last = { kind: 'text', r: checkMessage(input, { channel: 'pasted' }) };
  render();
}
function render() {
  if (!last) return;
  const box = $('result'); box.hidden = false; box.replaceChildren(); box.dir = lang === 'ar' ? 'rtl' : 'ltr';
  if (last.kind === 'batch') {
    const tb = h('tbody');
    for (const r of last.rows) tb.append(h('tr', {}, h('td', { class: 'host' }, r.url), h('td', {}, pill(urlKey(r))), h('td', {}, r.score == null ? '' : r.score.toFixed(2)), h('td', {}, ((r.reasons || []).find(x => x.w > 0) || r.reasons?.[0] || {})[lang] || '')));
    box.append(h('div', { class: 'label' }, `${last.rows.length} ${t('batch')}`), h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'URL'), h('th', {}, 'Verdict'), h('th', {}, 'Score'), h('th', {}, 'Main reason'))), tb)));
    const b = h('button', { type: 'button' }, t('copy'));
    b.addEventListener('click', () => { const csv = 'url,verdict,score\n' + last.rows.map(r => `"${r.url.replace(/"/g, '""')}",${r.verdict},${r.score ?? ''}`).join('\n'); navigator.clipboard?.writeText(csv).catch(() => {}); });
    box.append(h('div', { class: 'row' }, b));
    return;
  }
  if (last.kind === 'url') {
    const r = last.r;
    box.append(h('div', { class: 'row' }, pill(urlKey(r)), h('span', { class: 'host' }, r.host || r.url)));
    box.append(h('ul', { class: 'reasons' }, (r.reasons || []).slice(0, 5).map(x => h('li', {}, x[lang] || x.en, x.src ? h('span', { class: 'src' }, ` · ${x.src}`) : null))));
    return;
  }
  const r = last.r;
  box.append(h('div', { class: 'row' }, pill(r.verdict)));
  if (r.findings?.length) box.append(h('ul', { class: 'reasons' }, r.findings.slice(0, 5).map(f => h('li', {}, f.title?.[lang] || f.title?.en || ''))));
  if (r.judgedLinks?.length) {
    box.append(h('div', { class: 'label' }, t('links')));
    for (const l of r.judgedLinks) box.append(h('div', { class: 'row' }, pill(l.official ? 'official' : l.verdict), h('span', { class: 'host' }, l.host)));
  }
  box.append(h('div', { class: 'muted' }, `${t('sms')} ${r.sms?.flag ? t('flags') : t('noflag')}.`));
  if (r.next?.length) box.append(h('div', { class: 'label' }, t('todo')), h('ul', { class: 'reasons' }, r.next.slice(0, 3).map(n => h('li', {}, n[lang] || n.en))));
}
$('check').addEventListener('click', () => ready.then(run, run));
$('input').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) ready.then(run, run); });
$('lang').addEventListener('click', () => { lang = lang === 'en' ? 'ar' : 'en'; $('lang').textContent = t('other'); $('check').textContent = t('check'); render(); });
for (const b of document.querySelectorAll('[data-ex]')) b.addEventListener('click', () => { $('input').value = EX[b.dataset.ex]; ready.then(run, run); });
