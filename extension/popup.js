// Veto.ai popup: the verdict for the open website, and a box to check any message or link.
const T = {
  settings: { en: 'Settings', ar: 'الإعدادات' }, thisSite: { en: 'This website', ar: 'هذا الموقع' }, checking: { en: 'Checking…', ar: 'جارٍ الفحص…' },
  pasteLabel: { en: 'Check a message or link', ar: 'افحص رسالة أو رابطاً' }, check: { en: 'Check', ar: 'افحص' }, askAi: { en: 'Ask the AI too', ar: 'اسأل الذكاء الاصطناعي أيضاً' },
  privacy: { en: 'Checks run on this computer. Nothing is sent anywhere unless you turn on online checks or the AI in Settings.', ar: 'يتم الفحص على هذا الجهاز. لا يُرسل شيء إلا إذا فعّلت الفحص عبر الإنترنت أو الذكاء الاصطناعي في الإعدادات.' },
  placeholder: { en: 'Paste a text, WhatsApp message, e-mail or link you received', ar: 'الصق رسالة نصية أو رسالة واتساب أو بريداً أو رابطاً وصلك' },
  noPage: { en: 'Not a website (a browser page or a file).', ar: 'ليست صفحة ويب (صفحة متصفح أو ملف).' },
  trusted: { en: 'You chose to trust this site.', ar: 'اخترت الوثوق بهذا الموقع.' },
  online: { en: 'Also checked online through your Veto server.', ar: 'تم الفحص عبر خادم Veto أيضاً.' },
  outScope: { en: 'The rules read English and Arabic only, so this message needs the AI check.', ar: 'القواعد تقرأ العربية والإنجليزية فقط، لذا تحتاج هذه الرسالة إلى فحص الذكاء الاصطناعي.' },
  aiOff: { en: 'Turn on the AI in Settings (your Veto server or a Groq key) to translate and check it.', ar: 'فعّل الذكاء الاصطناعي من الإعدادات (خادم Veto أو مفتاح Groq) لترجمتها وفحصها.' },
  aiSays: { en: 'AI second opinion', ar: 'رأي الذكاء الاصطناعي' }, aiErr: { en: 'The AI check did not answer', ar: 'لم يُجب فحص الذكاء الاصطناعي' },
  translation: { en: 'Translation', ar: 'الترجمة' }, links: { en: 'Links in it', ar: 'الروابط فيها' }, whatToDo: { en: 'What to do', ar: 'ماذا تفعل' },
  smsModel: { en: 'On-device text model', ar: 'نموذج النصوص على الجهاز' }, flagged: { en: 'flags it', ar: 'يصنّفها مشبوهة' }, notFlagged: { en: 'does not flag it', ar: 'لا يصنّفها مشبوهة' },
  empty: { en: 'Paste something first.', ar: 'الصق شيئاً أولاً.' },
};
const V = {
  phishing: ['v-red', { en: 'Scam site', ar: 'موقع احتيالي' }], suspicious: ['v-amber', { en: 'Suspicious', ar: 'مشبوه' }],
  legitimate: ['v-green', { en: 'No scam signs found', ar: 'لا علامات احتيال' }], official: ['v-green', { en: 'Official site', ar: 'موقع رسمي' }],
  scam: ['v-red', { en: 'Scam', ar: 'احتيال' }], high: ['v-red', { en: 'Very likely a scam', ar: 'على الأرجح احتيال' }],
  caution: ['v-amber', { en: 'Be careful', ar: 'انتبه' }], otp: ['v-blue', { en: 'One-time code: never share it', ar: 'رمز لمرة واحدة: لا تشاركه' }],
  clear: ['v-green', { en: 'No scam signs found', ar: 'لا علامات احتيال' }], invalid: ['v-grey', { en: 'Not a web address', ar: 'ليس عنواناً' }],
};
const SRC = { rule: { en: 'rule', ar: 'قاعدة' }, model: { en: 'URL model', ar: 'نموذج الروابط' }, allowlist: { en: 'official list', ar: 'القائمة الرسمية' },
  popularity: { en: 'popularity', ar: 'الانتشار' }, bucket_layer: { en: 'storage check', ar: 'فحص التخزين' }, online_check: { en: 'online check', ar: 'فحص مباشر' },
  feed: { en: 'threat feed', ar: 'قائمة تهديدات' }, input: { en: 'input', ar: 'المدخل' }, ai: { en: 'AI', ar: 'الذكاء الاصطناعي' } };

let lang = 'en';
let last = null; let lastTab = null;
const $ = id => document.getElementById(id);
const send = msg => new Promise(res => chrome.runtime.sendMessage(msg, r => { void chrome.runtime.lastError; res(r); }));
const t = k => (T[k] ? T[k][lang] : k);
function h(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) e.setAttribute(k, v);
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k.nodeType ? k : String(k));
  return e;
}
const pill = key => { const [cls, txt] = V[key] || V.invalid; return h('span', { class: `pill ${cls}` }, txt[lang]); };

function applyLang() {
  document.documentElement.lang = lang;
  document.body.dir = lang === 'ar' ? 'rtl' : 'ltr';
  $('lang').textContent = lang === 'ar' ? 'English' : 'عربي';
  for (const el of document.querySelectorAll('[data-t]')) el.textContent = t(el.dataset.t);
  $('input').placeholder = t('placeholder');
  renderTab(lastTab);
  if (last) renderResult(last);
}

function renderTab(r) {
  const box = $('tab');
  box.replaceChildren(h('div', { class: 'label' }, t('thisSite')));
  if (r === undefined) { box.append(h('div', { class: 'muted' }, t('checking'))); return; }
  if (!r) { box.append(h('div', { class: 'muted' }, t('noPage'))); return; }
  box.append(h('div', { class: 'row' }, pill(r.official ? 'official' : r.verdict)), h('div', { class: 'host' }, r.host || r.url));
  const reasons = (r.reasons || []).slice(0, 3);
  if (reasons.length) box.append(h('ul', { class: 'reasons' }, reasons.map(x => h('li', {}, x[lang] || x.en, x.src ? h('span', { class: 'src' }, ` · ${(SRC[x.src] || {})[lang] || x.src}`) : null))));
  if (r.trusted) box.append(h('div', { class: 'muted' }, t('trusted')));
  if (r.online) box.append(h('div', { class: 'muted' }, t('online')));
}

function renderResult(r) {
  last = r;
  const box = $('result');
  box.hidden = false;
  box.replaceChildren();
  if (r.kind === 'url') {
    box.append(h('div', { class: 'row' }, pill(r.layers?.official || r.layers?.restricted ? 'official' : r.verdict)), h('div', { class: 'host' }, r.host || r.url));
    box.append(h('ul', { class: 'reasons' }, (r.reasons || []).slice(0, 4).map(x => h('li', {}, x[lang] || x.en, x.src ? h('span', { class: 'src' }, ` · ${(SRC[x.src] || {})[lang] || x.src}`) : null))));
    $('askAi').hidden = true;
    return;
  }
  box.append(h('div', { class: 'row' }, pill(r.verdict)));
  if (r.findings?.length) box.append(h('ul', { class: 'reasons' }, r.findings.slice(0, 4).map(f => h('li', {}, f[lang] || f.en))));
  if (r.links?.length) {
    box.append(h('div', { class: 'label' }, t('links')));
    for (const l of r.links) box.append(h('div', { class: 'row' }, pill(l.official ? 'official' : l.verdict), h('span', { class: 'host' }, l.host)));
  }
  box.append(h('div', { class: 'muted' }, `${t('smsModel')} ${r.sms?.flag ? t('flagged') : t('notFlagged')}.`));
  if (r.scope && !r.scope.inScope) box.append(h('div', { class: 'muted' }, t('outScope')));
  if (r.ai) {
    const ai = h('div', { class: 'ai' });
    if (r.ai.off) ai.append(h('div', { class: 'muted' }, t('aiOff')));
    else if (r.ai.error) ai.append(h('div', { class: 'muted' }, `${t('aiErr')}: ${r.ai.error}`));
    else {
      ai.append(h('div', { class: 'label' }, `${t('aiSays')} · ${r.ai.provider || ''}`));
      if (r.ai.translation_en) ai.append(h('div', {}, h('b', {}, `${t('translation')} (${r.ai.language || '?'}): `), r.ai.translation_en));
      const ex = lang === 'ar' ? r.ai.explanation_ar : r.ai.explanation_en;
      if (ex) ai.append(h('div', {}, ex));
      ai.append(h('div', { class: 'muted' }, `risk ${Math.round((r.ai.risk || 0) * 100)}%`));
    }
    box.append(ai);
  }
  if (r.next?.length) box.append(h('div', { class: 'label' }, t('whatToDo')), h('ul', { class: 'next' }, r.next.slice(0, 3).map(n => h('li', {}, n[lang] || n.en))));
  $('askAi').hidden = !!(r.ai && !r.ai.error && !r.ai.off);
}

async function run(ai) {
  const input = $('input').value.trim();
  if (!input) { $('status').textContent = t('empty'); return; }
  $('status').textContent = t('checking');
  $('check').disabled = true; $('askAi').disabled = true;
  const r = await send({ type: 'veto:check', input, ai });
  $('check').disabled = false; $('askAi').disabled = false;
  $('status').textContent = '';
  if (r && !r.error) renderResult(r); else $('status').textContent = r?.error || 'error';
}

$('check').addEventListener('click', () => run('auto'));
$('askAi').addEventListener('click', () => run('force'));
$('input').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) run('auto'); });
$('opts').addEventListener('click', () => chrome.runtime.openOptionsPage());
$('lang').addEventListener('click', async () => { lang = lang === 'en' ? 'ar' : 'en'; await chrome.storage.local.set({ lang }); applyLang(); });

(async () => {
  try { lang = (await chrome.storage.local.get('lang')).lang || 'en'; } catch { /* default English */ }
  renderTab(undefined);
  applyLang();
  lastTab = await send({ type: 'veto:tab' });
  renderTab(lastTab);
  const lc = await send({ type: 'veto:last' });
  if (lc?.result) { $('input').value = lc.input; renderResult(lc.result); }
})();
