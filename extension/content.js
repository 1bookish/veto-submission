// Veto.ai page script. Two jobs, both drawn inside a closed shadow root so a page cannot restyle or read them:
//  1. a warning on a site the background worker judged a scam (full screen) or suspicious (a bar at the top);
//  2. on messaging sites (WhatsApp Web, Google Messages, Telegram, Gmail, Outlook), a small label under each message
//     that the message check flags. The text is checked by the background worker on this computer.
(() => {
  if (window.top !== window || window.__vetoLoaded) return;
  window.__vetoLoaded = true;

  const T = {
    scamTitle: { en: 'Veto.ai: this site looks like a scam', ar: 'Veto.ai: يبدو أن هذا الموقع احتيالي' },
    scamBody: { en: 'Do not type passwords, card numbers or codes here.', ar: 'لا تكتب كلمات مرور أو أرقام بطاقات أو رموزاً هنا.' },
    suspTitle: { en: 'Veto.ai: be careful on this site', ar: 'Veto.ai: انتبه في هذا الموقع' },
    leave: { en: 'Leave this site', ar: 'غادر هذا الموقع' },
    trust: { en: 'I trust this site', ar: 'أثق بهذا الموقع' },
    once: { en: 'Continue this time', ar: 'متابعة هذه المرة' },
    close: { en: 'Close', ar: 'إغلاق' },
    other: { en: 'عربي', ar: 'English' },
    report: { en: 'Report scams: Abu Dhabi Police Aman 800 2626, Dubai Police ecrime.ae', ar: 'للإبلاغ: شرطة أبوظبي أمان 800 2626، شرطة دبي ecrime.ae' },
    online: { en: 'Checked online too', ar: 'تم الفحص عبر الإنترنت أيضاً' },
  };
  const VERDICT = {
    scam: { en: 'Scam', ar: 'احتيال', c: 'red' }, high: { en: 'Very likely a scam', ar: 'على الأرجح احتيال', c: 'red' },
    caution: { en: 'Be careful', ar: 'انتبه', c: 'amber' }, otp: { en: 'One-time code: never share it', ar: 'رمز لمرة واحدة: لا تشاركه أبداً', c: 'blue' },
  };
  const CSS = `
    :host { all: initial; }
    .wrap { font: 15px/1.45 "Segoe UI", system-ui, -apple-system, Roboto, "Noto Sans Arabic", Tahoma, sans-serif; color: #0d1b2e; }
    .full { position: fixed; inset: 0; z-index: 2147483647; background: rgba(13, 27, 46, .86); display: flex; align-items: center; justify-content: center; padding: 16px; }
    .card { background: #fff; border-radius: 20px; max-width: 560px; width: 100%; box-shadow: 0 24px 60px rgba(0,0,0,.35); overflow: hidden; }
    .head { background: #c62a1f; color: #fff; padding: 18px 22px; display: flex; gap: 12px; align-items: center; }
    .head.amber { background: #b54708; }
    .head h1 { font-size: 19px; margin: 0; font-weight: 700; flex: 1; }
    .badge { font-size: 12px; border: 1px solid rgba(255,255,255,.6); border-radius: 999px; padding: 2px 10px; background: transparent; color: #fff; cursor: pointer; }
    .body { padding: 18px 22px 8px; }
    .host { font-family: ui-monospace, Consolas, monospace; font-size: 14px; background: #fef3f2; color: #912018; border: 1px solid #fecdca; border-radius: 10px; padding: 6px 10px; word-break: break-all; }
    ul { margin: 12px 0 4px; padding-inline-start: 20px; } li { margin: 6px 0; }
    .src { color: #667085; font-size: 12px; }
    .note { color: #4a5a72; font-size: 13px; margin: 10px 0 0; }
    .row { display: flex; flex-wrap: wrap; gap: 10px; padding: 14px 22px 20px; }
    button.b { font: inherit; border-radius: 12px; padding: 10px 16px; cursor: pointer; border: 1px solid #d3ddeb; background: #f3f6fb; color: #0d1b2e; }
    button.b.primary { background: #c62a1f; border-color: #c62a1f; color: #fff; font-weight: 600; }
    .bar { position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647; background: #fffaeb; border-bottom: 2px solid #b54708; color: #7a2e0e;
      display: flex; gap: 12px; align-items: center; padding: 10px 16px; box-shadow: 0 4px 14px rgba(0,0,0,.12); }
    .bar b { color: #93370d; } .bar .grow { flex: 1; min-width: 0; }
    .bar button.b { padding: 6px 12px; }
    [dir=rtl] { text-align: right; }
  `;

  let lang = 'en';
  // remembered for this tab only; some pages block storage, so every access is guarded
  const once = { has: () => { try { return sessionStorage.getItem('veto-once:' + location.host) === '1'; } catch { return false; } },
    set: () => { try { sessionStorage.setItem('veto-once:' + location.host, '1'); } catch { /* blocked: the warning simply comes back */ } } };
  const tr = (k, l = lang) => (T[k] ? T[k][l] : k);

  // ---- 1. page warning -------------------------------------------------------------------------------------------------
  let host = null;
  function mount() {
    if (host) host.remove();
    host = document.createElement('veto-warning');
    const root = host.attachShadow({ mode: 'closed' });
    (document.documentElement || document).appendChild(host);
    const style = document.createElement('style');
    style.textContent = CSS;
    root.appendChild(style);
    return root;
  }
  function el(tag, attrs = {}, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) { if (k === 'on') e.addEventListener('click', v); else if (v != null) e.setAttribute(k, v); }
    for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : String(k));
    return e;
  }
  const send = msg => new Promise(res => { try { chrome.runtime.sendMessage(msg, r => { void chrome.runtime.lastError; res(r); }); } catch { res(null); } });

  let shown = false, shownVerdict = null;
  function showPage(r) {
    if (!r || (r.verdict !== 'phishing' && r.verdict !== 'suspicious')) return;
    if (once.has()) return;
    if (shown && host?.isConnected && shownVerdict === r.verdict) return; // already on screen
    shown = true; shownVerdict = r.verdict;
    const draw = () => {
      const root = mount();
      const reasons = (r.reasons || []).filter(x => x.w > 0).slice(0, 3);
      const list = el('ul', {}, reasons.map(x => el('li', {}, x[lang] || x.en)));
      const flip = el('button', { class: 'badge', on: () => { lang = lang === 'en' ? 'ar' : 'en'; draw(); } }, tr('other'));
      if (r.verdict === 'phishing') {
        root.appendChild(el('div', { class: 'wrap full', dir: lang === 'ar' ? 'rtl' : 'ltr' },
          el('div', { class: 'card', role: 'alertdialog', 'aria-label': tr('scamTitle') },
            el('div', { class: 'head' }, el('h1', {}, tr('scamTitle')), flip),
            el('div', { class: 'body' }, el('div', { class: 'host' }, r.host || location.host), list, el('p', {}, tr('scamBody')),
              r.online ? el('p', { class: 'src' }, tr('online')) : null, el('p', { class: 'note' }, tr('report'))),
            el('div', { class: 'row' },
              el('button', { class: 'b primary', on: () => send({ type: 'veto:leave' }) }, tr('leave')),
              el('button', { class: 'b', on: () => { once.set(); host.remove(); } }, tr('once')),
              el('button', { class: 'b', on: () => { send({ type: 'veto:trust', host: r.host }); host.remove(); } }, tr('trust'))))));
      } else {
        root.appendChild(el('div', { class: 'wrap bar', dir: lang === 'ar' ? 'rtl' : 'ltr', role: 'status' },
          el('div', { class: 'grow' }, el('b', {}, tr('suspTitle')), ' ', reasons[0] ? (reasons[0][lang] || reasons[0].en) : ''),
          el('button', { class: 'b', on: () => { lang = lang === 'en' ? 'ar' : 'en'; draw(); } }, tr('other')),
          el('button', { class: 'b', on: () => { send({ type: 'veto:trust', host: r.host }); host.remove(); } }, tr('trust')),
          el('button', { class: 'b', on: () => { once.set(); host.remove(); }, 'aria-label': tr('close') }, '×')));
      }
    };
    draw();
  }
  chrome.runtime.onMessage.addListener(msg => {
    if (msg?.type === 'veto:page') { lang = msg.lang || lang; showPage(msg.result); }
  });
  // ask now, and again when the page has loaded, in case the verdict was not ready yet
  const ask = () => { if (!shown) send({ type: 'veto:pageResult' }).then(x => { if (x?.result && !shown) { lang = x.lang || lang; showPage(x.result); } }); };
  ask();
  document.addEventListener('DOMContentLoaded', ask, { once: true });
  window.addEventListener('load', ask, { once: true });

  // ---- 2. messages on messaging sites -------------------------------------------------------------------------------------
  const MSG = {
    'web.whatsapp.com': '[data-pre-plain-text]',
    'messages.google.com': 'mws-text-message-part, .text-msg-content',
    'web.telegram.org': '.translatable-message, .text-content, .message .text',
    'mail.google.com': 'div.a3s',
    'outlook.live.com': '[aria-label="Message body"]',
    'outlook.office.com': '[aria-label="Message body"]',
    'outlook.office365.com': '[aria-label="Message body"]',
  };
  const selector = MSG[location.hostname];
  if (!selector) return;
  const LABEL = {
    red: 'background:#fef3f2;color:#912018;border:1px solid #fecdca',
    amber: 'background:#fffaeb;color:#7a2e0e;border:1px solid #fedf89',
    blue: 'background:#eff6ff;color:#1849a9;border:1px solid #c7dcff',
  };
  const seen = new WeakSet();
  const queue = [];
  let busy = false;
  function label(target, res) {
    const v = VERDICT[res.verdict];
    if (!v) return;
    const why = res.findings?.[0] ? (res.findings[0][lang] || res.findings[0].en) : '';
    const tag = document.createElement('div');
    tag.setAttribute('data-veto-label', '1');
    tag.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
    tag.style.cssText = `${LABEL[v.c]};border-radius:10px;padding:6px 10px;margin:6px 0 2px;font:13px/1.4 "Segoe UI",system-ui,sans-serif;max-width:520px;white-space:normal`;
    tag.textContent = `Veto.ai · ${v[lang]}${why ? ': ' + why : ''}${res.ai?.translation_en ? `  (${res.ai.language || 'translated'}: “${res.ai.translation_en.slice(0, 140)}”)` : ''}`;
    target.insertAdjacentElement('afterend', tag);
  }
  async function pump() {
    if (busy) return;
    busy = true;
    while (queue.length) {
      const target = queue.shift();
      if (!target.isConnected) continue;
      const text = (target.innerText || '').trim();
      if (text.length < 12 || text.length > 8000) continue;
      const res = await send({ type: 'veto:checkText', text, channel: location.hostname });
      if (res && !res.error) label(target, res);
      await new Promise(r => setTimeout(r, 60));
    }
    busy = false;
  }
  function scan() {
    for (const m of document.querySelectorAll(selector)) {
      if (seen.has(m) || m.closest('[data-veto-label]') || m.closest('.message-out')) continue;
      seen.add(m);
      queue.push(m);
    }
    pump();
  }
  send({ type: 'veto:scanOn' }).then(x => {
    if (!x?.on) return;
    lang = x.lang || lang;
    let t = null;
    const start = () => {
      scan();
      new MutationObserver(() => { clearTimeout(t); t = setTimeout(scan, 400); }).observe(document.documentElement, { childList: true, subtree: true });
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true }); else start();
  });
})();
