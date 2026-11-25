// Veto URL Judge page: paste or upload a list of URLs (optionally labelled) and get a verdict, a score and the reasons
// for each one, plus precision / recall / false alarms when labels are given. Offline by default (nothing leaves the
// Veto server); "online" also follows redirects and short links, checks domain age, registry holds and the page.
import { icon } from './icons.js';

const store = { get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* private */ } } };
const S = { lang: store.get('veto.lang', 'en'), online: false, busy: false, res: null, filter: 'all', text: '' };
const TX = {
  en: {
    tagline: 'URL Judge', title: 'Judge a list of links', help: 'Paste URLs (one per line) or upload a .txt / .csv file. A CSV can have a “url” column and a “label” column (1 / 0, phishing / legitimate): Veto then shows precision, recall and false alarms. Every verdict comes with its reasons.',
    placeholder: 'https://example.com/login\nhttps://www.emiratesnbd.com/en\n…\n\nor CSV:\nurl,label\nhttps://rta-fines-pay.top/ae,1\nhttps://www.rta.ae,0',
    upload: 'Upload file', sample: 'Load a sample', online: 'Online checks', onlineHelp: 'Follow redirects and short links, check domain age, registry holds, the landing page and known-phishing feeds. Sends each URL to its own site and to RDAP.',
    offlineHelp: 'Offline: nothing leaves this server. About 1 ms per URL.', run: 'Judge them', running: 'Judging…', results: 'Results', download: 'Download CSV',
    phishing: 'phishing', suspicious: 'suspicious', legitimate: 'legitimate', invalid: 'invalid', all: 'All', strict: 'Flagged = phishing', cautious: 'Flagged = phishing or suspicious',
    precision: 'Precision', recall: 'Recall', f1: 'F1', fpr: 'False alarms', acc: 'Accuracy', urls: 'URLs', perSec: 'URLs/s', model: 'Model', label: 'label', score: 'score', why: 'why',
    tp: 'caught', fp: 'false alarms', fn: 'missed', tn: 'cleared', noLabels: 'No labels in the input: add a “label” column to see precision and recall.', empty: 'Paste at least one URL.'
  },
  ar: {
    tagline: 'حَكَم الروابط', title: 'احكم على قائمة روابط', help: 'الصق الروابط (رابط في كل سطر) أو ارفع ملف ‎.txt / .csv. يمكن أن يحتوي ملف CSV على عمود «url» وعمود «label» (1 / 0): عندها يعرض فيتو الدقة والاستدعاء والإنذارات الكاذبة. كل حكم يأتي مع أسبابه.',
    placeholder: 'https://example.com/login\nhttps://www.emiratesnbd.com/en\n…',
    upload: 'ارفع ملفاً', sample: 'حمّل مثالاً', online: 'فحوص عبر الإنترنت', onlineHelp: 'يتتبع التحويلات والروابط المختصرة، ويفحص عمر النطاق وتعليقه والصفحة وقوائم الاحتيال المعروفة. يرسل كل رابط إلى موقعه وإلى RDAP.',
    offlineHelp: 'دون اتصال: لا يغادر شيء هذا الخادم. نحو 1 ملّي ثانية لكل رابط.', run: 'احكم عليها', running: 'جارٍ الحكم…', results: 'النتائج', download: 'نزّل CSV',
    phishing: 'احتيال', suspicious: 'مشبوه', legitimate: 'سليم', invalid: 'غير صالح', all: 'الكل', strict: 'المُعلَّم = احتيال', cautious: 'المُعلَّم = احتيال أو مشبوه',
    precision: 'الدقة', recall: 'الاستدعاء', f1: 'F1', fpr: 'إنذارات كاذبة', acc: 'الصحة', urls: 'رابط', perSec: 'رابط/ث', model: 'النموذج', label: 'التصنيف', score: 'الدرجة', why: 'لماذا',
    tp: 'تم كشفه', fp: 'إنذار كاذب', fn: 'فات', tn: 'سليم صحيح', noLabels: 'لا توجد تصنيفات: أضف عمود «label» لرؤية الدقة والاستدعاء.', empty: 'الصق رابطاً واحداً على الأقل.'
  }
};
const T = k => TX[S.lang][k] ?? TX.en[k] ?? k;
const L = o => (o == null ? '' : typeof o === 'string' ? o : o[S.lang] ?? o.en ?? '');
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
const app = document.getElementById('app');
// illustrative sample: official sites, popular sites, and made-up phishing-style addresses (not live sites)
const SAMPLE = `url,label
https://www.emiratesnbd.com/en/personal-banking,0
https://www.rta.ae/wps/portal/rta/ae/home,0
https://tamm.abudhabi/en/aspects-of-life,0
https://www.adpolice.gov.ae/en/services,0
https://u.ae/en/information-and-services/justice-safety-and-the-law,0
https://www.wikipedia.org/,0
https://github.com/login,0
https://www.amazon.ae/gp/cart/view.html,0
https://rta-fines-pay.top/ae/violations/pay.php,1
http://emiratesnbd-secure-verify.top/login.php?email=user@example.com,1
https://uaepass-login-update.online/auth/verify,1
https://salik-recharge-uae.com/topup/card,1
http://adcb.com-account-security.xyz/signin,1
https://emiratespost-redelivery.shop/customs-fee?id=AE99812,1
https://sites.google.com/view/adpolice-fines-payment/home,1
http://192.0.2.44/aramex/track/confirm.php,1`;

function render() {
  document.documentElement.lang = S.lang; document.documentElement.dir = S.lang === 'ar' ? 'rtl' : 'ltr';
  document.getElementById('tagline').textContent = T('tagline');
  document.getElementById('langBtn').textContent = S.lang === 'ar' ? 'EN' : 'ع';
  const ta = h('textarea', { rows: 9, dir: 'ltr', placeholder: T('placeholder'), class: 'judge-input', oninput: e => { S.text = e.target.value; } });
  ta.value = S.text;
  const file = h('input', { type: 'file', accept: '.txt,.csv,.tsv', hidden: true, onchange: async e => { const f = e.target.files[0]; if (f) { S.text = await f.text(); render(); } } });
  app.replaceChildren(
    h('section', { class: 'card' },
      h('h2', { class: 'section-title' }, icon('scan-search'), T('title')), h('p', { class: 'muted small' }, T('help')),
      ta,
      h('div', { class: 'hunt-row' },
        h('button', { class: 'ghost small', type: 'button', onclick: () => file.click() }, icon('upload'), T('upload')), file,
        h('button', { class: 'ghost small', type: 'button', onclick: () => { S.text = SAMPLE; render(); } }, icon('file-text'), T('sample')),
        h('label', { class: 'kind' }, h('input', { type: 'checkbox', checked: S.online, onchange: e => { S.online = e.target.checked; render(); } }), T('online')),
        h('span', { class: 'grow' }),
        h('button', { class: 'primary', type: 'button', disabled: S.busy, onclick: run }, icon(S.busy ? 'refresh-cw' : 'play'), S.busy ? T('running') : T('run'))),
      h('p', { class: 'tiny muted' }, S.online ? T('onlineHelp') : T('offlineHelp'))),
    S.res ? resultsView() : '');
}

async function run() {
  if (!S.text.trim()) { alert(T('empty')); return; }
  S.busy = true; render();
  const t0 = performance.now();
  try {
    const r = await fetch('/api/v1/judge', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: S.text, online: S.online }) });
    S.res = await r.json();
    S.res.seconds = (performance.now() - t0) / 1000;
  } catch (e) { S.res = { error: String(e) }; }
  S.busy = false; render();
}

function metricCard(m, title) {
  const pct = x => `${(x * 100).toFixed(1)}%`;
  return h('div', { class: 'jm' }, h('div', { class: 'jm-title' }, title),
    h('div', { class: 'jm-grid' },
      [['precision', m.precision], ['recall', m.recall], ['f1', m.f1], ['fpr', m.fpr]].map(([k, v]) => h('div', { class: `jm-k ${k === 'fpr' ? 'fpr' : ''}` }, h('b', {}, pct(v)), h('span', {}, T(k))))),
    h('div', { class: 'jm-cm' }, h('span', { class: 'tag ok' }, `${m.tp} ${T('tp')}`), h('span', { class: 'tag bad' }, `${m.fp} ${T('fp')}`), h('span', { class: 'tag mid' }, `${m.fn} ${T('fn')}`), h('span', { class: 'tag' }, `${m.tn} ${T('tn')}`)));
}

function resultsView() {
  const r = S.res;
  if (r.error || !r.results) return h('section', { class: 'card' }, String(r.message || r.error || 'error'));
  const rows = r.results.filter(x => S.filter === 'all' || x.verdict === S.filter);
  const count = v => r.results.filter(x => x.verdict === v).length;
  const seg = (id, label) => h('button', { type: 'button', class: `seg${S.filter === id ? ' on' : ''}`, onclick: () => { S.filter = id; render(); } }, `${label} (${id === 'all' ? r.results.length : count(id)})`);
  const csv = () => {
    const esc = s => `"${String(s ?? '').replace(/"/g, '""')}"`;
    const body = ['url,verdict,score,label,reasons', ...r.results.map(x => [esc(x.url), x.verdict, x.score ?? '', x.label ?? '', esc(x.reasons.map(y => y.en).join(' | '))].join(','))].join('\n');
    const a = h('a', { href: URL.createObjectURL(new Blob([body], { type: 'text/csv' })), download: 'veto-judge-results.csv' }); a.click();
  };
  return h('section', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', { class: 'section-title' }, icon('list-checks'), T('results')),
      h('div', { class: 'tiny muted' }, `${r.results.length} ${T('urls')} · ${(r.results.length / Math.max(0.01, r.seconds)).toFixed(0)} ${T('perSec')}${r.model ? ` · ${T('model')} ${r.model.version}` : ''}`)),
    r.metrics ? h('div', { class: 'jm-row' }, metricCard(r.metrics.strict, T('strict')), metricCard(r.metrics.cautious, T('cautious'))) : h('p', { class: 'tiny muted' }, T('noLabels')),
    h('div', { class: 'card-head' }, h('div', { class: 'segs' }, seg('all', T('all')), seg('phishing', T('phishing')), seg('suspicious', T('suspicious')), seg('legitimate', T('legitimate'))),
      h('button', { class: 'ghost small', type: 'button', onclick: csv }, icon('download'), T('download'))),
    h('div', { class: 'table-wrap' }, h('table', { class: 'ctable' },
      h('thead', {}, h('tr', {}, ['URL', T('score'), '', T('label'), T('why')].map(x => h('th', {}, x)))),
      h('tbody', {}, rows.slice(0, 1000).map(x => {
        const wrong = x.label != null && ((x.label === 1) !== (x.verdict === 'phishing'));
        return h('tr', { class: wrong ? 'wrong' : '' },
          h('td', {}, h('code', {}, x.url.length > 90 ? x.url.slice(0, 90) + '…' : x.url), x.finalUrl && x.finalUrl !== x.url ? h('div', { class: 'tiny muted' }, '→ ', x.finalUrl.slice(0, 80)) : null),
          h('td', {}, h('div', { class: 'meter' }, h('i', { style: `width:${Math.round((x.score || 0) * 100)}%`, class: x.verdict === 'phishing' ? 'bad' : x.verdict === 'suspicious' ? 'mid' : '' })), h('span', { class: 'tiny' }, x.score == null ? '' : x.score.toFixed(2))),
          h('td', {}, h('span', { class: `tag ${x.verdict === 'phishing' ? 'bad' : x.verdict === 'suspicious' ? 'mid' : x.verdict === 'legitimate' ? 'ok' : ''}` }, T(x.verdict))),
          h('td', { class: 'tiny' }, x.label == null ? '' : x.label ? T('phishing') : T('legitimate')),
          h('td', { class: 'tiny' }, x.reasons.slice(0, 3).map(y => h('div', {}, L(y)))));
      })))));
}

document.getElementById('langBtn').addEventListener('click', () => { S.lang = S.lang === 'ar' ? 'en' : 'ar'; store.set('veto.lang', S.lang); render(); });
render();
