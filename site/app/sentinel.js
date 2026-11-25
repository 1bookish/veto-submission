// Veto Sentinel police console: run hunts, watch suspects, X-ray them, see campaigns, open takedown packs.
// Talks only to this Veto server's /api/sentinel endpoints, which answer only on the server machine itself.
import { icon } from './icons.js';

const store = { get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* private */ } } };
const S = { lang: store.get('veto.lang', 'en'), data: null, job: null, filter: 'live', all: false, kinds: new Set(['lookalike', 'nrd', 'ct', 'search', 'maps']), xrayTop: 3, busy: new Set(), msg: null };
const TX = {
  en: {
    tagline: 'Sentinel · police console', app: 'Veto app', watched: 'Sites watched', live: 'Live now', dormant: 'Registered, no website yet', xrayed: 'X-rayed', dangerous: 'Proven dangerous', campaigns: 'Campaigns',
    hunt: 'Hunt for scam sites before the messages go out', huntHelp: 'Sentinel builds every look-alike of each official domain, checks which ones are registered, reads the certificate logs, searches the web and the map listings, visits what is live and X-rays the worst.',
    kLookalike: 'Look-alike names (DNS)', kNrd: 'Registered yesterday (all new domains)', src_nrd: 'new domain', kCt: 'Certificate logs', kSearch: 'Search results', kMaps: 'Map listings', needsKey: 'needs an API key', scope: 'Institutions', priority: 'Priority banks and government', allInst: 'All institutions',
    xrayTop: 'Then X-ray the top', liveOnes: 'live suspects', run: 'Run the hunt', running: 'Hunting…', phase: 'Phase', checked: 'names checked', registered: 'registered', liveFound: 'live',
    suspects: 'Suspects', fLive: 'Live', fDormant: 'Dormant', fAll: 'All', site: 'Site', imitates: 'Imitates', foundBy: 'Found by', status: 'Status', score: 'Threat', action: '',
    xray: 'X-ray', openCase: 'Takedown pack', armed: 'just switched on', noSuspects: 'No suspects yet. Run a hunt.',
    st_live: 'live', st_no_web: 'no website yet', st_parked: 'parked / for sale', st_error_page: 'error page', st_redirects_official: 'sends to an official site', st_brand_owned: 'brand-owned', st_gone: 'gone',
    src_lookalike: 'look-alike', src_ct: 'certificate', src_search: 'search', src_maps: 'maps', src_manual: 'manual',
    camps: 'Campaigns: sites run by the same people', campsHelp: 'Linked only by things criminals reuse (Telegram bots, WhatsApp numbers, wallets, analytics IDs, the same kit, the same server). Every link says why.', noCamps: 'No campaigns yet: they appear when two X-rayed sites share criminal infrastructure.',
    sites: 'sites', firstSeen: 'first seen', cases: 'Case file', noCases: 'No cases yet. X-ray a suspect or check a link.', verdict: 'Verdict', evidence: 'Evidence', seen: 'Seen', pack: 'Pack', stix: 'STIX',
    check: 'Check a link now', checkHelp: 'Paste any suspicious link. It is X-rayed in the sealed browser and added to the case file.', checkBtn: 'X-ray it', forbidden: 'The police console answers only on the Veto server itself (localhost).',
    graphLabel: 'Scam network graph', graphHelp: 'Circles are scam sites (click for the takedown pack). Squares are what links them: TG = the same Telegram bot, GA = the same analytics ID, IP = the same server, KIT = the same phishing kit.',
    ev_cloaked: 'cloaked', ev_logo: 'copied logo', armedTag: 'X-ray: armed', nameOnly: 'X-ray: name only, watch', lastSweep: 'Last hunt', never: 'never', radar: 'Certificate radar', candidates: 'candidates'
  },
  ar: {
    tagline: 'سنتينل · وحدة تحكم الشرطة', app: 'تطبيق فيتو', watched: 'مواقع تحت المراقبة', live: 'تعمل الآن', dormant: 'مسجلة بلا موقع بعد', xrayed: 'تم فحصها بالأشعة', dangerous: 'ثبت أنها خطيرة', campaigns: 'حملات',
    hunt: 'اصطد مواقع الاحتيال قبل إرسال الرسائل', huntHelp: 'يبني سنتينل كل الأسماء المشابهة لكل نطاق رسمي، ويتحقق من المسجّل منها، ويقرأ سجلات الشهادات، ويبحث في الويب وإدراجات الخرائط، ويزور ما يعمل ويفحص الأخطر بالأشعة.',
    kLookalike: 'أسماء مشابهة (DNS)', kNrd: 'سُجّلت أمس (كل النطاقات الجديدة)', src_nrd: 'نطاق جديد', kCt: 'سجلات الشهادات', kSearch: 'نتائج البحث', kMaps: 'إدراجات الخرائط', needsKey: 'يحتاج مفتاح API', scope: 'الجهات', priority: 'البنوك والجهات الحكومية ذات الأولوية', allInst: 'كل الجهات',
    xrayTop: 'ثم افحص بالأشعة أخطر', liveOnes: 'مواقع تعمل', run: 'ابدأ الصيد', running: 'جارٍ الصيد…', phase: 'المرحلة', checked: 'اسماً تم فحصه', registered: 'مسجّل', liveFound: 'يعمل',
    suspects: 'المشتبه بها', fLive: 'تعمل', fDormant: 'خاملة', fAll: 'الكل', site: 'الموقع', imitates: 'يقلّد', foundBy: 'اكتُشف عبر', status: 'الحالة', score: 'الخطورة', action: '',
    xray: 'أشعة', openCase: 'ملف الإزالة', armed: 'بدأ العمل للتو', noSuspects: 'لا يوجد مشتبه بهم بعد. ابدأ الصيد.',
    st_live: 'يعمل', st_no_web: 'بلا موقع بعد', st_parked: 'متوقف / للبيع', st_error_page: 'صفحة خطأ', st_redirects_official: 'يحوّل إلى موقع رسمي', st_brand_owned: 'مملوك للجهة', st_gone: 'زال',
    src_lookalike: 'اسم مشابه', src_ct: 'شهادة', src_search: 'بحث', src_maps: 'خرائط', src_manual: 'يدوي',
    camps: 'الحملات: مواقع يديرها الأشخاص أنفسهم', campsHelp: 'الربط فقط بما يعيد المحتالون استخدامه (بوتات تيليجرام، أرقام واتساب، محافظ، معرّفات تحليلات، الأداة نفسها، الخادم نفسه). كل رابط يذكر سببه.', noCamps: 'لا توجد حملات بعد: تظهر عندما يتشارك موقعان مفحوصان بنية إجرامية.',
    sites: 'مواقع', firstSeen: 'أول ظهور', cases: 'ملف القضايا', noCases: 'لا توجد قضايا بعد. افحص مشتبهاً به أو رابطاً.', verdict: 'الحكم', evidence: 'الأدلة', seen: 'شوهد', pack: 'الملف', stix: 'STIX',
    check: 'افحص رابطاً الآن', checkHelp: 'الصق أي رابط مشبوه. يُفحص في المتصفح المعزول ويُضاف إلى ملف القضايا.', checkBtn: 'افحصه', forbidden: 'وحدة تحكم الشرطة تعمل فقط على خادم فيتو نفسه.',
    graphLabel: 'شبكة مواقع الاحتيال', graphHelp: 'الدوائر مواقع احتيال (اضغط لملف الإزالة). المربعات ما يربطها: TG بوت تيليجرام نفسه، GA معرّف التحليلات نفسه، IP الخادم نفسه، KIT أداة التصيّد نفسها.',
    ev_cloaked: 'تمويه', ev_logo: 'شعار منسوخ', armedTag: 'الأشعة: مفعّل', nameOnly: 'الأشعة: الاسم فقط، راقب', lastSweep: 'آخر صيد', never: 'أبداً', radar: 'رادار الشهادات', candidates: 'مرشحاً'
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
const ic = name => icon(name);
const app = document.getElementById('app');
const fmtDate = s => (s ? new Date(s).toLocaleString(S.lang === 'ar' ? 'ar-AE' : 'en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '');

async function api(path, body) {
  const r = await fetch(path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {});
  if (r.status === 403) throw Object.assign(new Error('forbidden'), { forbidden: true });
  return r.json();
}
async function load() {
  try { S.data = await api('/api/sentinel'); S.job = S.data.job; render(); if (S.job?.running) poll(); }
  catch (e) { app.replaceChildren(h('div', { class: 'card' }, ic('lock'), ' ', e.forbidden ? T('forbidden') : String(e.message))); }
}
let pollTimer = null;
function poll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    const j = await api('/api/sentinel/job').catch(() => null);
    S.job = j?.job || null;
    if (S.job?.running) { renderJob(); poll(); } else load();
  }, 1200);
}

// ---------------- render ----------------
function render() {
  document.documentElement.lang = S.lang;
  document.documentElement.dir = S.lang === 'ar' ? 'rtl' : 'ltr';
  document.getElementById('tagline').textContent = T('tagline');
  document.getElementById('toApp').textContent = T('app');
  document.getElementById('langBtn').textContent = S.lang === 'ar' ? 'EN' : 'ع';
  const d = S.data;
  app.replaceChildren(kpis(d), huntCard(d), suspectsCard(d), campaignsCard(d), casesCard(d), checkCard());
}
function kpis(d) {
  const k = (n, label, ico, tone = '') => h('div', { class: `kpi ${tone}` }, h('div', { class: 'kpi-ico' }, ic(ico)), h('b', {}, String(n)), h('span', {}, label));
  return h('section', { class: 'kpis' },
    k(d.counts.total, T('watched'), 'radar'), k(d.counts.live, T('live'), 'activity', d.counts.live ? 'warn' : ''), k(d.counts.noWeb, T('dormant'), 'clock'),
    k(d.cases.length, T('xrayed'), 'scan-search'), k(d.cases.filter(c => c.verdict === 'dangerous').length, T('dangerous'), 'octagon-alert', d.cases.some(c => c.verdict === 'dangerous') ? 'bad' : ''), k(d.campaigns.length, T('campaigns'), 'waypoints', d.campaigns.length ? 'bad' : ''));
}
function huntCard(d) {
  const kind = (id, label, needs) => {
    const disabled = needs && !d.connectors[needs];
    return h('label', { class: `kind${disabled ? ' off' : ''}` }, h('input', { type: 'checkbox', checked: S.kinds.has(id) && !disabled, disabled,
      onchange: e => { e.target.checked ? S.kinds.add(id) : S.kinds.delete(id); } }), label, disabled ? h('small', {}, ` (${T('needsKey')})`) : null);
  };
  const last = d.sweeps?.[d.sweeps.length - 1];
  const running = !!S.job?.running;
  return h('section', { class: 'card hunt' },
    h('h2', { class: 'section-title' }, ic('crosshair'), T('hunt')),
    h('p', { class: 'muted small' }, T('huntHelp')),
    h('div', { class: 'kinds' }, kind('lookalike', T('kLookalike')), kind('nrd', T('kNrd')), kind('ct', T('kCt')), kind('search', T('kSearch'), 'search'), kind('maps', T('kMaps'), 'maps')),
    h('div', { class: 'hunt-row' },
      h('label', { class: 'scope' }, T('scope'), ' ', h('select', { onchange: e => { S.all = e.target.value === 'all'; } },
        h('option', { value: 'priority', selected: !S.all }, `${T('priority')} (${d.institutions.filter(i => i.priority).length})`),
        h('option', { value: 'all', selected: S.all }, `${T('allInst')} (${d.institutions.length})`))),
      h('label', { class: 'scope' }, T('xrayTop'), ' ', h('input', { type: 'number', min: 0, max: 10, value: S.xrayTop, onchange: e => { S.xrayTop = Number(e.target.value) || 0; } }), ' ', T('liveOnes')),
      h('button', { class: 'primary', type: 'button', disabled: running, onclick: runHunt }, ic(running ? 'refresh-cw' : 'play'), running ? T('running') : T('run'))),
    h('div', { id: 'jobBox' }, jobView()),
    h('div', { class: 'tiny muted' }, `${T('lastSweep')}: ${last ? `${fmtDate(last.t)} · ${last.names} · ${last.registered} ${T('registered')} · ${last.live} ${T('liveFound')}` : T('never')} · ${T('radar')}: ${d.radar.candidates} ${T('candidates')} (${(d.radar.generatedAt || '').slice(0, 10)})`));
}
function jobView() {
  const j = S.job;
  if (!j || (!j.running && !j.error)) return null;
  const pct = j.total ? Math.round((j.checked / j.total) * 100) : 0;
  return h('div', { class: 'job' },
    h('div', { class: 'job-top' }, h('b', {}, `${T('phase')}: ${j.phase}`), h('span', {}, `${j.checked}/${j.total} ${T('checked')} · ${j.registered} ${T('registered')} · ${j.live} ${T('liveFound')}`)),
    h('div', { class: 'bar' }, h('i', { style: `width:${pct}%` })),
    h('pre', { class: 'job-log' }, (j.log || []).slice(-6).join('\n')));
}
function renderJob() { const b = document.getElementById('jobBox'); if (b) b.replaceChildren(jobView() || ''); }
async function runHunt() {
  const insts = S.all ? S.data.institutions.map(i => i.id) : S.data.institutions.filter(i => i.priority).map(i => i.id);
  const r = await api('/api/sentinel/sweep', { insts, kinds: [...S.kinds], xrayTop: S.xrayTop }).catch(() => null);
  S.job = r?.job || { running: true, phase: 'starting', checked: 0, total: 0, registered: 0, live: 0, log: [] };
  render();
  poll();
}

const STATUS_TONE = { live: 'bad', no_web: 'mid', error_page: 'mid', parked: 'low', redirects_official: 'low', brand_owned: 'ok', gone: 'low' };
function suspectsCard(d) {
  const rows = d.suspects.filter(s => S.filter === 'all' ? true : S.filter === 'live' ? s.status === 'live' : ['no_web', 'error_page', 'parked'].includes(s.status)).slice(0, 80);
  const tab = (id, label, n) => h('button', { type: 'button', class: `seg${S.filter === id ? ' on' : ''}`, onclick: () => { S.filter = id; render(); } }, `${label} (${n})`);
  const counts = { live: d.suspects.filter(s => s.status === 'live').length, dormant: d.suspects.filter(s => ['no_web', 'error_page', 'parked'].includes(s.status)).length, all: d.suspects.length };
  return h('section', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', { class: 'section-title' }, ic('telescope'), T('suspects')),
      h('div', { class: 'segs' }, tab('live', T('fLive'), counts.live), tab('dormant', T('fDormant'), counts.dormant), tab('all', T('fAll'), counts.all))),
    rows.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'ctable' },
      h('thead', {}, h('tr', {}, [T('site'), T('imitates'), T('foundBy'), T('status'), T('score'), T('action')].map(x => h('th', {}, x)))),
      h('tbody', {}, rows.map(s => h('tr', {},
        h('td', {}, h('code', {}, s.host), s.armedAt ? h('span', { class: 'tag bad' }, ic('siren'), T('armed')) : null,
          s.why?.[0] ? h('div', { class: 'tiny muted' }, L(s.why[0])) : null, s.web?.title ? h('div', { class: 'tiny muted' }, `“${s.web.title.slice(0, 70)}”`) : null),
        h('td', {}, L(s.instName) || s.inst || ''),
        h('td', {}, h('div', { class: 'chips' }, (s.sources || []).map(x => h('span', { class: 'tag' }, T('src_' + x)))), h('div', { class: 'tiny muted' }, s.how || '')),
        h('td', {}, h('span', { class: `tag ${STATUS_TONE[s.status] || ''}` }, T('st_' + s.status)), s.verdict ? h('div', {}, h('span', { class: `tag ${s.armed ? 'bad' : 'mid'}` }, s.armed ? T('armedTag') : T('nameOnly'))) : null),
        h('td', {}, h('div', { class: 'meter' }, h('i', { style: `width:${Math.round((s.score || 0) * 100)}%`, class: (s.score || 0) >= 0.7 ? 'bad' : (s.score || 0) >= 0.4 ? 'mid' : '' })), h('span', { class: 'tiny' }, `${Math.round((s.score || 0) * 100)}%`)),
        h('td', {}, s.caseId ? h('a', { class: 'btn ghost small', href: `/api/dossier/${s.caseId}`, target: '_blank', rel: 'noopener' }, ic('file-text'), T('openCase'))
          : s.status === 'live' || s.status === 'error_page' ? h('button', { type: 'button', class: 'ghost small', disabled: S.busy.has(s.host), onclick: () => xrayHost(s.host) }, ic(S.busy.has(s.host) ? 'refresh-cw' : 'scan-search'), T('xray')) : null))))))
      : h('p', { class: 'muted' }, T('noSuspects')));
}
async function xrayHost(host) {
  S.busy.add(host); render();
  await api('/api/sentinel/xray', { host }).catch(() => null);
  S.busy.delete(host);
  await load();
}
// The scam network: every site of every campaign, joined through the criminal infrastructure they share
// (Telegram bot, analytics ID, wallet, server, kit …). A small force-directed layout, drawn as SVG (no library).
const KEY_ICON = { telegram_bot: 'TG', telegram: 'TG', whatsapp: 'WA', wallet: '₿', analytics: 'GA', pixel: 'PX', metrika: 'YM', email: '@', phone: '☎',
  kit_exact: 'KIT', kit_near: 'KIT', favicon: 'ICO', ip: 'IP', ns: 'NS', bulk: 'REG', exfil: 'EXF', apk: 'APK' };
function networkGraph(campaigns, cases) {
  const NS = 'http://www.w3.org/2000/svg';
  const nodes = new Map(), edges = [];
  const verdictOf = new Map((cases || []).map(c => [c.id, c.verdict]));
  const node = (id, o) => { if (!nodes.has(id)) nodes.set(id, { id, x: 400 + Math.cos(nodes.size * 2.4) * (60 + nodes.size * 9), y: 170 + Math.sin(nodes.size * 2.4) * (40 + nodes.size * 6), vx: 0, vy: 0, ...o }); return nodes.get(id); };
  for (const c of campaigns) {
    for (const m of c.members) node('s:' + m.id, { kind: 'site', label: m.host, verdict: verdictOf.get(m.id) || m.verdict, href: '/api/dossier/' + m.id });
    for (const l of c.links) {
      const k = node('k:' + l.why + ':' + l.value, { kind: 'key', label: KEY_ICON[l.why] || 'LINK', title: `${L(l)}: ${l.value}`, value: String(l.value).slice(0, 14) });
      for (const sid of [l.a, l.b]) if (!edges.some(e => e.s === 's:' + sid && e.t === k.id)) edges.push({ s: 's:' + sid, t: k.id });
    }
  }
  const N = [...nodes.values()];
  const byId = id => nodes.get(id);
  for (let it = 0; it < 320; it++) {
    for (const a of N) for (const b of N) {
      if (a === b) continue;
      const dx = a.x - b.x, dy = a.y - b.y, d2 = Math.max(80, dx * dx + dy * dy);
      a.vx += (dx / Math.sqrt(d2)) * 2600 / d2; a.vy += (dy / Math.sqrt(d2)) * 2600 / d2;
    }
    for (const e of edges) {
      const a = byId(e.s), b = byId(e.t); if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1, f = (d - 95) * 0.02;
      a.vx += dx / d * f; a.vy += dy / d * f; b.vx -= dx / d * f; b.vy -= dy / d * f;
    }
    for (const n of N) { n.vx += (400 - n.x) * 0.004; n.vy += (170 - n.y) * 0.006; n.x += n.vx; n.y += n.vy; n.vx *= 0.6; n.vy *= 0.6; n.x = Math.max(70, Math.min(730, n.x)); n.y = Math.max(28, Math.min(312, n.y)); }
  }
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 800 340'); svg.setAttribute('class', 'netgraph'); svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', T('graphLabel'));
  const el = (tag, attrs, text) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); if (text != null) e.textContent = text; return e; };
  for (const e of edges) { const a = byId(e.s), b = byId(e.t); if (a && b) svg.append(el('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: 'ng-edge' })); }
  for (const n of N) {
    const g = el('g', { class: `ng-node ${n.kind} ${n.verdict || ''}`, transform: `translate(${n.x.toFixed(1)},${n.y.toFixed(1)})` });
    if (n.kind === 'site') {
      const a = el('a', { href: n.href, target: '_blank' });
      a.append(el('circle', { r: 15 }), el('text', { y: 33, 'text-anchor': 'middle', class: 'ng-label' }, n.label.length > 26 ? n.label.slice(0, 25) + '…' : n.label), el('title', {}, n.label));
      g.append(a);
    } else {
      g.append(el('rect', { x: -17, y: -12, width: 34, height: 24, rx: 7 }), el('text', { y: 4.5, 'text-anchor': 'middle', class: 'ng-key' }, n.label),
        el('text', { y: 27, 'text-anchor': 'middle', class: 'ng-sub' }, n.value), el('title', {}, n.title));
    }
    svg.append(g);
  }
  return h('div', { class: 'netgraph-wrap' }, svg, h('div', { class: 'tiny muted' }, T('graphHelp')));
}

function campaignsCard(d) {
  return h('section', { class: 'card' },
    h('h2', { class: 'section-title' }, ic('waypoints'), T('camps')), h('p', { class: 'muted small' }, T('campsHelp')),
    d.campaigns.length ? networkGraph(d.campaigns, d.cases) : null,
    d.campaigns.length ? d.campaigns.map(c => h('div', { class: 'camp' },
      h('div', { class: 'camp-head' }, h('b', {}, c.id), h('span', { class: 'tag bad' }, `${c.size} ${T('sites')}`), c.brands.map(b => h('span', { class: 'tag' }, L(b.name))),
        h('span', { class: 'tiny muted' }, `${T('firstSeen')} ${fmtDate(c.firstSeen)}`)),
      h('ul', { class: 'camp-why' }, [...new Map(c.links.map(l => [l.why + l.value, l])).values()].slice(0, 6).map(l => h('li', {}, ic('link'), `${L(l)}: `, h('code', {}, l.value)))),
      h('div', { class: 'chips' }, c.members.map(m => h('a', { class: `tag ${m.verdict === 'dangerous' ? 'bad' : ''}`, href: `/api/dossier/${m.id}`, target: '_blank', rel: 'noopener' }, m.host)))))
      : h('p', { class: 'muted' }, T('noCamps')));
}
function casesCard(d) {
  return h('section', { class: 'card' },
    h('h2', { class: 'section-title' }, ic('gavel'), T('cases')),
    d.cases.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'ctable' },
      h('thead', {}, h('tr', {}, [T('site'), T('verdict'), T('imitates'), T('evidence'), T('seen'), ''].map(x => h('th', {}, x)))),
      h('tbody', {}, d.cases.slice(0, 60).map(c => h('tr', {},
        h('td', {}, h('code', {}, c.host)),
        h('td', {}, h('span', { class: `tag ${c.verdict === 'dangerous' ? 'bad' : c.verdict === 'suspicious' ? 'mid' : ''}` }, `${c.verdict} ${Math.round((c.risk || 0) * 100)}%`)),
        h('td', {}, L(c.imitates?.name) || ''),
        h('td', {}, h('div', { class: 'chips' }, (c.asks || []).map(a => h('span', { class: 'tag' }, a)), (c.exfil || []).map(x => h('span', { class: 'tag bad' }, x.replace(/_/g, ' '))),
          c.cloaked ? h('span', { class: 'tag bad' }, T('ev_cloaked')) : null, c.copiedLogo ? h('span', { class: 'tag bad' }, T('ev_logo')) : null)),
        h('td', { class: 'tiny' }, fmtDate(c.lastSeen)),
        h('td', {}, h('a', { href: `/api/dossier/${c.id}`, target: '_blank', rel: 'noopener' }, T('pack')), ' · ', h('a', { href: `/api/case/${c.id}/stix`, target: '_blank', rel: 'noopener' }, T('stix'))))))))
      : h('p', { class: 'muted' }, T('noCases')));
}
function checkCard() {
  const inp = h('input', { type: 'url', placeholder: 'https://…', dir: 'ltr', class: 'url-in' });
  const out = h('div', { class: 'tiny' }, S.msg || '');
  const go = async () => {
    if (!inp.value.trim()) return;
    out.textContent = '…';
    const r = await fetch('/api/xray', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: inp.value.trim() }) }).then(x => x.json()).catch(() => null);
    S.msg = r ? (r.ok ? `${r.verdict} · ${Math.round(r.risk * 100)}% · ${r.finalHost}${r.campaign ? ` · campaign ${r.campaign.id} (${r.campaign.size})` : ''}` : r.message) : 'error';
    await load();
  };
  return h('section', { class: 'card' }, h('h2', { class: 'section-title' }, ic('scan-search'), T('check')), h('p', { class: 'muted small' }, T('checkHelp')),
    h('div', { class: 'hunt-row' }, inp, h('button', { class: 'primary', type: 'button', onclick: go }, ic('scan-search'), T('checkBtn'))), out);
}

document.getElementById('langBtn').addEventListener('click', () => { S.lang = S.lang === 'ar' ? 'en' : 'ar'; store.set('veto.lang', S.lang); if (S.data) render(); });
load();
