// Approval watch and call report (phone side). Pure logic: the phone's sensors (Watchers.java, Veto.java) send a
// timeline of what they saw, and this module decides what to show. Memory only; nothing is stored or sent.
// A timeline event is { t: ms, type: 'call_start' | 'call_end' | 'app_front' | 'code', pkg, label, unknown }.
// 'unknown' is true for a call from a number that is not in the phone's contacts.

export const POST_CALL_MS = 10 * 60 * 1000;   // the approval watch stays on this long after an unknown call ends
export const STORM_COUNT = 3;                  // this many approval openings ...
export const STORM_MS = 10 * 60 * 1000;        // ... inside this window count as a storm
export const COOL_DOWN_S = 60;                 // the card asks for this many seconds before a decision

const APPROVAL = /(uae ?pass|authenticator|authy|digital ?id|\bmpass\b)/i;
const REMOTE = /(anydesk|teamviewer|quick ?support|rustdesk|airdroid|ultraviewer|supremo|splashtop|zoho ?assist|remote ?desktop|chromeremotedesktop|\bvnc\b)/i;
const BANK = /(bank|banking|بنك|mashreq|enbd|emirates ?nbd|emirates ?islamic|adcb|\bfab\b|adib|\bdib\b|rakbank|\bcbd\b|hsbc|citibank|standard ?chartered|\bwio\b|\bliv\b|\bnbf\b|al ?hilal|e& ?money|payit|botim ?money|careem ?pay|wallet)/i;

/** What kind of app is this: approval (UAE PASS, authenticator, digital ID), bank, remote (screen sharing) or none. */
export function classifyApp(label, pkg) {
  const s = `${label || ''} ${pkg || ''}`;
  if (APPROVAL.test(s)) return { kind: 'approval' };
  if (REMOTE.test(s)) return { kind: 'remote' };
  if (BANK.test(s) || /bank/i.test(pkg || '')) return { kind: 'bank' };
  return { kind: null };
}

const L = (en, ar) => ({ en, ar });

// the last unknown call in the timeline: its start and its end (end is null while the call is still going on)
function lastUnknownCall(events) {
  let call = null;
  for (const e of events) {
    if (e.type === 'call_start' && e.unknown) call = { start: e.t, end: null };
    else if (e.type === 'call_end' && e.unknown) {
      if (!call) call = { start: -Infinity, end: null };
      call.end = e.t;
    }
  }
  return call;
}

/** Where the phone is, relative to the last unknown call, at time t: during it, after it (with minutes), or neither. */
export function callContext(events, t, windowMs = POST_CALL_MS) {
  const call = lastUnknownCall(events);
  if (!call || t < call.start) return null;
  if (call.end === null) return { when: 'during', minutes: Math.max(0, Math.round((t - call.start) / 60000)) };
  if (t - call.end <= windowMs) return { when: 'after', minutes: Math.max(0, Math.round((t - call.end) / 60000)) };
  return null;
}

/** Any approval, bank or remote app in front during an unknown call, or within the window after it. */
export function postCallAlert(events, { windowMs = POST_CALL_MS } = {}) {
  for (const e of events) {
    if (e.type !== 'app_front') continue;
    const kind = classifyApp(e.label, e.pkg).kind;
    if (!kind) continue;
    const c = callContext(events, e.t, windowMs);
    if (c) return { alert: true, kind, reason: c.when === 'during' ? 'during_call' : 'after_call', label: e.label, minutesAfter: c.minutes };
  }
  return { alert: false };
}

/** Approval openings in a short window. Enough of them is a storm: somebody is pushing approval requests at you. */
export function approvalStorm(events, { count = STORM_COUNT, windowMs = STORM_MS } = {}) {
  const apps = events.filter(e => e.type === 'app_front' && classifyApp(e.label, e.pkg).kind === 'approval');
  if (!apps.length) return { storm: false, count: 0 };
  const newest = apps[apps.length - 1].t;
  const inWindow = apps.filter(e => newest - e.t <= windowMs).length;
  return { storm: inWindow >= count, count: inWindow };
}

// the card for an app the user did not start
function notStartedCard(label) {
  return {
    level: 'stop',
    source: L(`${label} · a sign-in you did not start`, `${label} · تسجيل دخول لم تبدأه`),
    title: L('Do not approve. Close the app.', 'لا توافق. أغلق التطبيق.'),
    reasons: [
      L('Someone else may be signing in with your account. Change your password in the official app, not from a link.',
        'قد يحاول شخص آخر تسجيل الدخول بحسابك. غيّر كلمة المرور من التطبيق الرسمي، لا من رابط.'),
      L('Call the official number printed on your card or on the official website, not the number that called you.',
        'اتصل بالرقم الرسمي المطبوع على بطاقتك أو على الموقع الرسمي، لا بالرقم الذي اتصل بك.'),
    ],
    family: L('Veto alert: someone may be trying to sign in to my account. Please call me.',
      'تنبيه من فيتو: قد يحاول أحد الدخول إلى حسابي. اتصل بي من فضلك.'),
    choices: [],
  };
}

// the card for an approval app opened during or just after an unknown call
function approvalCard(label, ctx) {
  const when = ctx.when === 'during'
    ? L('during an unknown call', 'أثناء مكالمة من رقم مجهول')
    : ctx.minutes < 1
      ? L('right after an unknown call', 'مباشرة بعد مكالمة من رقم مجهول')
      : L(`${ctx.minutes} min after an unknown call`, `بعد ${ctx.minutes} دقيقة من مكالمة من رقم مجهول`);
  return {
    level: 'caution',
    source: L(`${label} · ${when.en}`, `${label} · ${when.ar}`),
    title: L(`${label} opened ${when.en}.`, `تم فتح ${label} ${when.ar}.`),
    reasons: [
      L('Approval requests are how account takeovers finish. After a call, the usual order is a call, then a "verify" in an app.',
        'طلبات الموافقة هي ما يُكمل الاستيلاء على الحسابات. بعد المكالمة يكون الترتيب المعتاد: مكالمة، ثم «تحقّق» في تطبيق.'),
      L('Approve only a sign-in you started yourself, at a time you chose.',
        'وافق فقط على تسجيل دخول بدأته بنفسك، في وقت تختاره.'),
    ],
    cooldownS: COOL_DOWN_S,
    choices: [
      { id: 'started', label: L('I started it', 'أنا بدأته'), next: null },
      { id: 'not_started', label: L('I did not start it', 'لم أبدأه'), next: notStartedCard(label) },
    ],
  };
}

// the card for a storm of approval requests
function stormCard(label, count) {
  return {
    level: 'stop',
    source: L(`${label} · ${count} in 10 minutes`, `${label} · ${count} خلال 10 دقائق`),
    title: L('Too many approval requests', 'طلبات موافقة كثيرة جداً'),
    reasons: [
      L(`${count} approval requests in 10 minutes. Stop approving. No legitimate sign-in needs that many.`,
        `${count} طلبات موافقة خلال 10 دقائق. توقّف عن الموافقة. لا يحتاج أي تسجيل دخول شرعي إلى هذا العدد.`),
      L('Tell a family member now. Veto can prepare the message for you.',
        'أخبر أحد أفراد عائلتك الآن. يستطيع فيتو تجهيز الرسالة لك.'),
    ],
    family: notStartedCard(label).family,
    choices: [],
  };
}

/** Called when an app comes to the front. Returns { show: true, card, kind } or { show: false }. */
export function decideForeground(payload = {}) {
  const events = Array.isArray(payload.events) ? payload.events : [];
  const last = events[events.length - 1];
  if (!last || last.type !== 'app_front') return { show: false };
  if (classifyApp(last.label, last.pkg).kind !== 'approval') return { show: false };
  const storm = approvalStorm(events);
  if (storm.storm) return { show: true, kind: 'storm', card: stormCard(last.label, storm.count) };
  const ctx = callContext(events, last.t);
  if (!ctx) return { show: false };
  return { show: true, kind: 'approval', card: approvalCard(last.label, ctx) };
}

const fmt = s => (s >= 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s} s`);
const fmtAr = s => (s >= 60 ? `${Math.floor(s / 60)} د ${s % 60} ث` : `${s} ث`);

/**
 * The short report shown when an unknown call ends. It says what Veto checked and what happened on the phone,
 * then closes by itself. Lines are English and Arabic; the phone shows the language the user chose.
 */
export function callReport(p = {}) {
  const lines = [];
  const dur = Math.max(0, Math.round(p.durationS || 0));
  if (dur > 0) lines.push(L(`Call ended after ${fmt(dur)}.`, `انتهت المكالمة بعد ${fmtAr(dur)}.`));
  const c = p.caller || {};
  const country = c.country && c.country.name ? c.country.name : null;
  const num = p.number ? ` (${p.number})` : '';
  lines.push(country
    ? L(`From ${country.en}${num}, not in your contacts.`, `من ${country.ar}${num}، ليس في جهات اتصالك.`)
    : L(`From an unknown number${num}, not in your contacts.`, `من رقم مجهول${num}، ليس في جهات اتصالك.`));
  const reported = (c.signals || []).some(s => s.id === 'reported_by_you');
  lines.push(reported
    ? L('Background check: you reported this number before.', 'فحص في الخلفية: سبق أن أبلغت عن هذا الرقم.')
    : L('Background check: not in your reports.', 'فحص في الخلفية: ليس في بلاغاتك.'));
  if (p.online) lines.push(L(String(p.online), String(p.online)));
  const events = Array.isArray(p.events) ? p.events : [];
  let approvalLine = false;
  for (const e of events) {
    if (e.type !== 'app_front' || approvalLine) continue;
    if (classifyApp(e.label, e.pkg).kind !== 'approval') continue;
    const cc = callContext(events, e.t);
    if (!cc || cc.when !== 'after') continue;
    lines.push(L(`${e.label} opened ${cc.minutes} min after the call.`, `تم فتح ${e.label} بعد ${cc.minutes} دقيقة من المكالمة.`));
    approvalLine = true;
  }
  if (p.bankOpened) lines.push(L('A bank or remote-control app came to the front during the call.',
    'ظهر تطبيق بنك أو تطبيق تحكم عن بُعد أثناء المكالمة.'));
  const codes = Math.max(0, Math.round(p.codes || 0));
  if (codes > 0) lines.push(L(`${codes} one-time code${codes > 1 ? 's' : ''} arrived during the call. Nobody legitimate needs it.`,
    `وصل ${codes} رمز تحقق أثناء المكالمة. لا يحتاجه أي شخص شرعي.`));
  const happened = approvalLine || !!p.bankOpened || codes > 0;
  if (!happened) lines.push(L('Nothing else happened on this phone: no code arrived, no bank or approval app opened.',
    'لم يحدث شيء آخر على هذا الهاتف: لم يصل أي رمز، ولم يُفتح تطبيق بنك أو موافقة.'));
  return { lines };
}
