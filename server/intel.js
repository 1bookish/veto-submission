// Optional online reputation look-ups. OFF unless the operator sets a key in the environment:
//   ABUSECH_KEY  free Auth-Key from https://auth.abuse.ch  -> URLhaus (malware links) + MalwareBazaar (malware files)
//   IPQS_KEY     IPQualityScore key (free tier ~1,000 look-ups/month) -> phone-number fraud reputation
// Privacy: only the link, the file's SHA-256 or the phone number is sent, never the message text,
// never who the user is. Truecaller has no public look-up API (its SDK only verifies your OWN number),
// so Veto does not scrape it.

const ABUSE = () => process.env.ABUSECH_KEY || '';
const IPQS = () => process.env.IPQS_KEY || '';
export const intelConfigured = () => ({ abusech: !!ABUSE(), ipqs: !!IPQS() });

async function postForm(url, form, headers = {}) {
  const r = await fetch(url, {
    method: 'POST', body: new URLSearchParams(form), signal: AbortSignal.timeout(7000),
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'Veto-anti-scam/0.2', ...headers }
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

/** URLhaus: is this exact link a known malware-download link? */
export async function urlhausUrl(url) {
  if (!ABUSE()) return null;
  try {
    const j = await postForm('https://urlhaus-api.abuse.ch/v1/url/', { url }, { 'Auth-Key': ABUSE() });
    if (j.query_status === 'ok') return { listed: true, threat: j.threat || null, status: j.url_status || null, tags: j.tags || [], ref: j.urlhaus_reference || null };
    return { listed: false, status: j.query_status };
  } catch (e) { return { error: String(e.message || e) }; }
}

/** MalwareBazaar: is this file (by SHA-256) a known malware sample? */
export async function bazaarHash(sha256) {
  if (!ABUSE()) return null;
  try {
    const j = await postForm('https://mb-api.abuse.ch/api/v1/', { query: 'get_info', hash: sha256 }, { 'Auth-Key': ABUSE() });
    const d = j.query_status === 'ok' && Array.isArray(j.data) ? j.data[0] : null;
    if (d) return { known: true, signature: d.signature || null, fileType: d.file_type || null, tags: d.tags || [], firstSeen: d.first_seen || null };
    return { known: false, status: j.query_status };
  } catch (e) { return { error: String(e.message || e) }; }
}

/** IPQualityScore phone reputation. Fields per https://www.ipqualityscore.com/documentation/phone-number-validation-api/response-parameters */
export async function ipqsPhone(number) {
  if (!IPQS()) return null;
  const n = String(number || '').replace(/[^\d+]/g, '').replace(/^00/, '+');
  if (n.replace(/\D/g, '').length < 6) return { error: 'too short' };
  try {
    const url = `https://www.ipqualityscore.com/api/json/phone/${encodeURIComponent(IPQS())}/${encodeURIComponent(n)}?strictness=1&country[]=AE`;
    const r = await fetch(url, { signal: AbortSignal.timeout(7000), headers: { 'user-agent': 'Veto-anti-scam/0.2' } });
    const j = await r.json();
    if (!j.success) return { error: j.message || 'lookup failed' };
    return phoneVerdict({
      fraudScore: j.fraud_score, recentAbuse: j.recent_abuse, spammer: j.spammer, risky: j.risky, voip: j.VOIP, prepaid: j.prepaid,
      lineType: j.line_type, carrier: j.carrier !== 'N/A' ? j.carrier : null, country: j.country, valid: j.valid, active: j.active,
      name: j.name && j.name !== 'N/A' ? j.name : null, leaked: j.leaked, source: 'IPQualityScore'
    });
  } catch (e) { return { error: String(e.message || e) }; }
}

/** Turns raw reputation fields into Veto signals (shared by the server and the Android app's logic). */
export function phoneVerdict(rep) {
  const s = [];
  const add = (id, w, en, ar) => s.push({ id, w, en, ar });
  if (rep.recentAbuse || rep.spammer) add('reported', 0.85, 'This number was recently reported for scam or spam calls.', 'تم الإبلاغ عن هذا الرقم مؤخراً بسبب مكالمات احتيال أو إزعاج.');
  else if (rep.fraudScore >= 85) add('fraud_score', 0.75, `Fraud score ${rep.fraudScore}/100. This number is linked to fraud.`, `درجة الاحتيال ${rep.fraudScore}/100، هذا الرقم مرتبط بالاحتيال.`);
  else if (rep.fraudScore >= 75) add('fraud_score', 0.45, `Fraud score ${rep.fraudScore}/100, suspicious.`, `درجة الاحتيال ${rep.fraudScore}/100، مشبوه.`);
  if (rep.voip) add('voip', 0.3, 'Internet (VoIP) number, anyone can get one anonymously.', 'رقم إنترنت (VoIP)، يمكن لأي شخص الحصول عليه دون هوية.');
  if (/premium/i.test(rep.lineType || '')) add('premium', 0.7, 'Premium-rate number, calling back can cost a lot.', 'رقم بتعرفة مرتفعة، معاودة الاتصال قد تكلّفك كثيراً.');
  if (rep.valid === false) add('invalid', 0.5, 'This is not a valid phone number. It may be faked (spoofed).', 'هذا ليس رقماً صالحاً، قد يكون مزوّراً.');
  const risk = 1 - s.reduce((p, x) => p * (1 - x.w), 1);
  return { ...rep, signals: s, risk: +risk.toFixed(3) };
}
