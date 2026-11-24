// "Is this app a virus?", static check of an Android app file (APK) WITHOUT installing or running it.
//
// An APK is a ZIP file. Its AndroidManifest.xml (stored in Android's binary XML format) lists every
// power the app will ask for. Banking trojans seen in the Gulf (fake bank updates, fake UAE PASS,
// fake parcel apps) need the same toolkit: read SMS codes, read the screen (Accessibility), draw fake
// screens over the bank app, read notifications, block uninstalling. Veto reads the manifest and
// explains, in plain words, what the app could do to you.
//
// Pure Node (zlib + crypto), no Android SDK needed on the server.

import zlib from 'node:zlib';
import crypto from 'node:crypto';

export const sha256 = buf => crypto.createHash('sha256').update(buf).digest('hex');

// ---------- ZIP: read one entry ----------
export function unzipEntry(buf, wanted) {
  let eocd = -1;
  for (let i = buf.length - 22, min = Math.max(0, buf.length - 65557); i >= min; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a ZIP/APK file');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const names = [];
  let found = null;
  for (let k = 0; k < count && p + 46 <= buf.length; k++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20);
    const nlen = buf.readUInt16LE(p + 28), elen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    const off = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nlen);
    names.push(name);
    if (name === wanted) found = { method, csize, off };
    p += 46 + nlen + elen + clen;
  }
  let data = null;
  if (found && buf.readUInt32LE(found.off) === 0x04034b50) {
    const start = found.off + 30 + buf.readUInt16LE(found.off + 26) + buf.readUInt16LE(found.off + 28);
    const raw = buf.subarray(start, start + found.csize);
    // Android ignores some header tricks malware uses to break analysers (e.g. a bogus method):
    // try the declared method first, then the other one.
    const tries = found.method === 0 ? [r => r, r => zlib.inflateRawSync(r)] : [r => zlib.inflateRawSync(r, { maxOutputLength: 8 << 20 }), r => r];
    for (const t of tries) { try { const d = t(raw); if (d.readUInt16LE(0) === 0x0003) { data = d; break; } } catch { /* next */ } }
  }
  return { names, data };
}

// ---------- Android binary XML ----------
const ANDROID_ATTR = { 0x01010001: 'label', 0x01010003: 'name', 0x01010006: 'permission', 0x0101021b: 'versionCode', 0x0101021c: 'versionName' };

function readPool(buf, p, hsz) {
  const count = buf.readUInt32LE(p + 8), flags = buf.readUInt32LE(p + 16), strStart = buf.readUInt32LE(p + 20);
  const utf8 = (flags & 0x100) !== 0;
  const out = new Array(count).fill('');
  for (let i = 0; i < count; i++) {
    try {
      let q = p + strStart + buf.readUInt32LE(p + hsz + i * 4);
      if (utf8) {
        if (buf[q++] & 0x80) q++;                       // UTF-16 length, unused
        let len = buf[q++];
        if (len & 0x80) len = ((len & 0x7f) << 8) | buf[q++];
        out[i] = buf.toString('utf8', q, q + len);
      } else {
        let len = buf.readUInt16LE(q); q += 2;
        if (len & 0x8000) { len = ((len & 0x7fff) << 16) | buf.readUInt16LE(q); q += 2; }
        out[i] = buf.toString('utf16le', q, q + len * 2);
      }
    } catch { /* leave empty */ }
  }
  return out;
}

export function parseAxml(buf) {
  if (buf.readUInt16LE(0) !== 0x0003) throw new Error('manifest is not Android binary XML');
  let strings = [];
  const resMap = [];
  const elements = [];
  let p = buf.readUInt16LE(2), depth = 0;
  while (p + 8 <= buf.length) {
    const type = buf.readUInt16LE(p), hsz = buf.readUInt16LE(p + 2), size = buf.readUInt32LE(p + 4);
    if (size < 8 || p + size > buf.length) break;
    if (type === 0x0001) strings = readPool(buf, p, hsz);
    else if (type === 0x0180) for (let i = p + hsz; i + 4 <= p + size; i += 4) resMap.push(buf.readUInt32LE(i));
    else if (type === 0x0102) {
      const nameIdx = buf.readUInt32LE(p + 20);
      const attrStart = buf.readUInt16LE(p + 24), attrSize = buf.readUInt16LE(p + 26) || 20, attrCount = buf.readUInt16LE(p + 28);
      const attrs = {};
      for (let a = 0; a < attrCount; a++) {
        const q = p + 16 + attrStart + a * attrSize;
        if (q + 20 > p + size) break;
        const an = buf.readUInt32LE(q + 4), raw = buf.readUInt32LE(q + 8), dt = buf.readUInt8(q + 15), data = buf.readUInt32LE(q + 16);
        // Android identifies attributes by resource id, not by the (forgeable) string, so do we.
        const key = (resMap[an] && ANDROID_ATTR[resMap[an]]) || strings[an] || `attr${an}`;
        let val;
        if (raw !== 0xffffffff) val = strings[raw];
        else if (dt === 0x03) val = strings[data];
        else if (dt === 0x12) val = data !== 0;
        else if (dt === 0x10 || dt === 0x11) val = data | 0;
        else if (dt === 0x01) val = '@0x' + data.toString(16);
        else val = data;
        attrs[key] = val;
      }
      elements.push({ name: strings[nameIdx] || '', attrs, depth });
      depth++;
    } else if (type === 0x0103) depth = Math.max(0, depth - 1);
    p += size;
  }
  return elements;
}

// ---------- what the app could do to you ----------
const P = 'android.permission.';
export const CAPABILITIES = [
  { id: 'sms', w: 0.55, perms: [P + 'RECEIVE_SMS', P + 'READ_SMS'], actions: ['android.provider.Telephony.SMS_RECEIVED'],
    en: 'read your text messages, including the codes your bank sends', ar: 'قراءة رسائلك النصية، ومنها الرموز التي يرسلها البنك' },
  { id: 'accessibility', w: 0.6, perms: [P + 'BIND_ACCESSIBILITY_SERVICE'], actions: ['android.accessibilityservice.AccessibilityService'],
    en: 'see everything on your screen and tap buttons for you (Accessibility)', ar: 'رؤية كل ما على شاشتك والضغط على الأزرار نيابةً عنك (خدمة تسهيل الاستخدام)' },
  { id: 'notifications', w: 0.45, perms: [P + 'BIND_NOTIFICATION_LISTENER_SERVICE'], actions: ['android.service.notification.NotificationListenerService'],
    en: 'read all your notifications, codes, chats, bank alerts', ar: 'قراءة كل إشعاراتك، الرموز والمحادثات وتنبيهات البنك' },
  { id: 'overlay', w: 0.35, perms: [P + 'SYSTEM_ALERT_WINDOW'], actions: [],
    en: 'draw fake screens on top of your banking app', ar: 'رسم شاشات مزيّفة فوق تطبيق البنك' },
  { id: 'admin', w: 0.5, perms: [P + 'BIND_DEVICE_ADMIN'], actions: ['android.app.action.DEVICE_ADMIN_ENABLED'],
    en: 'make itself device administrator so you cannot uninstall it', ar: 'جعل نفسه مسؤولاً عن الجهاز فلا تستطيع حذفه' },
  { id: 'install', w: 0.3, perms: [P + 'REQUEST_INSTALL_PACKAGES'], actions: [],
    en: 'download and install more apps', ar: 'تنزيل تطبيقات أخرى وتثبيتها' },
  // FakeCall-style trojans (Kaspersky 2022, Zimperium 2024): when you dial your bank, the call silently goes to the criminals
  { id: 'call_hijack', w: 0.75, perms: [P + 'BIND_CALL_REDIRECTION_SERVICE'], actions: ['android.telecom.CallRedirectionService'],
    en: 'secretly send the calls you make to your bank to someone else', ar: 'تحويل مكالماتك إلى البنك سراً إلى شخص آخر' },
  { id: 'dialer', w: 0.5, perms: [P + 'BIND_INCALL_SERVICE'], actions: ['android.telecom.InCallService'],
    en: 'replace your phone app and show fake call screens', ar: 'استبدال تطبيق الهاتف وعرض شاشات مكالمات مزيّفة' },
  { id: 'calls', w: 0.3, perms: [P + 'CALL_PHONE', P + 'ANSWER_PHONE_CALLS', P + 'PROCESS_OUTGOING_CALLS', P + 'READ_CALL_LOG'], actions: [],
    en: 'make, answer or redirect your phone calls', ar: 'إجراء مكالماتك أو الرد عليها أو تحويلها' },
  { id: 'send_sms', w: 0.3, perms: [P + 'SEND_SMS'], actions: [],
    en: 'send text messages from your number (to spread itself)', ar: 'إرسال رسائل من رقمك (لينشر نفسه)' },
  { id: 'apps', w: 0.15, perms: [P + 'QUERY_ALL_PACKAGES'], actions: [],
    en: 'see which banking apps you have', ar: 'معرفة تطبيقات البنوك الموجودة لديك' },
  { id: 'contacts', w: 0.1, perms: [P + 'READ_CONTACTS'], actions: [],
    en: 'read your contacts', ar: 'قراءة جهات اتصالك' },
  { id: 'boot', w: 0.05, perms: [P + 'RECEIVE_BOOT_COMPLETED'], actions: ['android.intent.action.BOOT_COMPLETED'],
    en: 'start itself every time the phone starts', ar: 'تشغيل نفسه كلما شغّلت الهاتف' }
];

export function inspectApk(buf) {
  const out = { sha256: sha256(buf), size: buf.length, ok: false };
  try {
    const { names, data } = unzipEntry(buf, 'AndroidManifest.xml');
    out.entries = names.length;
    out.hasCode = names.some(n => /^classes\d*\.dex$/.test(n));
    out.nativeLibs = names.filter(n => /^lib\/.+\.so$/.test(n)).length;
    if (!data) { out.error = 'no readable AndroidManifest.xml'; return out; }
    const els = parseAxml(data);
    const man = els.find(e => e.name === 'manifest') || { attrs: {} };
    const app = els.find(e => e.name === 'application') || { attrs: {} };
    out.package = typeof man.attrs.package === 'string' ? man.attrs.package : null;
    out.versionName = typeof man.attrs.versionName === 'string' ? man.attrs.versionName : null;
    out.label = typeof app.attrs.label === 'string' && !app.attrs.label.startsWith('@') ? app.attrs.label : null;
    const perms = new Set(), actions = new Set();
    for (const e of els) {
      if (/^uses-permission/.test(e.name) && typeof e.attrs.name === 'string') perms.add(e.attrs.name);
      if (/^(service|receiver|activity|provider)$/.test(e.name) && typeof e.attrs.permission === 'string') perms.add(e.attrs.permission);
      if (e.name === 'action' && typeof e.attrs.name === 'string') actions.add(e.attrs.name);
    }
    out.permissions = [...perms].sort();
    out.capabilities = CAPABILITIES.filter(c => c.perms.some(p => perms.has(p)) || c.actions.some(a => actions.has(a)))
      .map(({ id, w, en, ar }) => ({ id, w, en, ar }));
    const has = id => out.capabilities.some(c => c.id === id);
    // The banking-trojan toolkit: a way to SEE your codes + a way to CONTROL or FAKE your screen.
    out.trojanProfile = ((has('sms') || has('notifications')) && (has('accessibility') || has('overlay'))) || (has('call_hijack') && (has('dialer') || has('overlay') || has('calls')));
    const risk = 1 - out.capabilities.reduce((p, c) => p * (1 - c.w), 1);
    out.risk = +(out.trojanProfile ? Math.max(risk, 0.95) : risk).toFixed(3);
    out.ok = true;
  } catch (e) {
    out.error = String(e.message || e);
  }
  return out;
}
