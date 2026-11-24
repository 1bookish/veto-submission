// Removes personal data before anything leaves the device (AI deep-check, police report).

function luhn(d) {
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = +d[i];
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

/**
 * @param {string} text
 * @param {{keepPhones?: boolean}} opts keepPhones=true for police reports (scammer numbers are evidence)
 */
export function redact(text, opts = {}) {
  const counts = { card: 0, iban: 0, eid: 0, email: 0, phone: 0, code: 0 };
  let t = String(text ?? '');
  t = t.replace(/\b784[\s\-]?\d{4}[\s\-]?\d{7}[\s\-]?\d\b/g, () => (counts.eid++, '[EMIRATES-ID]'));
  t = t.replace(/\bAE\d{2}(?:[\s]?\d{3,4}){4,5}\b/gi, () => (counts.iban++, '[IBAN]'));
  t = t.replace(/\b(?:\d[ \-]?){12,18}\d\b/g, m => {
    const d = m.replace(/\D/g, '');
    if (d.length >= 13 && d.length <= 19 && luhn(d)) { counts.card++; return `[CARD ••${d.slice(-4)}]`; }
    return m;
  });
  t = t.replace(/[a-z0-9._%+\-]+@((?:[a-z0-9\-]+\.)+[a-z]{2,24})/gi, (m, dom) => (counts.email++, `[EMAIL]@${dom}`));
  if (!opts.keepPhones) {
    t = t.replace(/(?<![\d+])(?:(?:\+|00)\s?971[\s\-]?|0)5\d[\s\-]?\d{3}[\s\-]?\d{4}(?!\d)/g, () => (counts.phone++, '[UAE-MOBILE]'));
    t = t.replace(/(?<![\d+])(?:\+|00)\s?\d{1,3}[\s\-]?\d{2,4}(?:[\s\-]?\d{2,4}){2,4}(?!\d)/g, () => (counts.phone++, '[PHONE]'));
  }
  t = t.replace(/(?<![\d\-.,\/:]|(?:aed|dhs?|usd)\s?)\b(\d{3}[\s\-]\d{3}|\d{4,8})\b(?![\d\-]|[.,]\d|\s?(?:aed|dhs?|درهم))/gi, () => (counts.code++, '[CODE]'));
  return { text: t, counts, removed: Object.values(counts).reduce((a, b) => a + b, 0) };
}
