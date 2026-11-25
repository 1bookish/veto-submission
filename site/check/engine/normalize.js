// Text normalisation shared by every detector.
// Goal: make "O.T.P", "ОТР" (Cyrillic), "٤٨٢٩١٣", "hxxps://evil[.]top" and
// "رمز  التحقّق" all look the same to the matchers that follow.

const ZERO_WIDTH = /[​-‏‪-‮⁠-⁤﻿­]/g;
const AR_DIACRITICS = /[ؐ-ًؚ-ٰٟۖ-ۭ]/g;
const TATWEEL = /ـ/g;

// Letters from other alphabets that look like Latin letters (common filter-evasion trick).
const CONFUSABLES = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j',
  'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'в': 'b', 'к': 'k', 'м': 'm',
  'н': 'h', 'т': 't', 'г': 'r', 'п': 'n', 'А': 'a', 'В': 'b', 'Е': 'e', 'К': 'k', 'М': 'm',
  'Н': 'h', 'О': 'o', 'Р': 'p', 'С': 'c', 'Т': 't', 'Х': 'x', 'У': 'y', 'І': 'i',
  'ο': 'o', 'α': 'a', 'ν': 'v', 'τ': 't', 'κ': 'k', 'ρ': 'p', 'ι': 'i', 'ϲ': 'c', 'ε': 'e',
  'Α': 'a', 'Β': 'b', 'Ε': 'e', 'Ζ': 'z', 'Η': 'h', 'Ι': 'i', 'Κ': 'k', 'Μ': 'm', 'Ν': 'n',
  'Ο': 'o', 'Ρ': 'p', 'Τ': 't', 'Υ': 'y', 'Χ': 'x', 'ı': 'i', 'ɡ': 'g', 'ⅼ': 'l'
};
const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLES).join('')}]`, 'g');

export function foldDigits(s) {
  return s
    .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 0x660))
    .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 0x6F0));
}

export function normalizeArabic(s) {
  return s
    .replace(AR_DIACRITICS, '')
    .replace(TATWEEL, '')
    .replace(/[أإآٱ]/g, 'ا')
    .replace(/ى/g, 'ي')
    .replace(/ة/g, 'ه')
    .replace(/ؤ/g, 'و')
    .replace(/ئ/g, 'ي')
    .replace(/[،]/g, ',')
    .replace(/[؟]/g, '?');
}

// Reverse "defanged" links people paste from security bulletins.
export function undefang(s) {
  return s
    .replace(/\bhxxp(s?)/gi, 'http$1')
    .replace(/\[\s*(\.|dot)\s*\]|\(\s*(\.|dot)\s*\)|\{\s*\.\s*\}/gi, '.')
    .replace(/\[\s*:\s*\]/g, ':');
}

// Pre-processing applied once to the raw input. Keeps case and original letters
// (URL parsing and evidence quotes need them).
export function normalizeText(raw) {
  let s = String(raw ?? '');
  s = s.normalize('NFKC');
  s = s.replace(ZERO_WIDTH, '');
  s = foldDigits(s);
  s = undefang(s);
  return s;
}

export function foldConfusables(s) {
  return s.replace(CONFUSABLE_RE, ch => CONFUSABLES[ch] ?? ch);
}

// Lower-cased, Arabic-normalised, confusable-folded form used by every pattern matcher.
export function matchForm(s) {
  return normalizeArabic(foldConfusables(String(s)).toLowerCase()).replace(/[ \t]+/g, ' ');
}

const SCRIPT = {
  latin: /[A-Za-zÀ-ɏ]/,
  cyrillic: /[Ѐ-ӿ]/,
  greek: /[Ͱ-Ͽ]/,
  arabic: /[؀-ۿ]/
};

export function scriptsOf(word) {
  return Object.keys(SCRIPT).filter(k => SCRIPT[k].test(word));
}

// Words that are mostly Latin but hide one or two Cyrillic/Greek look-alikes ("Еmirates" with a
// Cyrillic Е). Real Russian/Greek words with a Latin brand inside are mostly non-Latin, so they pass.
export function mixedScriptWords(text) {
  const out = [];
  for (const w of String(text).split(/[\s.,:;!?()"'«»\-\/]+/)) {
    if (w.length < 3) continue;
    const latin = (w.match(/[A-Za-z]/g) || []).length;
    const foreign = (w.match(/[Ͱ-ϿЀ-ӿ]/g) || []).length;
    if (latin >= 2 && foreign >= 1 && foreign <= 2 && latin > foreign) out.push(w);
  }
  return [...new Set(out)];
}

export function detectLang(text) {
  const ar = (text.match(/[؀-ۿ]/g) || []).length;
  const lat = (text.match(/[A-Za-z]/g) || []).length;
  if (ar && lat) return ar > lat * 0.5 ? 'ar' : 'mixed';
  return ar ? 'ar' : 'en';
}

export function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
