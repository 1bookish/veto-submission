// Which messages the rulebook can read. The rulebook and the SMS model know English and Arabic; a message in another
// language (Urdu, Hindi, Tagalog, Malayalam, Russian, Chinese ...) is "out of scope": the AI layer translates and judges
// it when one is configured, and the card says plainly that the rules could not read it.
// English grammar words only: words such as "account", "link" or "bank" are borrowed by Tagalog, Hinglish and others,
// so they say nothing about the language
const EN_WORDS = new Set(['the', 'you', 'your', 'to', 'is', 'and', 'for', 'of', 'a', 'in', 'on', 'this', 'that', 'with', 'be', 'are', 'we', 'our',
  'will', 'has', 'have', 'it', 'at', 'from', 'by', 'or', 'not', 'please', 'now', 'dear', 'here', 'my', 'me', 'i', 'can', 'if', 'an', 'as', 'all',
  'just', 'was', 'were', 'been', 'do', 'does', 'did', 'there', 'their', 'they', 'he', 'she', 'his', 'her', 'them', 'us', 'what', 'when', 'which',
  'who', 'how', 'would', 'could', 'should', 'may', 'than', 'then', 'so', 'but', 'about', 'into', 'out', 'up', 'any', 'no', 'yes', 'hi', 'hello']);
const ARABIC = /[؀-ۿݐ-ݿࢠ-ࣿﭐ-﷿ﹰ-﻿]/;
const LATIN = /[A-Za-zÀ-ɏ]/;
// letters used in Urdu or Persian but not in Arabic: pe, che, zhe, gaf, tte, ddal, rre, noon ghunna, do-chashmi he,
// gol he, bari ye, keheh, farsi ye
const URDU_PERSIAN = /[پچژگٹڈڑںھہےۓکی]/g;

export function scopeOf(text) {
  const s = String(text || '');
  const letters = s.match(/\p{L}/gu) || [];
  if (letters.length < 4) return { inScope: true, lang: 'none' };
  let lat = 0, ar = 0, other = 0;
  for (const c of letters) { if (LATIN.test(c)) lat++; else if (ARABIC.test(c)) ar++; else other++; }
  const n = letters.length;
  if (other / n > 0.3) return { inScope: false, lang: 'other_script' };
  if (ar / n > 0.3 && (s.match(URDU_PERSIAN) || []).length >= 2) return { inScope: false, lang: 'urdu_persian' };
  if (lat / n > 0.6) {
    const words = s.toLowerCase().match(/[a-z]+/g) || [];
    if (words.length >= 6 && words.filter(w => EN_WORDS.has(w)).length / words.length < 0.1) return { inScope: false, lang: 'latin_other' };
  }
  return { inScope: true, lang: ar > lat ? 'ar' : 'en' };
}
