// Tokens for the on-device SMS model: words, word pairs and three cues (a link, a number of four or more digits,
// Arabic script). The trainer (tools/build-sms-model.js) and the phone use this one function, so they cannot differ.
export function smsTokens(text) {
  const t = String(text).toLowerCase();
  const words = t.split(/[^\p{L}\p{N}]+/u).filter(w => w.length > 1 && w.length < 30);
  const out = new Set(words);
  for (let i = 0; i + 1 < words.length; i++) out.add(words[i] + ' ' + words[i + 1]);
  if (/https?:\/\/|www\.|\.(com|net|org|xyz|top|info|site|online|icu|shop|ly|me|co)\b/.test(t)) out.add('__LINK__');
  if (/\d{4,}/.test(t)) out.add('__LONGNUM__');
  if (/[؀-ۿ]/.test(t)) out.add('__ARABIC__');
  return [...out];
}
