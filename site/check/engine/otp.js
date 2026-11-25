// OTP Guard, reads a one-time-code message and explains, in plain words, what the
// code actually unlocks and what a scammer could do with it.

import { rx } from './lexicon.js';

const OTP_WORDS = rx([
  String.raw`\botp\b`, String.raw`\bone[\s-]?time\b`, String.raw`\b(?:verification|confirmation|activation|authentication|security|login|access|whatsapp|telegram|instagram|facebook|google|uae ?pass)\s?code\b`,
  String.raw`\bpasscode\b`, String.raw`\bcode is\b`, String.raw`\bis your (?:\w+ )?code\b`, String.raw`\bcode:`, String.raw`\bpin\b`,
  String.raw`\byour (?:\w+ )?code\b`, String.raw`\bcode (?:to|for)\b`,
  'رمز التحقق', 'رمز التفعيل', 'كلمة المرور لمرة واحدة', 'رمز المرور', 'رمزك', 'الرمز', 'كود'
], 'iu');
const CODE_RE = /(?<![\d\-.,\/:])(\d{3}[\s\-]\d{3}|\d{4,8})(?![\d\-]|[.,]\d|\s?(?:aed|dhs?|درهم|%))/gi;

const PURPOSES = [
  { id: 'wallet', re: rx([String.raw`\b(?:apple|google|samsung|garmin|fitbit) ?pay\b`, String.raw`\bwallet\b`, String.raw`\btokeni[sz]`, String.raw`\badd(?:ing)? (?:your )?card to\b`, 'محفظة', 'ابل باي', 'جوجل باي']) },
  { id: 'beneficiary', re: rx([String.raw`\bbeneficiar`, String.raw`\bpayee\b`, 'مستفيد']) },
  { id: 'contact_change', re: rx([String.raw`\b(?:change|update|updating|changing)\b[^.]{0,20}\b(?:mobile|phone|number|e-?mail)\b`, 'تغيير رقم', 'تحديث رقم', 'تغيير البريد']) },
  { id: 'password_reset', re: rx([String.raw`\breset\b`, String.raw`\bforgot\b`, String.raw`\b(?:change|new) password\b`, 'اعادة تعيين', 'نسيت كلمة']) },
  { id: 'whatsapp', re: rx([String.raw`\bwhatsapp\b`, 'واتساب', 'واتس اب']) },
  { id: 'social', re: rx([String.raw`\b(?:telegram|instagram|facebook|snapchat|tiktok|gmail|google account|apple id|microsoft account)\b`, 'تيليجرام', 'انستغرام', 'فيسبوك']) },
  { id: 'uaepass', re: rx([String.raw`\buae ?pass\b`, 'الهوية الرقمية']) },
  { id: 'transfer', re: rx([String.raw`\btransfer\b`, String.raw`\bremittance\b`, String.raw`\bsend money\b`, 'تحويل']) },
  { id: 'device', re: rx([String.raw`\bnew device\b`, String.raw`\bregister(?:ing)? (?:a |your )?(?:new )?(?:device|app|phone)\b`, String.raw`\b(?:app|device) activation\b`, String.raw`\bactivate (?:the |your )?(?:app|mobile banking)\b`, 'جهاز جديد', 'تفعيل التطبيق']) },
  { id: 'card_activation', re: rx([String.raw`\bactivat(?:e|ion|ing)\b[^.]{0,15}\bcard\b`, String.raw`\bcard activation\b`, String.raw`\b(?:set|generate|generation of) (?:your )?pin\b`, 'تفعيل البطاقة']) },
  { id: 'login', re: rx([String.raw`\blog ?in\b`, String.raw`\bsign[\s-]?in\b`, String.raw`\bonline banking\b`, String.raw`\bmobile banking\b`, String.raw`\binternet banking\b`, 'تسجيل الدخول', 'الدخول']) },
  { id: 'purchase', re: rx([String.raw`\bpurchase\b`, String.raw`\btransaction\b`, String.raw`\bpayment\b`, String.raw`\bspent\b`, String.raw`\bat [a-z0-9]`, String.raw`\btxn\b`, 'عملية شراء', 'معاملة', 'دفع', 'شراء']) }
];

const RISKY_MERCHANTS = /(binance|bybit|okx|kucoin|crypto\.?com|coinbase|rain\b|kraken|bitoasis|western union|moneygram|wise\b|remitly|worldremit|payoneer|skrill|neteller|paysafe|google play|itunes|apple\.com\/bill|steam|razer|bet|casino)/i;

export const PURPOSE_TEXT = {
  wallet: {
    en: (o) => `adding your card to a phone wallet (Apple Pay / Google Pay)`,
    ar: () => 'إضافة بطاقتك إلى محفظة هاتف (Apple Pay / Google Pay)',
    riskEn: 'Whoever gets this code can put YOUR card on THEIR phone and spend from it anywhere, even after you hang up.',
    riskAr: 'من يحصل على هذا الرمز يستطيع إضافة بطاقتك إلى هاتفه والصرف منها في أي مكان، حتى بعد انتهاء المكالمة.'
  },
  beneficiary: {
    en: () => 'adding a NEW beneficiary to your bank account', ar: () => 'إضافة مستفيد جديد إلى حسابك البنكي',
    riskEn: 'This lets someone register their own account as a payee so they can move your money out.',
    riskAr: 'يسمح لشخص بتسجيل حسابه كمستفيد ليحوّل أموالك إليه.'
  },
  contact_change: {
    en: () => 'changing the mobile number or e-mail on your account', ar: () => 'تغيير رقم الهاتف أو البريد المسجّل في حسابك',
    riskEn: 'After this, every future code goes to the scammer instead of you.', riskAr: 'بعدها ستذهب كل الرموز القادمة إلى المحتال بدلاً منك.'
  },
  password_reset: {
    en: () => 'resetting your password', ar: () => 'إعادة تعيين كلمة المرور',
    riskEn: 'This lets someone set a new password and lock you out of your own account.', riskAr: 'يسمح لشخص بتعيين كلمة مرور جديدة وإخراجك من حسابك.'
  },
  whatsapp: {
    en: () => 'moving your WhatsApp account to another phone', ar: () => 'نقل حساب واتساب الخاص بك إلى هاتف آخر',
    riskEn: 'Sharing it hands over your WhatsApp, the scammer then messages your family and friends asking for money as you.',
    riskAr: 'مشاركته تعني تسليم حساب واتساب، ثم يراسل المحتال عائلتك وأصدقاءك باسمك طالباً المال.'
  },
  social: {
    en: () => 'signing in to one of your online accounts', ar: () => 'تسجيل الدخول إلى أحد حساباتك',
    riskEn: 'Sharing it hands over that account.', riskAr: 'مشاركته تعني تسليم ذلك الحساب.'
  },
  uaepass: {
    en: () => 'a UAE PASS login or digital signature', ar: () => 'تسجيل دخول أو توقيع رقمي عبر UAE PASS',
    riskEn: 'With it someone can log in to government services or sign documents as you.', riskAr: 'به يستطيع شخص الدخول إلى الخدمات الحكومية أو توقيع مستندات باسمك.'
  },
  transfer: {
    en: (o) => `a transfer${o.amount ? ` of ${o.amount}` : ''} from your account`, ar: (o) => `تحويل${o.amount ? ` بقيمة ${o.amount}` : ''} من حسابك`,
    riskEn: 'Whoever has this code can complete that transfer.', riskAr: 'من يملك هذا الرمز يستطيع إتمام التحويل.'
  },
  device: {
    en: () => 'linking a new phone or app to your bank account', ar: () => 'ربط هاتف أو تطبيق جديد بحسابك البنكي',
    riskEn: 'This gives someone a permanent foothold in your account from their own phone.', riskAr: 'يمنح شخصاً وصولاً دائماً إلى حسابك من هاتفه.'
  },
  card_activation: {
    en: () => 'activating a card or setting its PIN', ar: () => 'تفعيل بطاقة أو تعيين رقمها السري',
    riskEn: 'If this is a card you did not receive, someone may be activating it.', riskAr: 'إذا لم تستلم البطاقة، قد يكون شخص آخر يفعّلها.'
  },
  login: {
    en: () => 'signing in to your online / mobile banking', ar: () => 'تسجيل الدخول إلى خدماتك المصرفية',
    riskEn: 'This gives someone full access to your bank account.', riskAr: 'يمنح شخصاً وصولاً كاملاً إلى حسابك البنكي.'
  },
  purchase: {
    en: (o) => `a payment${o.amount ? ` of ${o.amount}` : ''}${o.merchant ? ` at ${o.merchant}` : ''}`,
    ar: (o) => `عملية دفع${o.amount ? ` بقيمة ${o.amount}` : ''}${o.merchant ? ` لدى ${o.merchant}` : ''}`,
    riskEn: 'Whoever has this code can complete that payment from your card.', riskAr: 'من يملك هذا الرمز يستطيع إتمام الدفع من بطاقتك.'
  },
  generic: {
    en: () => 'an action on one of your accounts', ar: () => 'إجراء على أحد حساباتك',
    riskEn: 'Only type it into the app or website you are using yourself, right now.', riskAr: 'اكتبه فقط في التطبيق أو الموقع الذي تستخدمه أنت الآن.'
  }
};

function findMerchant(normText) {
  const t = normText.replace(/\b(?:aed|dhs?|usd|sar|inr)\s?[\d,.]+/gi, ' ').replace(/[\d,.]+\s?(?:aed|dhs?|درهم)/gi, ' ');
  const STOP = /^(your|the|a|an|card|account|ending|you|complete|confirm|verify|this|that|our|purchase|transaction|payment|online|mobile|least|any|anyone)\b/i;
  const re = /\bat ([a-z0-9&*'.\- ]{2,32}?)(?= on\b| for\b| using\b| with\b| card\b| from\b| via\b|[,;]|\.(?:\s|$)| is\b| otp\b| has\b| was\b|$)/gi;
  for (const m of t.matchAll(re)) {
    const c = m[1].trim();
    if (c.length >= 2 && !STOP.test(c)) return c;
  }
  const ar = /لدى ([^\s,.،]+(?: [^\s,.،]+){0,2})/.exec(normText);
  return ar ? ar[1] : null;
}

export function analyzeOtp(normText, ex) {
  const dt = ex.dt;
  const hasWord = OTP_WORDS.test(dt);
  if (!hasWord) return null;
  // find a code that is not a phone number, amount, date or card fragment
  const phones = ex.phones.map(p => [p.index, p.index + p.raw.length]);
  const amounts = ex.amounts.map(a => [a.index, a.index + a.raw.length]);
  const inRanges = (i, rs) => rs.some(([a, b]) => i >= a && i < b);
  let code = null;
  CODE_RE.lastIndex = 0;
  for (const m of normText.matchAll(CODE_RE)) {
    if (inRanges(m.index, phones) || inRanges(m.index, amounts)) continue;
    const digits = m[1].replace(/\D/g, '');
    if (/^(19|20)\d\d$/.test(digits) && digits.length === 4) continue; // a year
    const before = normText.slice(Math.max(0, m.index - 18), m.index);
    if (/(ending|ends|end in|x{2,}|\*{2,}|card|a\/c|acct|account|no\.?|order|ref\w*|#|رقم|المنتهية)\s*(in|with|:)?\s*$/i.test(before)) continue;
    code = { raw: m[1], digits, index: m.index };
    break;
  }
  if (!code) return null;
  let purpose = 'generic';
  for (const p of PURPOSES) { p.re.lastIndex = 0; if (p.re.test(dt)) { purpose = p.id; break; } }
  const amount = ex.amounts[0] ? `${ex.amounts[0].currency} ${ex.amounts[0].value.toLocaleString('en-US', { minimumFractionDigits: ex.amounts[0].value % 1 ? 2 : 0 })}` : null;
  let merchant = findMerchant(normText);
  if (merchant && merchant.length > 30) merchant = merchant.slice(0, 30);
  if (merchant && purpose === 'generic') purpose = 'purchase';
  const o = { amount, merchant: merchant ? merchant.toUpperCase() : null };
  const t = PURPOSE_TEXT[purpose];
  return {
    code: code.digits,
    masked: code.digits.replace(/\d(?=\d{2})/g, '•'),
    purpose,
    amount: o.amount,
    merchant: o.merchant,
    riskyMerchant: !!(merchant && RISKY_MERCHANTS.test(merchant)),
    unlocks: { en: t.en(o), ar: t.ar(o) },
    risk: { en: t.riskEn, ar: t.riskAr }
  };
}
