// HELD-OUT set v1, written after the engine was tuned on corpus.js.
// FIRST BLIND MEASUREMENT (20 Nov 2026, before any fix): 45 msgs, TP 20 FN 5 TN 20 FP 0
//   -> precision 100%, recall 80.0%, F1 88.9%, false-alarm rate 0%.  <- the honest number to quote.
// The 5 misses were then analysed and 4 general gaps fixed (Gulf-Arabic verb forms, "changed my number",
// "I need you to transfer", "is temporarily suspended"). The rental-deposit scam (h-s20) is a known limit.
// Because fixes were informed by this set, it is now a development set: write holdout v2 blind
// (by a teammate who has not read the engine) before quoting a new number.

export const HOLDOUT = [
  // ---- scams ----
  { id: 'h-s01', label: 'scam', channel: 'call', text: 'Good afternoon, I am calling from Dubai Islamic Bank head office. Your debit card will be deactivated today because your Emirates ID has expired. I will send you a verification SMS, kindly share the number with me to update it.' },
  { id: 'h-s02', label: 'scam', channel: 'sms', sender: '+971 56 778 2210', text: 'CBD Alert: Unusual login detected on your account. If this was not you secure your account now at cbd-secure-login.com' },
  { id: 'h-s03', label: 'scam', channel: 'sms', text: 'Your Amazon order #112-55 could not be delivered. Update your payment details within 12 hours: amaz0n-delivery.info' },
  { id: 'h-s04', label: 'scam', channel: 'whatsapp', text: 'Dear customer, you are selected for Lulu Hypermarket 30th anniversary gift AED 1,000 voucher. Click to claim: lulu-anniversary.click' },
  { id: 'h-s05', label: 'scam', channel: 'call', text: 'معك الضابط أحمد من شرطة دبي، حسابك مرتبط بقضية غسيل أموال، لازم تحول رصيدك لحساب آمن اليوم وما تخبر أحد' },
  { id: 'h-s06', label: 'scam', channel: 'sms', text: 'UAE PASS: Your account will be blocked within 24 hours. Verify your identity here: uaepass-verify.com' },
  { id: 'h-s07', label: 'scam', channel: 'whatsapp', text: 'Hello dear, I am Sarah, financial advisor. Our AI trading robot gives 5% daily profit. Start with only 1000 AED deposit in USDT.' },
  { id: 'h-s08', label: 'scam', channel: 'call', text: 'This is Microsoft Windows support. Your computer is infected. Please download AnyDesk so our engineer can fix it.' },
  { id: 'h-s09', label: 'scam', channel: 'sms', text: 'e&: Your mobile line will be barred today due to unpaid bill AED 245. Pay now: eand-pay.online' },
  { id: 'h-s10', label: 'scam', channel: 'whatsapp', text: 'Ate, ibigay mo na yung OTP na pinadala sa phone mo, para ma-verify ang account mo' },
  { id: 'h-s11', label: 'scam', channel: 'call', text: 'Aap ka account band ho jayega, jo OTP aaya hai woh batao' },
  { id: 'h-s12', label: 'scam', channel: 'sms', text: 'Dubai Police: you have a pending violation. To avoid court action pay AED 750 within 2 hours via dubaipolice-gov.org/pay' },
  { id: 'h-s13', label: 'scam', channel: 'email', sender: 'noreply@salik-ae.com', text: 'Salik: Your tag balance is negative. Recharge now to avoid fines of AED 400: https://salik-ae.com/recharge' },
  { id: 'h-s14', label: 'scam', channel: 'whatsapp', text: "Hi it's me, I changed my number. Urgent - I need you to transfer AED 3,500 to my friend's account, I'll return it tonight" },
  { id: 'h-s15', label: 'scam', channel: 'call', text: 'Sir, this is FAB. Someone is trying to add your card to Apple Pay. To stop it, give me the code you get now.' },
  { id: 'h-s16', label: 'scam', channel: 'sms', text: 'ENBD: Dear customer, your credit card reward points 18,400 will expire today. Redeem: enbd-points.co' },
  { id: 'h-s17', label: 'scam', channel: 'whatsapp', text: 'Get 10 tasks daily, each task earns 50 AED. Just rate hotels on Booking. Join our Telegram channel.' },
  { id: 'h-s18', label: 'scam', channel: 'sms', text: 'Emirates Post: Customs duty of AED 9.50 is pending for your package. Pay here: http://em1ratespost.com/pay' },
  { id: 'h-s19', label: 'scam', channel: 'call', text: 'We are calling from the Ministry of Interior, your residency file has an issue. We will send you a code from UAE PASS, please accept the request.' },
  { id: 'h-s20', label: 'scam', channel: 'whatsapp', text: 'Pay the remaining AED 2,000 deposit for the Marina apartment today via this link to reserve it, the owner is abroad: rent-dubai-marina.site/pay' },
  { id: 'h-s21', label: 'scam', channel: 'sms', text: 'ADCB: Your account is temporarily suspended. Call our security team on +971 55 901 2233 to reactivate.' },
  { id: 'h-s22', label: 'scam', channel: 'email', sender: 'support@fab-bank-secure.net', text: 'FAB Security: confirm your username and password to restore access.' },
  { id: 'h-s23', label: 'scam', channel: 'whatsapp', text: 'انا موظف من بنك المشرق، بطاقتك موقوفة، ارسل لي رقم البطاقة والرمز الامني عشان نفعلها' },
  { id: 'h-s24', label: 'scam', channel: 'sms', text: "Your Careem account was used on a new device. If this wasn't you, verify at careem-security.top" },
  { id: 'h-s25', label: 'scam', channel: 'call', text: 'Hello, Etisalat technical team. Your internet will be cut. Install the support app from the link I send you and share your screen.' },
  // ---- legitimate ----
  { id: 'h-l01', label: 'legit', channel: 'sms', sender: 'CBD', text: 'CBD: Your salary of AED 18,500.00 has been credited to account ending 0912.' },
  { id: 'h-l02', label: 'legit', channel: 'sms', sender: 'ADIB', text: 'ADIB: 663201 is your OTP to log in to ADIB Mobile Banking. Never share it with anyone.' },
  { id: 'h-l03', label: 'legit', channel: 'sms', sender: 'HSBC', text: "HSBC: A payment of AED 1,250.00 to DEWA was made from your account. If you don't recognise it, call us on 600 554 722." },
  { id: 'h-l04', label: 'legit', channel: 'whatsapp', text: 'Habibi, landed in Dubai, see you at dinner tonight' },
  { id: 'h-l05', label: 'legit', channel: 'sms', sender: 'Aramex', text: 'Aramex: Your shipment 4482910 will be delivered today between 2-5 PM. Track at aramex.com' },
  { id: 'h-l06', label: 'legit', channel: 'email', sender: 'noreply@icp.gov.ae', text: 'ICP: Your Emirates ID renewal application has been approved. Collect your card from the nearest customer happiness centre.' },
  { id: 'h-l07', label: 'legit', channel: 'whatsapp', text: 'Can you send me the PDF of the contract? Need it for the bank tomorrow.' },
  { id: 'h-l08', label: 'legit', channel: 'sms', sender: 'ADPolice', text: 'Abu Dhabi Police: Scammers impersonate banks and ask for OTPs. Never share codes. Report fraud to Aman 800 2626.' },
  { id: 'h-l09', label: 'legit', channel: 'sms', sender: 'Etisalat', text: 'e&: Your bill of AED 312 is ready. Pay via the e& UAE app or etisalat.ae' },
  { id: 'h-l10', label: 'legit', channel: 'sms', sender: 'RAKBANK', text: 'RAKBANK: Your new debit card PIN has been set successfully. If you did not do this, call 04 213 0000.' },
  { id: 'h-l11', label: 'legit', channel: 'call', text: "Hi, this is Omar from Mashreq. I'm following up on your home loan application. Could you visit our Downtown branch on Sunday with your passport and salary certificate?" },
  { id: 'h-l12', label: 'legit', channel: 'whatsapp', text: 'Mama, I lost my keys again 😅 can you leave the door open?' },
  { id: 'h-l13', label: 'legit', channel: 'sms', sender: 'TDRA', text: 'TDRA: Beware of messages asking you to approve UAE PASS requests you did not initiate. Reject them immediately.' },
  { id: 'h-l14', label: 'legit', channel: 'email', sender: 'orders@noon.com', text: 'noon: Your order has been delivered. Rate your experience in the app.' },
  { id: 'h-l15', label: 'legit', channel: 'sms', sender: 'DubaiPolice', text: 'Dubai Police: Your traffic fine of AED 400 has been paid successfully. Thank you.' },
  { id: 'h-l16', label: 'legit', channel: 'whatsapp', text: "Salam, Friday prayer at 12:30, I'll pick you up at 12." },
  { id: 'h-l17', label: 'legit', channel: 'sms', sender: 'EmiratesNBD', text: 'Emirates NBD: Your Apple Pay was successfully added for card ending 7733. If this was not you, call 600 54 0000.' },
  { id: 'h-l18', label: 'legit', channel: 'whatsapp', text: 'Our school trip fee is AED 120, please pay on the school app by Thursday.' },
  { id: 'h-l19', label: 'legit', channel: 'sms', sender: 'Salik', text: 'Salik: Your account was recharged with AED 100. New balance AED 112.' },
  { id: 'h-l20', label: 'legit', channel: 'sms', sender: 'ADCB', text: 'ADCB: Use 448190 as your one-time password to activate your new device. ADCB will never ask you for this code.' }
];
