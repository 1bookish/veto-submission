// "Test yourself": 8 messages people in the UAE really receive, half of them scams. You decide, then Veto shows
// what it found (the same engine, on the device). Written from public UAE scam reports and real bank SMS formats;
// the legitimate ones are deliberately hard look-alikes (real OTPs, real fraud alerts, police awareness SMS).
export const QUIZ = [
  { scam: true, channel: 'sms', text: 'RTA: You have an unpaid Salik toll fine of AED 50. Pay within 24 hours to avoid a AED 400 penalty: https://rta-fines-pay.top/ae' },
  { scam: false, channel: 'sms', text: 'Your Emirates NBD debit card ending 4821 was used for AED 142.50 at CARREFOUR MOE on 23/11. If this was not you, call 600 54 0000.' },
  { scam: true, channel: 'whatsapp', text: 'Hello, this is ADCB fraud team. A suspicious transfer of AED 9,800 is pending on your account. To cancel it, read me the 6-digit code we just sent you.' },
  { scam: false, channel: 'sms', text: '482915 is your one-time password for your FAB online purchase of AED 230.00 at NOON. Never share this code with anyone, including bank staff.' },
  { scam: true, channel: 'sms', text: 'Emirates Post: your parcel is on hold because of an incomplete address. Pay the AED 5.89 redelivery fee today: https://emiratespost-redelivery.com/track' },
  { scam: false, channel: 'sms', text: 'Abu Dhabi Police: beware of fraudsters asking for your bank card details or OTP by phone. Report suspicious calls to Aman on 8002626.' },
  { scam: true, channel: 'whatsapp', text: 'Hi Mum, this is my new number, my phone fell in water. Can you send me AED 2,000 urgently for a bill? I will explain later, don’t call the old number.' },
  { scam: false, channel: 'whatsapp', text: 'Hi, your Talabat order from Al Mallah is on its way. Your rider Imran will arrive in about 20 minutes.' }
];
