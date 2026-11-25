# 1-minute demo video (submission: recorded by us, no AI video)

Record the screen (laptop) and the phone (a second phone filming it, or `scrcpy`). Speak live or add a voice-over. No music needed.

| Time | Show | Say (short) |
|---|---|---|
| 0:00 to 0:08 | Phone: a fake "Emirates NBD" SMS arrives, Kiki jumps out red | "A scam SMS. Veto catches it on the phone: Emirates NBD never asks for your OTP." |
| 0:08 to 0:18 | Dial the number written in the SMS → **Veto held this call** → tap *Call Emirates NBD: 600 54 0000* | "And if you call the scammer's number anyway, Veto holds the call and offers the bank's real number." |
| 0:18 to 0:32 | Laptop: X-ray `salik-fine-pay.localhost` → "what it wants", fake data sent to a Telegram bot (blocked) → open *Evidence for investigators* | "Veto opens the link in a sealed browser: it wants your card and OTP, sends them to a criminal's Telegram bot, wears Salik's real icon, and hides from computers." |
| 0:32 to 0:46 | `/sentinel.html`: KPIs, *Run the hunt* progress, suspects list, a campaign card | "Sentinel hunts these sites before the SMS goes out: ten thousand look-alike names, the registered ones, the live ones, and links them into campaigns by the same Telegram bot." |
| 0:46 to 0:55 | Open the takedown pack (evidence + abuse contacts + STIX) | "One click: the evidence pack for the registrar, the host and aeCERT." |
| 0:55 to 1:00 | Title slide | "Veto.ai. Scammers can fake a logo. They can't fake the bank's own rules." |

Before recording: `npm start`; X-ray the three demo pages once (bank, parcel, Salik) so the campaign exists; run one hunt
(about 5 minutes) so the suspects list is full; on the phone, the call-redirection role must be on (Veto setup screen → *Stop calls to fake numbers*).

# Final pitch (26 Nov): 3-minute demo + 2-minute Q&A, built on the judging sheet

The official sheet scores **accuracy 30 %, early detection & coverage 25 %, explainability & actionability 20 %,
UAE relevance & innovation 15 %, feasibility & presentation 10 %**. Every minute below earns one of them, in that order
of weight. Have four browser tabs open before you start: `/judge.html`, `/sentinel.html`, the app `/` and one
takedown pack; the phone on the table, Veto open, the scammer phone ready.

| Time | Criterion | Show | Say |
|---|---|---|---|
| 0:00 to 0:20 | (problem + solution, max 1 min) | Title slide | "Scam sites live for days, victims report after the money is gone. Veto finds the site before the SMS goes out, proves what it does, hands police the takedown file, and on the phone stops the call to the scammer's number." |
| 0:20 to 0:55 | **Accuracy 30 %** | `/judge.html` → *Load a sample* (or the judges' own list) → **Judge them** | "This is how you can test us: paste your hidden list. Allowlist, rulebook, a URL model trained on half a million dated public URLs, and a popularity guard. On the last 30 days of real phishing, never seen in training: precision X, recall Y, false alarms Z, and **zero** false alarms on 2,231 pages of official UAE sites. Online mode follows short links and redirects, and catches cloaking." |
| 0:55 to 1:35 | **Early detection 25 %** | `/sentinel.html` → *Run the hunt* (or the result of the morning run): 70,000 domains registered yesterday read in 20 s, ~10,000 look-alikes checked in DNS, certificate logs, search ads and Maps listings (key) | "Yesterday 70,000 domains were registered worldwide. Veto read every one in twenty seconds: a Salik look-alike registered yesterday (name withheld until it is reported). Before a certificate, before an SMS, before a victim." |
| 1:35 to 2:15 | **Explainability 20 %** | App → X-ray `http://salik-fine-pay.localhost:8787/` → what it wants → the fake-data trap caught the Telegram bot → Evidence for investigators → **Takedown pack** → *evidence.zip* | "Veto typed FAKE card details: the page sent them to a criminal's Telegram bot, blocked. It wears Salik's real icon and shows computers a travel blog. One click: PDF, screenshot, WHOIS, hosting, timestamps, SHA-256 manifest, STIX for aeCERT." |
| 2:15 to 2:40 | **UAE + innovation 15 %** | Console → the **scam network graph**: three scams, one Telegram bot | "Three different scams, bank, parcel, Salik: one criminal. Veto links sites by what criminals reuse, the bot, the analytics ID, the kit." |
| 2:40 to 3:00 | **Feasibility 10 %** (+ the trump card) | Phone: a scam SMS arrives (Kiki STOP) → dial its number → **Veto held this call** → *Call Emirates NBD 600 54 0000* | "And for the person who already has the scam SMS: Veto holds the call to the scammer's number and offers the bank's real one. It runs on a laptop and a phone today; the police pilot is the console plus Aman." |

**Q&A cheat-sheet (2 min):** accuracy method (time split, never-seen domains, honest misses) · privacy (the phone checks
on-device; the server stores scam SITES, never people) · scale (DNS + NRD + model are milliseconds per name; the X-ray is
the only heavy step and runs only on the top suspects) · what is not done (live Search/Maps need a SerpApi or Google key;
voice deepfakes; iPhone call interception is impossible on iOS).

# 3-minute demo script

**Setup (before you go on stage):** `npm start` on the laptop; open http://localhost:8787 full-screen. Android phone with Veto installed (USB install, see HANDOFF.md), every row "On", and WhatsApp + Messages switched on under *Apps Veto reads*. A teammate's phone is the "scammer": its number must NOT be saved in the demo phone. Save a second teammate as "Mum". Same Wi-Fi for both; in Veto → Settings: online checks ON,
server `http://<laptop-ip>:8787`. Volume up. Rehearse once. Keep this file open
server `http://<laptop-ip>:8787` (emulator: `http://10.0.2.2:8787`). Volume up. Rehearse once. Keep this file open
on a second screen.

| Time | Show | Say |
|---|---|---|
| 0:00 to 0:15 | Title screen | "Every scam ends with the same ask: a code, a card detail, an app, an approval or a transfer. Scammers can fake a caller ID, a logo, even a voice, but they can't fake the bank's own rules." |
| 0:15 to 0:45 | **Phone**: the teammate sends a real WhatsApp: *"Dubai Police: your Emirates ID is blocked because of an unpaid fine. Send your card number and CVV today to unblock it."* | Kiki was invisible. Now it jumps out red with a card at the bottom of the screen: *"This is a scam. Dubai Police never asks you to share your card's CVV… not in your contacts."* "Nothing was staged: a real WhatsApp from a real number. Kiki compared what the message **claims** with what the phone **knows**, and quoted Dubai Police's own rule." Tap **Report** → Aman 800 2626 / SMS 2828 with the evidence prepared. |
| 0:45 to 1:10 | The teammate **calls** the demo phone; answer. While on the call they text: *"Your ADCB OTP is 482915 to ADD A NEW BENEFICIARY. Never share it."* | Kiki sits at the edge ("watching this call"). The code arrives → **sharp beep**, vibration, "hang up now", STOP card. "No call recording, Android forbids it and we don't need it. We read the scam's footprints." |
| (optional, +15 s) | After a red card, tap **Got it**, then open any banking app on the phone | Kiki comes back once: *"Before you pay: Veto warned you 1 min ago… A real bank, police officer or relative can wait ten minutes. Scammers can't."* "People dismiss the first warning and pay anyway. Opening the bank app is the last moment before the money leaves, so that is when Veto speaks again." |
| 1:10 to 1:20 | "Mum" (the saved teammate) sends *"Dinner at 8? Bring bread on the way home"* | Nothing happens. "Mum's chat is never analysed. And Veto reads only the apps you switch on under *Apps Veto reads*; everything else is never read." |
| 1:20 to 2:00 | **Laptop** → *Check a message → 🔐 Fake bank verification* → **X-ray this link** | "Veto opens the link *for* you in a sealed browser. In one sentence: *this page wants your card number, CVV, the code your bank texts you and your Emirates ID, enough to spend your money.* Then the trap: Veto typed **fake** card details into the page, and caught it sending them to a **Telegram bot**, the way 43 % of live phishing kits deliver stolen data. The send was blocked." |
| 2:00 to 2:20 | X-ray `http://phone-cleaner.localhost:8787/` | "Is it a virus? This page is a **fake** virus warning, websites can't scan your phone. Its button pushes an app: Veto read the app *without installing it*, SMS codes + Accessibility + drawing over your bank app = the **banking-trojan toolkit**." |
| 2:20 to 2:35 | Phone: tap the link in a scam SMS (Veto set as the link opener, *Link Shield*) | Veto checks the link before any browser opens it: red verdict, "Don't open"; on a dangerous page "Open anyway" unlocks only after 5 seconds. |
| 2:35 to 2:50 | **🔒 Network requests during this check: 0** (web) / Privacy card (phone) | "Messages never leave the phone. Only a link or a number goes online, and only if you switch it on." |
| (finals, +30 s) | `/sentinel.html` → a campaign card → takedown pack | "For AD Police: Sentinel finds the look-alike sites, proves which are armed, links them into campaigns by the same Telegram bot, and prepares the takedown pack with the registrar's abuse contact and a STIX file for aeCERT." |
| 2:50 to 3:00 | Results slide | "Held-out test: 100 % precision, 80 % recall on the first blind run, zero false alarms. One rulebook for web and phone. Next: real AD Police data and an anonymised threat feed." |

## Backup plan

* No phone, or the phone misbehaves → the same scenarios work in the web app: *Try an example* (`himum`, `police_wa`, `callcode`) with the sender-details panel. On an emulator: `adb emu sms send 0559876543 "<scam text>"` sends a real SMS into Messages.
* No internet → everything except the X-ray of *real* sites and the AI check still works (the demo X-ray pages are local).
* Microphone fails → the web call guard runs from a script; turn off *Speak it aloud* if the room is noisy.
* Browser problem → `npm run eval:all -- -v` in a terminal shows every verdict.

## Expected judge questions

**"Isn't this just regular expressions?"**, The *verdict* is deliberately rule-based: for police use it must be explainable and citable, and it must not be talked out of a decision by a clever prompt. Language understanding has two layers: a multilingual pattern grammar that runs on the phone in under a millisecond, and an optional Claude layer for open-ended scams. The AI can only add warnings.

**"What happens with a brand-new scam?"**. Veto doesn't need to have seen it. If any message, from any number, asks for something the institution has publicly said it never asks for, that contradiction is the proof. Links get X-rayed live, not looked up in a stale blacklist.

**"Can you check the caller like Truecaller?"**, Truecaller has no public look-up API, and scraping it breaks its terms. Veto checks the number offline (country, one-ring ranges, your own reports, "this is the bank's real number, but caller ID can be faked") and, if you allow it, asks an official reputation service (IPQualityScore), sending only the number.

**"Doesn't the fake-data trap send data to criminals?"**, No. Only invented values (test card 4111…), and every request carrying them is aborted inside the sealed browser. We learn the destination; they get nothing.

**"What about a deepfake of my son's voice?"**, The voice can be perfect; the request still isn't. "Send money now, don't tell dad, new number" trips the rules, and on the phone, the number isn't the son's saved number.

**"False positives?"**, 54 legitimate look-alikes (real OTPs, fraud alerts, police awareness SMS that mention OTPs) → zero false alarms; emiratesnbd.com X-rays as "Official website". Veto never says "safe"; it says "no scam signs found".

**"Isn't an app that reads notifications and draws over apps dangerous itself?"**. Those are exactly the powers malware abuses, so Veto is read-only (never taps, types or sends), its engine has no network access, online checks are off by default, and every permission is explained on its own row.

**"Why should AD Police care?"**. Veto turns AD Police's own warnings into rules that act at the moment of the scam, generates clean reports, and (roadmap) an anonymised feed of new scam domains, numbers and Telegram bots.

**"Most look-alike domains are innocent, aren't they?"**, Yes, and we measured it: on the first hunt most live look-alikes were unrelated businesses (rta.org is a railway association). That is why Sentinel ranks on page evidence and the X-ray only says *dangerous* when the page is armed. Name-only sites stay on the watch list, because a dormant name can be armed any day.

**"How do you know two sites are the same gang?"**, Only by what criminals reuse: the same Telegram bot receives the data, the same analytics ID, the same wallet, the same kit skeleton, the same server. Each link in the console says which one, so an analyst can check it.

**"Doesn't holding a call scare people?"**, Veto holds only calls to numbers it can explain (a number from a scam message, a reported number, a contact saved as a bank with a number the bank does not publish). Everything else goes straight through, and after 2.5 s without an answer the call goes through anyway. "Call anyway" is always one tap.

**"Did you pre-build this?"**, Answer truthfully according to the event rules confirmed with the organisers.
