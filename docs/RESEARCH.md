# Research notes: what we studied before building Veto

Compiled 20 Nov 2026. Sources are listed under each section; statistics come from different surveys with different methods and should not be combined.

## 1. The UAE scam landscape (2025 to 2026)

**Scale**
* 56 % of UAE residents report at least one fraud attempt per month; shopping scams and identity theft are most common, investment scams third (UAE Cyber Security Council × TRENDS study, [Gulf News](https://gulfnews.com/business/banking/over-50-of-uae-residents-report-being-targeted-by-one-financial-fraud-a-month-1.500064786)).
* GASA "State of Scams in the UAE 2025" (1,000 residents): seven in ten encountered a scam; more than half experienced one in the past 12 months ([GASA](https://gasa.org/knowledge-base/reports/state-of-scams-in-the-united-arab-emirates-2025)).
* GASA/BioCatch 2024: ~27 % lost money (average USD 2,194), only 9 % fully recovered ([BioCatch](https://www.biocatch.com/press-release/uae-residents-lose-millions-to-scams-2024)). WhatsApp is the most used scam channel.

**What police are warning about (2025 to 2026)**
| Pattern | Source |
|---|---|
| Remote-control apps (AnyDesk-type) used to empty accounts, AD Police campaign, 10 Apr 2026 | [Gulf Today](https://www.gulftoday.ae/news/2026/04/10/abu-dhabi-police-warn-against-remote-control-app-scams), [Khaleej Times](https://www.khaleejtimes.com/uae/abu-dhabi-police-warn-residents-of-remote-access-apps-used-in-scams) |
| Fake "consumer protection" sites (via search ads) that push remote-control apps while you are logged in to your bank | [Khaleej Times](https://www.khaleejtimes.com/uae/dubai-police-fake-consumer-protection-links-banking-scam-warning), [Gulf News](https://gulfnews.com/uae/crime/abu-dhabi-police-warn-public-about-fake-links-in-search-engines-1.500566188) |
| Fake traffic-fine links | [Gulf News](https://gulfnews.com/uae/crime/scam-alert-abu-dhabi-police-warn-against-traffic-fine-suspicious-link-1.500243502) |
| "Dh3 delivery fee" parcel messages | [Gulf News](https://gulfnews.com/uae/crime/dh3-delivery-scam-abu-dhabi-police-alert-uae-residents-of-fake-messages-1.500272577) |
| Callers posing as the UAE Central Bank | [Gulf News](https://gulfnews.com/uae/be-wary-of-scammers-purporting-to-be-from-uae-central-bank-abu-dhabi-police-warns-1.80068299) |
| UAE PASS approval / code requests by fake officials (TDRA, Digital Dubai, Dubai Police: reject any request you did not start) | [Gulf News, TDRA](https://gulfnews.com/uae/uae-pass-security-alert-tdra-issues-advisory-amid-fraud-attempts-1.500459682), [Gulf News, Dubai Police](https://gulfnews.com/uae/crime/dubai-police-caution-residents-against-fake-calls-seeking-uae-pass-details-1.500460239) |
| Salary-day scam surges | [Khaleej Times](https://www.khaleejtimes.com/uae/abu-dhabi-police-warn-fraud-scams-salary-payments) |
| Fake visa and job offers | [Gulf News](https://gulfnews.com/uae/crime/dubai-police-warn-public-against-fake-visa-and-job-scams-online-1.500612157) |

**Two structural changes Veto builds on**
1. **SMS/e-mail OTPs are being phased out.** CBUAE notice 3057 (May 2025) moved banks from SMS/e-mail OTPs to in-app authentication from July 2025, with a deadline of 31 March 2026 ([Gulf News](https://gulfnews.com/business/banking/new-rule-uae-banks-to-stop-sending-otps-via-sms-and-email-from-july-25-1.500209071), [The National](https://www.thenationalnews.com/business/money/2025/07/24/uae-banks-otp-fraud-crime/)). Scammers adapt by asking victims to **approve the request in the app**, so Veto treats "approve the notification" exactly like "read me the OTP".
2. **Business SMS sender IDs are regulated** (promotional IDs carry an `AD-` prefix; transactional IDs are registered names) ([Twilio's UAE guidelines](https://www.twilio.com/en-us/guidelines/ae/sms)). A "bank" SMS from a personal +9715x number is therefore a strong signal.

**Reporting channels (used by Veto)**: Abu Dhabi Police Aman 800 2626 / SMS 2828 / aman@adpolice.gov.ae ([Gulf News](https://gulfnews.com/living-in-uae/safety-security/how-to-report-online-fraud-and-phone-scams-in-abu-dhabi-1.1644936083156)); Dubai Police 901 and eCrime platform ([Emirates 24/7](https://www.emirates247.com/uae-guide/dubai-police-ecrime-hub-how-to-report-cybercrime-online-recover-from-scams-and-protect-yourself/6353)); MOHRE labour advice 80084 ([u.ae](https://u.ae/en/information-and-services/jobs/employment-in-the-private-sector/labour-rights)).

## 2. What the institutions themselves say (the rulebook's raw material)

`npm run ingest` extracted 37 policy sentences from 7 banks' own pages on 20 Nov 2026, for example:

* *"Emirates NBD will never ask for sensitive information, such as passwords, PINs, or OTPs, via email or other channels."*, [emiratesnbd.com/en/security](https://www.emiratesnbd.com/en/security)
* *"Never add new beneficiaries to your mobile banking at the request of an unknown caller."*, [Emirates NBD, United Against Fraud](https://www.emiratesnbd.com/en/campaigns/united-against-fraud)
* *"FAB Staff shall never ask for any password, OTP or PIN for any banking services."*, [bankfab.com](https://www.bankfab.com/en-ae/about-fab/security-and-certifications/comprehensive-security-tips)
* *"Mashreq Staff will never ask for OTP."*, [mashreq.com](https://www.mashreq.com/en/uae/neo/security/card-safety/)
* *"We will never ask for your card number, CVV, PIN, OTP or passwords via email, SMS or phone."*, [Standard Chartered UAE](https://www.sc.com/ae/protecting-your-cards-and-digital-payments/)

The full, dated list is in `data/evidence.js`. Law-based rule: Art. 6 of Federal Decree-Law 33/2021 forbids charging workers recruitment costs ([u.ae](https://u.ae/en/information-and-services/jobs/employment-in-the-private-sector/labour-rights)).

## 3. Critique of our seed idea: "train the AI on every bank's T&Cs"

| Weakness | What we changed |
|---|---|
| Legal T&Cs talk about fees and liability, rarely about what staff will never ask | Ingest **security / fraud-awareness pages** and regulator/police advisories instead |
| A model "trained" on documents cannot cite, can hallucinate, and goes stale | A **rulebook** with verbatim quotes, URLs and dates; re-ingest to update; every alert cites |
| Inbound vs outbound asymmetry: a bank *may* verify your date of birth on a call **you** made | Rules focus on the **universal never-items** (codes, PIN, CVV, passwords, app approvals, remote access, safe accounts, gift cards) that hold in every direction |
| Many top scams impersonate nobody (romance, investment, task jobs, "Hi Mum") | Pressure-tactic layer + universal rules + labour-law rule + optional AI deep check |
| Caller ID spoofing makes the "real number" meaningless | Judge the **request**, not the number |
| Policies change | `npm run ingest` re-runs; changes show up as a git diff |
| Scammers adapt wording, letters, languages | Normalisation (homoglyphs, Arabic digits, defanging) + multilingual lexicon + AI layer |

## 4. How others defend (and the gap Veto fills)

Background knowledge of publicly documented national programmes (summarised, not exhaustive):

| Country / system | Approach | Gap relative to Veto |
|---|---|---|
| Singapore, ScamShield (app, helpline, check service) | Blocklists of reported numbers/messages, reporting, public education | Mostly reactive to *known* scams; little "why" for the user |
| United Kingdom, Confirmation of Payee; APP-fraud reimbursement rules; O2's AI "scam-baiting" persona | Payment-side name checks; reimbursement; wasting scammers' time | Acts at payment or network level, not at the moment a victim is asked for a code |
| Australia, National Anti-Scam Centre; Scams Prevention Framework | Cross-sector intelligence sharing and obligations on banks/telcos/platforms | Institutional, not a personal in-the-moment assistant |
| United States, STIR/SHAKEN caller authentication | Verifies caller ID on carrier networks | Spoofing across borders / OTT apps (WhatsApp) not covered |
| EU, Verification of Payee for instant payments | Name, IBAN match before transfer | Doesn't stop OTP theft, app approvals or remote-access scams |
| UAE, police hotlines, campaigns, eCrime portals, bank in-app authentication | Reporting and awareness; stronger bank authentication | No citizen tool that checks a message against the institutions' own rules |

**Prior art at the same venue:** a 42 Abu Dhabi × Ministry of Interior hackathon (InnovateX) produced a scam-prevention prototype for people of determination ([Dubai Schools](https://dubaischools.com/news/uae-students-develop-high-tech-tool-that-can-prevent-scams)); no technical details were published. Veto's differentiators: cited policy-contradiction verdicts, the sealed link X-ray, the OTP Guard and the live call guard.

**Gap Veto fills:** a **zero-day**, **cross-channel**, **explainable** (cites the institution's own words), **private** (on-device) second opinion **at the moment of the request**.

## 5. What judges will probably weigh, and how Veto answers

| Likely criterion | Evidence in Veto |
|---|---|
| Working product, not slides | Running PWA + server, 9 unit tests, evaluation script, live X-ray of real pages |
| Technical depth & model choices | Neuro-symbolic design, sealed browser, SSRF guard, monotonic AI merge, docs/TECHNICAL.md |
| Privacy design (explicitly requested) | On-device analysis, live network counter, redaction preview, URL-only X-ray |
| Impact & UAE fit | Arabic/English, UAE institutions and laws, AD Police reporting built in, AD Police warnings encoded as rules |
| Honesty / rigor | Held-out measurement reported before fixes; known misses listed |

## 6. Risks to keep in mind for the pitch

* Do not claim "100 % prevention", claim measured precision/recall and the zero-day property.
* Bank phone numbers marked `v: false` in the rulebook must be checked before production (the UI also says "or the number on the back of your card").
* The corpus is synthetic; ask AD Police for real data access as a pilot outcome.
