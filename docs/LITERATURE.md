# Literature and prior-art review: where Veto stands

_Compiled 20 Nov 2026. Method: GitHub API searches ("scam detection", "smishing", "phishing detection llm", "scam call detection",
"phishing brand logo", "certstream phishing", "scam uae", "scam arabic", "otp scam", "scam baiting llm"), academic search
(arXiv, USENIX Security, SOUPS, CHI, ACM MM, ACL, ARES) and vendor / government announcements. Star counts are from that day.
Metrics quoted below are the authors' own unless stated; we did not re-run their systems._

---

## 1. Academic research

### 1.1 Catching the scam *request* in a conversation
| Work | What it does | What Veto takes / how Veto differs |
|---|---|---|
| Derakhshan, Harris & Behzadi, 2021, "scam signatures" ([paper](https://par.nsf.gov/servlets/purl/10250241)) | Phone social-engineering attacks are characterised by **speech acts** (e.g. Requests for secrets); their ASsET tool matches them like malware signatures | Veto's action taxonomy (20 request types, EN/AR/romanised Hindi) is a modern descendant. New: each request is checked against **what the named institution itself says it never asks** |
| Wood et al., 2023, scam-baiting call analysis ([arXiv 2307.01965](https://arxiv.org/abs/2307.01965)) | Topic + time-series + emotion modelling of YouTube scam-baiting calls; finds **scripted scam progressions** and stage-linked techniques | Basis for Veto's **predictive script tracker**: warn at "authority → problem → pressure", *before* the ask |
| "Combating Phone Scams with LLM-based Detection: Where Do We Stand?", 2024 ([arXiv 2409.11643](https://arxiv.org/pdf/2409.11643); [AAAI-25 student abstract](https://ojs.aaai.org/index.php/AAAI/article/view/35298)) | LLMs on scam-call transcripts; reports low recall and hallucinations as open problems | Veto keeps the verdict out of the LLM (no hallucinated verdicts, no prompt injection) |
| "It Warned Me Just at the Right Moment", CHI EA 2025 ([arXiv 2502.03964](https://arxiv.org/abs/2502.03964)) | Real-time LLM analysis of live call transcripts with in-call warnings | Same goal; Veto runs rule-based **on the device** (< 1 ms per update), in Arabic, and adds the pre-ask warning |
| MASK, ACM MM 2025 ([arXiv 2510.18493](https://arxiv.org/abs/2510.18493)) | User-adjustable sanitisation before cloud LLMs see a call (local model summarises) | Confirms Veto's "redact before the cloud" design; a privacy-level slider is a good next step |
| Singh, Singh & Singh, 2025, RAG-based real-time fraud detection ([arXiv 2501.15290](https://arxiv.org/abs/2501.15290)) | Transcribes calls; a RAG LLM checks whether the caller **solicits private information**, against policies that update without retraining; 100 synthetic calls (97.98 % acc.) | **Closest prior art to Veto's core idea.** Differences: Veto's policies are *extracted automatically from real institutions' public pages with verbatim provenance* (37 quotes, 7 banks), the decision is deterministic and on-device, it covers SMS/WhatsApp/e-mail/links/OTPs as well as calls, works in Arabic, and is evaluated on 124 messages incl. 54 hard negatives and a blind held-out set |
| Explainable agentic conversational-scam detector, 2026 ([arXiv 2607.11707](https://arxiv.org/pdf/2607.11707)) | Single-message + conversation-level detection with summary memory; ConScamBench-278 | Long chats (romance-baiting) are Veto's weakest area, summary memory is a candidate for the AI layer |

### 1.2 SMS phishing (smishing)
* **SmishX**, Wang et al., SOUPS 2025 ([paper](https://www.usenix.org/conference/soups2025/presentation/wang), [code+data, MIT](https://github.com/yizhu-joy/SmishX)): an LLM agent gathers domain/brand info, redirects and screenshots, then writes an evidence-based explanation. 98.8 % accuracy on 1,200 real SMS; in a user study (N = 175) the explanations **significantly improved people's own detection across age groups** (SUS 82.6). → Strong evidence for Veto's explanation-first design. Veto differs by deciding on-device and citing the institution, and by sending only the link (not the message) to its X-ray.
* **Arabic**: Ghourabi, Mahmood & Alzubi, *Future Internet* 2020, CNN-LSTM for Arabic+English SMS spam, dataset released ([doi](https://doi.org/10.3390/FI12090156)); Alsufyani & Alajmani, IJACSA 2025, deep learning on URLs in Arabic SMS, 16,521 Arabic messages ([pdf](https://thesai.org/Downloads/Volume16No1/Paper_38-A_Deep_Learning_for_Arabic_SMS_Phishing.pdf)); SMS-phishing systematic review 2026 ([arXiv 2604.11429](https://arxiv.org/pdf/2604.11429)). → Arabic work is classifier-centric; none grounds verdicts in UAE institutions' rules.

### 1.3 Phishing web pages (what the Link X-ray builds on)
* **Reference-based detection**, flag a page whose *brand* doesn't match its *domain*: Phishpedia (USENIX Security 2021), PhishIntention (USENIX Security 2022, adds "credential-requiring page" checks), DynaPhish, **KnowPhish** (USENIX Security 2024, multimodal brand knowledge base + LLM; notes earlier brand lists held only 277 brands, [arXiv 2403.02253](https://arxiv.org/abs/2403.02253)), **PhishLLM** (USENIX Security 2024, no predefined list, +21 to 66 % recall, [paper](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-ruofan)), PhishIntel (deployment, [arXiv 2412.09057](https://arxiv.org/pdf/2412.09057)). → Veto's X-ray applies the same principle (brand on page ≠ official domain + asks for card/CVV/OTP/PIN) with a **UAE brand knowledge base**, UAE banks and government entities that global lists miss.
* **Where phishing kits send stolen data**, "An Analysis of Architectural and Operational Dynamics of Phishkits in the Wild" ([arXiv 2608.07451](https://arxiv.org/pdf/2608.07451)): Telegram bot tokens in **314 of 732 (42.9 %)** live kits from a daily feed (but only 10 % in the older Phishunt dataset); Forescout 2025: **9,100 phishing domains** using the Telegram bot API with **4,145 unique bot tokens**, often on front-end hosting platforms ([Forescout](https://www.forescout.com/blog/revamped-phishing-techniques-how-telegram-and-front-end-hosting-platforms-scale-campaigns/)); KnowBe4 2025 campaign analysis of kits posting credentials straight to Telegram bots ([KnowBe4](https://blog.knowbe4.com/telegram-bot-phishing-kit-data-exfiltration)); older baseline: e-mail dominated exfiltration, Telegram/Google Forms ~5.7 % (Group-IB). → Veto's **fake-data trap** watches the page try to send *fake* values and names the channel (Telegram bot, Discord webhook, Google Apps Script…), the send is blocked. Server-side forwarding (PHP → Telegram) is invisible to any client-side test; we say so.
* **Fake virus / "scareware" pages and app droppers**, the X-ray's watcher records the pressure tricks (vibration, full-screen, back-button traps, alarm sounds) and the app inspector reads the pushed APK's manifest (SMS + Accessibility + overlay = the banking-trojan toolkit) without installing it.
* **Certificate Transparency monitoring**, Drichel et al., "Finding Phish in a Haystack", ARES 2021 ([arXiv 2106.12343](https://arxiv.org/abs/2106.12343)): catch phishing sites *while they are being prepared*, before blocklists react; Aalborg study: certificates appear before blacklisting, cheap CAs dominate ([pdf](https://vbn.aau.dk/ws/files/475848757/105166.pdf)). → **Veto Radar**.

### 1.4 Romance-baiting, investment and job scams
* Gressel et al., "Love, Lies, and Language Models", USENIX Security 2026 ([arXiv 2512.16280](https://arxiv.org/abs/2512.16280)): 87 % of scam-compound labour is automatable; **Llama Guard 3, Google Perspective and OpenAI Moderation failed to detect romance-baiting conversations**. → Rule engines and moderation filters share this blind spot; Veto states it and routes long chats to the AI deep-check.
* Investigation systems: Victim-as-a-Service / Chatterbox ([arXiv 2510.23927](https://arxiv.org/abs/2510.23927)), Anansi job-scam pipeline ([arXiv 2602.24223](https://arxiv.org/html/2602.24223v1)).

### 1.5 Benchmarks and datasets
Fraud-R1 ([arXiv 2502.12904](https://web3.arxiv.org/pdf/2502.12904)), nine-LLM scam-detection study ([arXiv 2607.17353](https://arxiv.org/abs/2607.17353)), ConScamBench-278 and LoveFraud02 ([arXiv 2607.11707](https://arxiv.org/pdf/2607.11707)), honeypot Scam Conversation Corpus, 13,801 messages from 903 scammers ([TU Wien thesis](https://repositum.tuwien.at/bitstream/20.500.12708/216289/1/Eder%20Christoph%20-%202025%20-%20Honeypot%20LLM%20Creation%20of%20the%20Scam%20Conversation%20Corpus.pdf)), ASR synthetic scam conversations ([arXiv 2507.17543](https://arxiv.org/pdf/2507.17543)), **SmishX's 1,200 labelled real SMS (MIT)**, the best candidate for an external benchmark of Veto.

### 1.6 Active defence (scam-baiting)
Apate.ai, AI "victims" deployed through telcos to waste scammers' time and extract intelligence ([TechCrunch, Oct 2026](https://techcrunch.com/2026/10/14/apate-sends-ai-agents-undercover-to-get-scammed-so-they-can-gather-fraud-intelligence/), [Macquarie University](https://lighthouse.mq.edu.au/article/november-2024/ai-chatbots-outsmart-scammers-world-first-pilot-with-australias-largest-bank)); ScamChatBot engaged 450 scammers via decoy posts ([arXiv 2412.15072](https://arxiv.org/html/2412.15072v1)). → Out of scope for a citizen app (legal/ethical), but Veto's police reports are the kind of intelligence these systems harvest.

### 1.7 Voice deepfakes
ASVspoof 5 (53 teams) reports degradation under adversarial attacks and neural codecs and persistent generalisation problems ([arXiv 2601.03944](https://arxiv.org/abs/2601.03944)); detectors trained in the lab degrade sharply on in-the-wild audio ([arXiv 2203.16263](https://arxiv.org/pdf/2203.16263)) and over the phone channel ([arXiv 2509.26471](https://arxiv.org/html/2509.26471v1)). → Justifies Veto being **voice-agnostic**: judge the request, not the voice.

### 1.8 Human factors
* A 4.5-minute **inoculation** training against government-imposter scams raised fraud detection **without lowering trust in real communications**, but mainly for the communication type trained ([AARP summary](https://www.aarp.org/money/scams-fraud/social-security-scams-studies/), [Wisconsin CFS brief](https://cfsrdrc.wisc.edu:443/files/research-briefs/WI21-03_Robb-Wendel_Research-Brief_9.27.21-(1).pdf)). → If Veto adds drills, they must use **UAE-specific** scenarios.
* SmishX's user study: explanations help people of all ages (above).

---

## 2. Products and government services

| Product | What it does | Gap Veto fills |
|---|---|---|
| **Google** on-device Scam Detection, Messages and Pixel calls ([Google blog](https://blog.google/security/new-ai-powered-scam-detection-features/), [2026 update](https://9to5google.com/2026/02/25/google-messages-scam-detection-gemini/)) | Gemini Nano flags conversational scams; call detection beeps and warns; nothing stored | Opaque "likely scam" label (no source); call detection limited to listed countries (UAE not among those in the source); Android/Pixel only |
| Google **in-call protection for banking apps** ([Google blog](https://blog.google/security/android-expands-pilot-in-call-scam-protection-financial-apps/)) | Unknown caller + banking app + screen sharing → warning and 30-second pause | Uses device state, not meaning; Veto's fusion links *what a code unlocks* with *who is asking* |
| Singapore **ScamShield** ([ask.gov.sg](https://ask.gov.sg/scamshield/questions/clzj6xu6k004ee2cm4fozbjsk)) | Known-scam lists, warnings, "Check" for numbers/messages/links | List-based; no policy reasoning |
| Norton Genie, Bitdefender Scamio, McAfee Scam Detector, Trend Micro ScamCheck ([Malwarebytes overview](https://www.malwarebytes.com/solutions/best-scam-detection-tools), [KSL hands-on](https://www.ksl.com/article/51440941)) | Cloud AI chat checkers for texts/links/screenshots | Cloud-only, generic, no UAE rules; none perfect in hands-on tests |
| **TDRA Digital FraudHunter** (UAE, Sept 2025) ([Gulf News](https://gulfnews.com/living-in-uae/telephone-internet/telephone-1.500263006)) | Upload a screenshot of an SMS/e-mail/social message; AI says if it is fraudulent; advisory | Screenshot leaves the device; no calls, no link detonation, no cited reasons. **Complementary**. Veto's rulebook could feed it |
| **e& × Mavenir CallShield** (UAE network, Oct 2025) ([TelecomTV](https://www.telecomtv.com/content/security/e-and-mavenir-unveil-ai-powered-voice-service-security-and-anti-fraud-collaboration-54072/)) | Network-level spam/scam/spoofed-call blocking | Stops known patterns at the network; can't see WhatsApp calls or the words of a new scam |
| **Truecaller** / Hiya (caller ID) | Crowd-sourced caller reputation | **No public look-up API**, Truecaller's developer SDK only verifies the user's *own* number; the 2013 lookup API went to hand-picked partners ([TechCrunch 2013](https://techcrunch.com/2013/05/22/truecaller-api/)); third-party "Truecaller API" wrappers are unofficial. Veto uses an official reputation API instead (IPQualityScore: `fraud_score`, `recent_abuse`, `spammer`, `VOIP`, `line_type`, [docs](https://www.ipqualityscore.com/documentation/phone-number-validation-api/response-parameters); ~1,000 free look-ups/month) plus offline one-ring ranges and the user's own reports |
| abuse.ch **URLhaus / MalwareBazaar** | Free malware-URL and malware-file databases | Free Auth-Key required since 2025 ([URLhaus API](https://urlhaus.abuse.ch/api/), [abuse.ch blog](https://abuse.ch/blog/community-first/)); Veto queries them by link and SHA-256 when a key is configured |
| UAE **one-ring (Wangiri)** warnings | Operators and press: don't return missed international calls; up to US$50/min ([Gulf News](https://gulfnews.com/uae/wangiri-fraud-warning-in-uae-dont-return-missed-calls-from-unknown-numbers-1.1605443371172), [The National](https://www.thenationalnews.com/uae/wangiri-scam-hits-uae-foreign-gangs-target-residents-with-phone-calls-and-phishing-texts-1.735189)) | Veto recognises a short ring from a foreign / premium-range number that stopped before you answered and says "don't call back" |

## 3. Open-source projects (GitHub)

| Repository | ★ | What it is | Lesson for Veto |
|---|---|---|---|
| [x0rz/phishing_catcher](https://github.com/x0rz/phishing_catcher) | 1,832 | Scores new CT-log certificates by suspicious keywords | → Veto Radar (UAE brand tokens) |
| [thalesgroup-cert/Watcher](https://github.com/thalesgroup-cert/Watcher) | 1,451 | Threat-intel platform incl. look-alike domain monitoring | Analyst-facing; Veto is citizen-facing |
| [wesleyraptor/streamingphish](https://github.com/wesleyraptor/streamingphish) | 329 | ML classifier on CT logs | Possible upgrade for Radar scoring |
| [d-Rickyy-b/certstream-server-go](https://github.com/d-Rickyy-b/certstream-server-go) | 241 | Self-hosted live CT stream | Real-time Radar instead of crt.sh batches |
| [jarelllama/Scam-Blocklist](https://github.com/jarelllama/Scam-Blocklist) | 107 | Daily list of newly created scam domains (GPL-3.0) | Could be fetched at runtime (licence) |
| [yizhu-joy/SmishX](https://github.com/yizhu-joy/SmishX) | n/a | Explainable smishing (SOUPS 2025), 1,200-SMS dataset (MIT) | External benchmark candidate |
| [Linklow/coachguard](https://github.com/Linklow/coachguard) | 15 | On-device "coached payment" detection SDK for Android banking apps (call, screen share, remote access, behaviour) | Bank-side complement; Veto is user-side and semantic |
| [OrangeAKA/saaya](https://github.com/OrangeAKA/saaya) | 2 | Android: unknown call + banking/UPI/remote app → overlay, Hindi voice warning, SMS to a guardian | → Veto "warn a family member" |

## 4. Honest novelty statement

**Not new (others do it. We say so):** on-device message analysis; UAE domain registries; URL-only cloud lookups; LLM explanations; LLM monitoring of live calls; call-plus-banking-app warnings; scam-baiting; CT-log monitoring in general.

**What Veto adds (to our knowledge, after this review):**
1. **Self-citing policy-contradiction verdicts from an auto-ingested national rulebook.** The closest work checks calls against policies with an LLM on synthetic data (Singh et al., 2025). Veto extracts "we will never ask…" commitments from institutions' own public pages, keeps the exact sentence + URL + date, and decides deterministically on the device in under a millisecond.
2. **Predictive scam-script tracker** that warns *before* the ask. Prior work analyses scripts offline (Wood et al., 2023) or warns once a scam is detected (Google; CHI EA 2025).
3. **Scam-in-progress fusion** of a real one-time code's purpose with the caller's claims ("they are asking for the code you received 1 min ago. It adds a NEW beneficiary"). Existing protections use device state (unknown caller, screen sharing), not meaning.
4. **Citizen-facing sealed link X-ray inside the same flow** as the message verdict. Others use reputation lookups, refuse to open links, or offer analyst tools (urlscan, Lookyloo).
5. **Veto Radar**: Certificate-Transparency discovery specialised to UAE institutions, shipped to devices as an offline blocklist.
6. **Honest measurement**: blind held-out score reported before fixes, with 54 hard negatives.

## 5. Changes made because of this review
* Predictive pre-ask warning + live 4-stage tracker in the call guard (Wood et al., 2023).
* OTP × call **fusion** and an "I just got a code" button during calls.
* **Allowed-verification exception**: banks may ask for the *last 4 digits*; no longer treated as a card-number request (the policy example in Singh et al. shows partial details can be legitimate).
* **Veto Radar** (`npm run radar`, Drichel et al. 2021; phishing_catcher).
* **Warn a family member** (Saaya's guardian alert, adapted as a user-initiated share).
* New positioning against FraudHunter, ScamX, ScamShield UAE and the other "Veto".

## 6. External benchmark (done 20 Nov 2026)
SmishX dataset ([MIT](https://github.com/yizhu-joy/SmishX)): 1,200 real SMS, 259 phishing ("smishing"), 622 legitimate, 319 spam; mostly US, India and Europe.

| Run | Precision | Recall | F1 | False alarms (legit) |
|---|---|---|---|---|
| **Blind**, engine unchanged | **68.0 %** | **6.6 %** | **12.0 %** | **1.3 %** |
| After general fixes from error analysis (not blind) | 98.8 % | 32.0 % | 48.4 % | 0.2 % |

* "Flagged" = *scam* or *very likely*; a further 65 phishing texts get *caution*.
* Why the blind recall was so low: Veto's strongest evidence (an institution's own rules and official domains) only exists for UAE institutions, and foreign smishing uses short redirect links and phrasings ("verify your latest Zelle payment: link") the lexicon did not cover.
* Fixes kept general (no dataset-specific brand lists): the "story + link" smishing shape, unknown short redirect links, merchant mentions vs. sender claims ("payment … for Amazon"), awareness texts with links, a "% daily data" regex bug, an over-broad "send me the number" rule, Amazon's own `a.co` short links; PayPal, Netflix and Binance added because they are widely impersonated in the UAE as well.
* Not comparable to SmishX's own 98.8 % accuracy (3-class, cloud LLM with web context). The fair comparison is the opt-in AI layer, still to be measured.
* Our UAE corpus did not regress (0 false alarms, 100 % recall on the 124 messages in the current run; the set was used for tuning, so this is not a blind estimate).

## 7. Recommended next steps
1. **Arabic external benchmark** (Ghourabi 2020 dataset) and measure the AI deep-check on SmishX.
3. Privacy-level slider for the AI layer (MASK); summary memory for long chats (arXiv 2607.11707).
4. Real-time Radar via a self-hosted certstream server; Radar scoring with a CT classifier.
5. UAE-specific inoculation drills (only local scenarios transfer).
