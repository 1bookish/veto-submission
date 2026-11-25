# Pitch deck outline (10 slides)

The T&Cs require a PPT covering architecture, model choices and privacy design. Suggested flow:

1. **Veto, the scam guard that reads the rulebook.** One line: "Scammers can fake a voice. They can't fake the bank's rules." Team names.
2. **The problem in the UAE.** 56 % face a fraud attempt monthly (CSC/TRENDS); WhatsApp is the top channel; AD Police 2026 warnings (remote-control apps, fake fines, fake consumer-protection sites, UAE PASS approvals). Every scam ends in one ask: code, card, app, approval, transfer.
3. **Why current defences miss it.** Blacklists are zero-day blind; awareness fades under panic; cloud filters read private messages; nothing explains *why*.
4. **Our insight.** Institutions publish what they will *never* ask. A request that contradicts the rulebook is proof, no matter how real the voice or logo. (Show the Emirates NBD / FAB / Mashreq quotes.)
5. **Product.** Message check · Link X-ray · OTP Guard with scam-in-progress fusion · Live call guard with predictive script tracker · Veto Radar, plus police report and "warn a family member". Screenshot collage (verdict, X-ray phone frame, amber "they will ask next", HANG UP banner).
5b. **What's new vs. existing work** (from docs/LITERATURE.md): Google/ScamShield/FraudHunter/commercial checkers give a label; research checks calls with LLMs on synthetic data. Veto: self-citing verdicts from an auto-ingested rulebook · warns *before* the ask · links a real code to the fake caller · opens links for you in a sealed browser · Radar finds look-alike domains before the SMS · blind held-out score. Be explicit about what is *not* new (on-device checks, registries, LLM explanations).
6. **Live demo** (see DEMO.md).
7. **Architecture.** The Mermaid diagram from TECHNICAL.md §1: on-device engine + rulebook; optional server helpers; ingestion pipeline.
8. **Model choices.** Rules decide (explainable, zero-day, < 1 ms); Claude reads open-ended scams and screenshots (opt-in, redacted, monotonic); real browser for links; why not deepfake detection yet.
9. **Privacy design.** On-device by default; network counter; URL-only X-ray with PII strip; redaction preview; no accounts; PDPL alignment. Threat model highlights (prompt injection, homoglyphs, SSRF, sandbox).
10. **Results & roadmap.** Held-out: precision 100 %, recall 80 % on first blind run, 0 false alarms; latency about 1 ms median per message (laptop, 24 Nov). Next: AD Police data pilot, Android app with call screening, anonymised threat feed, full CBUAE bank coverage, more languages. Ask: data access and a pilot with Aman.
