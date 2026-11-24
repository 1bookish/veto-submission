# Research log

Every experiment we ran on the URL Judge, including the ones we rejected, and the papers we checked.
Numbers come from the held-out split in the README (time split, 25 Oct to 24 Nov 2026) unless stated otherwise.
Reproduce with `npm run eval:judge -- --data <dataset folder>` and `node tools/train-url-model2.js` (see TECHNICAL.md, section 1b2).

## Experiments (24 Nov 2026)

| # | Change | Result | Decision |
|---|---|---|---|
| 1 | Official UAE pages as legitimate training data (split by domain, flag `--official-as-legit`) | Held-out UAE domains (192 URLs): 1 flagged before and after. Test false alarms rose from 0.62 % to 0.71 %; recall moved from 93.9 % to 94.1 %. | Rejected. The shipped model is the previous one. |
| 2 | Popularity guard (top 10,000 scaled to 0.25, top 100,000 to 0.6, hosting platforms exempt) | Long-tail legitimate false alarms 0.83 %, popular 0.28 %. Phishing on popular domains caught 57.2 % (232 of 402). | Kept. The trade-off is disclosed. Next: a separate test for hacked popular sites. |
| 3 | Brand words that are also ordinary words abroad (centralbank, police, emirates, finance, post, customs, courts, tax, bank, gov) count only with the model | Removed false alarms on real central banks such as centralbank.cy and centralbank.org.sz | Kept |
| 4 | Google Sites, Docs, Forms and Firebase storage are no longer treated as official | A phishing page on sites.google.com had been passed as an official Google page | Kept, in the engine, the judge and the phone build |
| 5 | Sampling for the online check used a comparator-based sort, which is biased (14 phishing in a sample of 300) | The earlier online figures (P 99.1 %, R 91.3 %, FPR 0.54 %) came from that biased sample | Withdrawn. Replaced by a Fisher-Yates shuffle with a fixed seed: P 94.7 %, R 94.7 %, FPR 1.79 % on 300 URLs (76 phishing) |
| 6 | URLhaus download as a phishing feed | HTTP 410: the endpoint is retired | Removed. OpenPhish and Phishing.Database are kept. |
| 7 | Newly registered domains (WhoisDS free daily list, two days read) | About 70,000 domains per day. Four look-alikes of UAE institutions among them (salilk.net, salio.in, palik.tech, alik.info). | Kept as a Sentinel source. Names are withheld from public material until they are reported. |
| 8 | Trust Issues' published metrics changed between our two reads | 13:02 file: P 98.1 %, R 92.1 % on 38,001 URLs. 13:24 file: P 98.1 %, R 87.7 %, FPR 1.1 % on 16,953 URLs. | We quote the current file and say the test sets differ. |

## Literature checked (search results, 24 Nov 2026)

Read the full papers before quoting any number. Figures marked "their own" are the authors' claims.

| Work | What it shows | What we take from it |
|---|---|---|
| Lin et al., Phishpedia, USENIX Security 2021 | A hybrid deep-learning system that finds brand logos in screenshots, without phishing training samples. The authors report that a CertStream deployment surfaced 1,704 new phishing sites in 30 days (their own figure). | Next step for our copied-logo module: match page screenshots against the official logo references |
| PhishIntention, USENIX Security 2022 | Adds a check of what a page asks for to reference matching. Reports a false positive on a benign page with a similar logo. | Use the intent idea: check what a page asks for, not only how it looks |
| Reference-based phishing detection without a pre-defined reference list, USENIX Security 2024 | Reference matching that does not need a fixed brand list | Our UAE brand list is incomplete. This is the way to scale it |
| Oest et al., PhishFarm, IEEE S&P 2019 | 2,380 live, innocuous phishing sites tested against six request filters (user agent, geolocation, JavaScript, .htaccess). Cloaking weakened browser blocklists. | Our cloaking test varies only the user agent. Add geolocation and JavaScript variants. Verify page numbers and DOI 10.1109/SP.2019.00049 before citing. |
| Le et al., URLNet, arXiv 2018 | Character and word CNNs learn a URL representation directly from the string | A challenger model to compare with our logistic regression |
| Huang et al., Pinning Down Abuse on Google Maps, WWW 2017 (UC San Diego and Google) | More than 100,000 fraudulent listings analysed; about 40 % were contractor scams. Google reports a 70 % fall after tighter checks, and 85 % of fake listings caught before they appear (their own figures). | Focus the listing check on categories scammers use most (helplines, contractors) |
| TU Delft 2025 master's thesis, Exploring Malvertising Driven by Brand Impersonation in Search Engine Ads | About 52,000 ads from 605 brands over 24 days; 7.9 % abusive (4,160). Most of the abuse (3,781 ads) is affiliate brand bidding, not look-alike domains. Not peer reviewed. | The ads check should flag brand-name bidding that lands on a non-brand domain, not only look-alike domains |
| Agarwal and Vasek, Examining Newly Registered Phishing Domains at Scale, WEIS 2025 | 15,126 new domains over eleven months; about 26 % used Cloudflare to evade detection; phishing sites lived about 8.6 days on average | A registration watch has a real window before the attack |
| Lim et al., Registration, Detection and Deregistration: Analyzing DNS Abuse for Phishing Attacks, arXiv 2025 | Malicious registrations were flagged in a median of 16.3 days, compromised sites in 86 days | Registration monitoring is an earlier signal than blocklists |
| Seweryn et al., BadDomains: Early Detection of Phishing Domains Registration, Sensors 2026 (DOI 10.3390/s26031041) | Registration-based early detection, live at CERT.PL from 29 Nov 2024 to 28 Jul 2025 | The closest deployed analogue to our newly registered domains source |
| Vendor reports: Forescout, Netcraft, KnowBe4, Netlas (2025) | Telegram bots are the stolen-data channel in many phishing kits. Netcraft reports more than 500 separate tokens in credential-theft kits in one month. Forescout reports about 9,100 domains and 4,145 distinct tokens. Netlas says tokens recur across several domains. | Shared bot tokens link campaigns (our campaign keys). The 28 % token-reuse figure is NOT verified against the primary Forescout report and is not used. |

**Could not verify:** arXiv 2608.07451, cited earlier as "Telegram bot tokens in 42.9 % of 732 live phishing kits". It did not appear in any search, so the claim has been removed from the README.

## Novelty, stated carefully

Newly registered domain monitoring and reference-based phishing detection are established research. What appears new in our set is the combination in one pipeline: a daily free registration feed, UAE institution rules as evidence, a three-vantage cloaking test, a fake-data trap that shows where data goes, and a call hold on Android. We checked the 19 public repositories, not app stores, so "nobody else holds calls to scam numbers" is not verified.

## Experiments (24 Nov, audit pass 2: challenge run on our own code)

Scripts, results and the run log are in the handoff package under audit/. Each number below comes from the same script run before and after the fix.

| # | Change | Result | Decision |
|---|---|---|---|
| 9 | Open redirects on trusted hosts: a link such as google.com/url?q=<address>, or a bank /redirect?url=<address>, passed because the host itself is trusted | Synthetic test (400 caught phishing, three redirect forms): 400 of 400 passed before, 0 of 400 after. The judge now judges the address inside the link and reports the worse verdict. Held-out test split unchanged. | Kept. A trusted host no longer gets a free pass. |
| 10 | Trailing dot on the host (metamzklogi.gitbook.io.) | 5 of 400 passed before, 0 after. The first attempt did nothing because a regular expression lost its backslash; the test caught it. | Kept, in the URL parser every caller uses. |
| 11 | Letter n-gram explanations ("the letters ...") shown to readers | Fragments with no meaning for a reader | Not shown. Scores unchanged. |
| 12 | Campaign linking merged sites on any shared trace (same-day registrations, common icons, shared hosting addresses) | Only high and medium traces now merge; low traces stay in the record. Each campaign states its confidence. The existing campaign test still passes; a new test covers weak traces. | Kept. Sites that share only weak traces are no longer put in one campaign. |

### Results, before and after (same scripts, same data)

| Measure | Before | After |
|---|---|---|
| Red team: open redirect via Google (400 base) | 400 pass (100 %) | 0 pass |
| Red team: open redirect via a bank domain | 400 pass | 0 pass |
| Red team: open redirect via a UAE university domain | 400 pass | 0 pass |
| Red team: trailing dot on the host | 5 pass (1.25 %) | 0 pass |
| Red team: the other 9 transforms (homoglyph, path decoy, percent encoding, userinfo, subdomain brand, query noise, upper case, port, www) | none pass; 0 to 0.75 % downgraded to suspicious | unchanged |
| UAE: phishing that names a rulebook institution (324 URLs, 25 Oct to 24 Nov) | recall 95.7 % (strict) | unchanged |
| UAE: the part whose institution has an .ae domain (103 URLs) | recall 90.3 % | unchanged |
| UAE: the rest (221 URLs) | recall 98.2 % | unchanged |
| UAE: hand-listed open sites (21) | 1 flagged (suspicious, model only) | unchanged |
| New-domain watch, all 77 institutions, two days | 68 candidates, 14 institutions | unchanged; precision not measured |
| Held-out test split (33,766 URLs) | strict P 98.2 / R 93.9 / FPR 0.62 %; cautious P 96.9 / R 95.2 / FPR 1.11 % | identical |
| Official UAE pages, model alone (2,231) | 62 flagged (2.78 %) | identical |
| Unit tests | 54 of 54 | 59 of 59 |

### Still open (found, not fixed)

- Public file hosts: 10 of the 12 misses among the UAE-named URLs sit on S3 or Backblaze B2 buckets (the first pass said 9; corrected). A bucket layer followed (section below). Still open: a labelled benign bucket sample, and typo-tolerant brand matching.
- A famous brand glued to words on a foreign domain (amazonprime-network.fr) is missed when the model is unsure, because the brand rule only counts next to a model that already leans phishing.
- New-domain watch: 68 candidates in two days, most imitating global brands (WhatsApp 26, Apple 18, Amazon 6). The four Salik look-alikes match the earlier count. Precision is unknown until a sample is checked by hand, without visiting the sites.
- Trusted-site redirects: real prevalence unknown. The 57,892 OpenPhish rows we hold contain none.
- Latency: the same test split gave 0.28 and 0.92 ms per URL in two runs. Quote a range, measured on a stated machine.

## Literature checked in audit pass 2 (search snippets; read the full pages before quoting)

Every row below came from a search result in this pass. None of the figures has been checked against the full paper or report.

| Source | What it shows (snippet) | What we take from it |
|---|---|---|
| Silent Push, "Powerful Pivots: Hunting with Infrastructure Fingerprints" (silentpush.com/?p=16741) | A JARM value plus an HTTP hash pulls every domain on matching servers; it can link one operator's campaigns, but it also groups unrelated large providers | Pivot on JARM only together with a second key |
| Intel Insights, "Gone Phishing" (intelinsights.substack.com/p/gone-phishing) | In a Rhadamanthys infrastructure write-up, JARM ranked below banner and certificate-hash pivots | Use certificate and banner pivots first |
| Botnet fingerprint study, 2023 (zenodo.org/records/8421241) | Fingerprints need frequent updates; legitimate hosts increasingly match malicious ones | Treat a fingerprint match as a lead, not as proof |
| MITRE ATT&CK T1656, Impersonation (attack.mitre.org/techniques/T1656) | Mirrors list it under Defense Evasion with no sub-techniques; a newer "Social Engineering: Impersonation" page (T1684.001) also appears | Check the current matrix on attack.mitre.org before mapping brand impersonation |
| ATT&CK T1566 sub-techniques (IntechOpen chapter, secondary source) | Lists T1566.001 (attachment), T1566.002 (link), T1566.003 (service); T1566.004 (voice) comes from the summary's background knowledge | Map URL lures to T1566.002 once confirmed on attack.mitre.org |
| Himdi and Alhayan, Journal of Engineering Research, Sep 2025 (DOI 10.1016/j.jer.2025.08.013) | Arabic phishing-email collection with ensemble detectors and a cross-domain check | Arabic lure text is a data source for the copied-lure check |
| Salloum et al., ACM TALLIP 2023 (DOI 10.1145/3606031) | 1,258 English and Arabic emails; the authors report about 96.8 % (Arabic) and 94.6 % (English) accuracy (their own figures) | A benchmark for email text only, not for URLs |
| ASLC-448 Arabic scam-call dataset (data.mendeley.com/datasets/p384bgyzz3) | 448 annotated Arabic call conversations, nine dialects, paired synthetic audio | For the call-scam module. Licence not confirmed: do not ingest before checking |
| SoK on LLM-generated phishing, arXiv 2508.21457 | Nine stages in which attackers get around LLM guardrails | Expect fluent lures; URL-only checks will miss more |
| PhishDebate, arXiv 2506.15656 | Several LLM agents debate whether a site is phishing | An option for the explanation layer; cost and latency not measured |
| Small language models for phishing websites, arXiv 2511.15434 | Compares 15 models of up to 70B parameters | Locally run small models are a realistic choice for the optional AI layer |
| arXiv 2408.05667 (search summary calls it PhishLang; the search titles differ) | Lightweight LLM with page context and explanation text | Check the title before citing |
| Phishing pages written by LLMs, par.nsf.gov 10514634 | Reports 96 % (website prompts) and 94 % (email prompts); the metric is not shown | Check the metric before quoting |
| Drichel et al., "Finding Phish in a Haystack", ARES 2021 (arXiv 2106.12343) | Real-time phishing classification on certificate transparency logs; criticises earlier work that skipped real logs | A certificate feed is a missing early-warning source for us |
| Scheitle et al., "The Rise of Certificate Transparency", IMC 2018 (arXiv 1809.08325) | CT logs help spot phishing domains; attackers can read the same logs | Certificates can appear before a campaign: a lead time to measure |
| US patent 11546377 B2 | CT monitoring with passive DNS and lexical features; performance claims are self-reported | CT-based early detection is already patented: do not claim it as new |
| SANS ISC diary, 6 Apr 2026 (isc.sans.edu/diary.html?date=2026-04-06) | Analysts still see open redirects in phishing lures in 2026 | Trusted-redirect handling is current |
| SANS ISC diary, May 2025 (isc.sans.edu/diary/31950) | Phishing waves abusing google.com redirects | Same pattern as our redirect test |
| KnowBe4, "Make-Shift Brand Impersonation" (blog.knowbe4.com/make-shift-brand-impersonation-abusing-trusted-domains-with-open-redirects) | Multi-payload campaign; open redirect (CWE-601) as the main technique, per the search summary | Matches the fix we shipped |
| Microsoft, "Widespread credential phishing campaign abuses open redirector links" (2021) | A 2021 campaign that abused open redirectors | Background only |

**Could not verify:** a claim that 350-plus domains used one open-redirect campaign (Microsoft OAuth post; date not shown); the NSF paper's metric; the exact ATT&CK sub-technique list (check attack.mitre.org).

**Novelty note, updated:** certificate-transparency monitoring for phishing is covered by a granted patent (US 11546377 B2) and by academic work. Our claim is narrower: the registration feed, UAE rulebook evidence, cloaking test, and call hold in one pipeline. Do not claim CT monitoring as new.

## Experiments (24 Nov, bucket layer)

| # | Change | Result | Decision |
|---|---|---|---|
| 13 | Public file buckets (S3, Backblaze B2, Azure Blob, Google Storage, Cloudflare R2, DigitalOcean Spaces): the verdict uses the bucket name, the path and the query. A victim's e-mail in the link (raw or base64) is strong evidence; a famous name with lure words is strong; two lure words, or a famous name alone, is suspicious. | Validation (30,528 URLs): strict recall 91.77 to 91.61 %, cautious 93.13 to 93.34 %, strict false alarms 199 to 198. Test (33,766 URLs): strict 93.92 to 93.93 %, cautious 95.24 to 95.35 % (+10 caught), false alarms unchanged. Named UAE phishing: strict 95.7 to 96.3 %; legitimate verdicts 12 to 4. | Kept. |
| 14 | Bucket cap: a bucket file with no victim e-mail and no famous name with lure words is capped at suspicious | Probe: reports-2025.s3.amazonaws.com/annual.html scored 1.00 before any bucket evidence, because the model reads bucket hostnames as phishing-like. Bucket rows, validation: 27 phishing without the cap, 5 with it (24 suspicious); cautious unchanged. Test: 14 without, 5 with (9 suspicious); cautious unchanged. | Kept. Chosen from the probe and the design rule before the split numbers were computed. It costs strict recall on bucket phishing with no content evidence. |
| 15 | Two lure words give suspicious, not phishing | The first version gave phishing at three lure words; reduced to two words at suspicious | Kept. Lure words are weak alone. |

**The model's hostname prior.** Our training data holds almost no legitimate bucket URLs (one in validation, one in test), so the URL model learned bucket hostnames as phishing-like. The probe shows it. The model is not retrained in this pass; the cap limits its effect. A labelled benign bucket sample is the P0 fix.

**Process note.** tools/eval-judge.js writes data/judge-report.json only for the test split. A validation run leaves the test report in place, so a copy taken after a validation run is stale. The validation numbers above come from its console output and from an ablation (same code, bucket layer off), not from a copied JSON.

**Unit tests:** 61 of 61 after the bucket layer.

## Prior art and the UAE test protocol (24 Nov, night, written before the first run)

### What others do (searched 24 Nov; from search results, to be checked against the originals before quoting)

| Source | What it reports | What we do about it |
|---|---|---|
| PhreshPhish, arXiv 2507.10854 (https://arxiv.org/html/2507.10854v2) | Time-based splits and pruning of near-duplicates; older phishing datasets had leakage and unrealistic phishing rates | Phishing is split by time and legitimate sites by domain. We do not yet screen near-duplicates, so diagnostic D1 measures infrastructure reuse instead |
| arXiv 2005.08454 (https://arxiv.org/pdf/2005.08454) | URL classifiers flag legitimate sites of frequently targeted brands (for example Netflix, PayPal) and mislabel URLs that contain "login" | Diagnostic D2 measures false alarms on legitimate URLs with UAE brand tokens and on URLs containing "login" |
| Know Your Phish, arXiv 1510.06501 (https://arxiv.org/pdf/1510.06501) | Brand-based methods miss phishing aimed at brands that were absent from earlier attacks | The UAE set is the easier case, and it is reported as such. We also report which catches come from the rulebook and which from the model |
| arXiv 2411.09813 (https://ar5iv.labs.arxiv.org/html/2411.09813) | URL features may not transfer between datasets | Stated limit: one data family (the OpenPhish history). No transfer claim is made |
| Springer chapter, doi 10.1007/978-3-031-84371-6_16 (2025; abstract only, not read in full), and Hussain and Shabaan 2015 (https://repository.mdx.ac.uk/item/89z14) | The chapter is a design-science detection tool for UAE critical infrastructure; the 2015 paper is an impact study for UAE online banking | No public labelled UAE bank phishing set was found, so our UAE set is constructed and labelled as such |
| OpenPhish academic use (https://openphish.com/academic_use.html) | An academic track for accredited research bodies; non-commercial use; OpenPhish must be named with its URL in outputs | Cite OpenPhish with its URL. The submission repository does not contain the OpenPhish history. The sources disagree on whether the free Community feed is free or paid, so check openphish.com before any external release |
| ADCB StaySafe (https://www.adcb.com/en/consumer-education-awareness/fraud-awareness/phishing-scam) | A bank already points customers to a tool that cross-references sources to flag scam sites | Make a pitch comparison only after checking how StaySafe works |

### Protocol (fixed before the first run; no rule below may change to fit a result)

1. **Phishing:** unique URLs in `data_raw/urlv2/openphish_history.tsv` first seen 25 Oct to 24 Nov 2026 (the test window), whose lowercase text contains a UAE brand token from `project/data/brands.js` (the UAE block, tokens of 4 or more characters). The script checks that all of them are label 1 in `split_test.tsv`.
2. **Legitimate:** `split_uae.tsv`, the official UAE institution pages, which the shipped model never trained on.
3. **Judge:** `judgeOffline` only, with no network and no page visits. Strict = phishing verdict; cautious = phishing or suspicious. **Model alone:** `mlUrlScore2` flags when `p >= threshold`.
4. **Metrics:** recall on phishing, false-alarm rate on legitimate pages, and precision on the combined set (this depends on the mix, so it is not comparable with the test split). 95% bootstrap intervals, 1,000 resamples, seed 20261124.
5. **Breakdown:** UAE phishing caught by a rule only, by the model only, by both, or by neither.
6. **Diagnostics (not headline; they change no threshold):**
   - D1: the share of UAE phishing whose hostname or registrable domain also appears in phishing first seen before 4 Oct, and recall on the subset with no such overlap.
   - D2: false alarms on validation-split legitimate URLs that contain a UAE brand token or the word "login", compared with all validation-split legitimate URLs.
7. **Honesty:** the test window has been measured after each change, so this set is not blind. Every result is logged here, including weak ones. No threshold or rule changes on the basis of this test.
8. **Privacy:** any phishing URL in output is defanged (hxxp, [.]).



### Result (run once, 24 Nov night; numbers from project/data/uae-report.json)

| Measure | Value | 95% interval | Note |
|---|---|---|---|
| UAE phishing URLs, n | 14 | | Test window, UAE brand token of 4+ characters, label 1 in split_test |
| Judge, strict recall | 85.7% (12 of 14) | 64.3% to 100% bootstrap; 60.1% to 96.0% Wilson | Wide because n is small |
| Judge, cautious recall | 92.9% (13 of 14) | 78.6% to 100% bootstrap | |
| Model alone, recall | 85.7% (12 of 14) | 64.3% to 100% bootstrap | The same 12 as the judge |
| Official UAE pages, n | 2,231 | | split_uae: pages of the 77 listed institutions |
| Judge, strict false alarms | 0% | | Allowlist by design, so not a finding |
| Model alone, false alarms | 2.78% (62 of 2,231) | 2.11% to 3.50% bootstrap | The honest measure on official pages |
| Precision, combined | 100% | | Trivial with 14 positives and the allowlist, so not a finding |

Breakdown of the 14: caught by both judge and model 12; judge only 0; model only 0; neither 2. Judge catches that carry at least one rule reason: 12.

Diagnostics (not headline):
- D1, infrastructure reuse: no host was seen in phishing before 4 Oct; 2 of 14 registrable domains were. On the 12 with an unseen registrable domain, recall is 83.3% (10 of 12).
- D2, validation split: over all legitimate URLs the judge's strict false alarm rate is 0.72% and the model's is 0.75%. Legitimate URLs with a UAE brand token: 0 false alarms of 31. Legitimate URLs containing the word login: 9 of 43 (21%).
- Post-hoc sensitivity, added after the run and NOT the headline: the substring rule admits spurious matches. Both misses matched the token eand inside a longer word on one unrelated domain, so they are not UAE-branded. With whole-label matches only, 5 of 5 are caught (Wilson 95%: 56.5% to 100%; the bootstrap collapses to 100% at n = 5).
- Login-word cap, measured on validation only and NOT applied: capping login-only strict verdicts at suspicious would remove 7 of 175 false alarms (0.72% to 0.69%) and lose 32 of 6,127 phishing verdicts (recall 92.8% to 92.3%). Not worth it.

Interpretation:
- What the result supports: the judge catches 12 of 14 UAE brand-named phishing URLs in the held-out window, and the model alone catches the same 12. The sample is too small for a firm claim; the interval runs from about 60% to 100%.
- What it does not support: real-world UAE performance. The set is built from brand names, which makes it easier than real life, as the protocol says.
- Known weakness to disclose: legitimate URLs containing the word login are flagged about 1 time in 5 on a small validation sample. The fix belongs to the model work after the submission (more labelled legitimate login pages).
- The judge's 0% on official pages comes from the allowlist and is not evidence. The model alone (2.8%) is the honest figure.
- The test window has been measured after each change, so this set is not blind.

Correction: the 2.8% model-alone figure is for the official pages of the 77 listed institutions (split_uae). It is not a figure for institutions outside the list. Open item 13 in 01_INVENTORY_AND_STATUS.md and any other place that says otherwise must be corrected.

Next step for a stronger, blind UAE result: a fresh set of UAE-brand phishing first seen after 24 Nov, with whole-label matching fixed in advance. That needs new data (an OpenPhish feed download), which needs explicit permission and a licence check first.

## Unseen-data tests (24 Nov, late; written before the first run)

Why: the judges will test on data we have not used. Two tests use data that the model and the rules never saw.

### Test A: Phishing.Database, unseen by domain

1. **Population:** data_raw/urlv2/pdb_active.txt (Phishing.Database active list, undated, 789,051 lines). It is a second source, independent of OpenPhish.
2. **Exclusion:** remove every URL whose registrable domain (the training script's rule) appears in any of these sets: (a) the phishing domains of the training set, rebuilt exactly: OpenPhish rows dated before 4 Oct, plus the Phishing.Database sample that tools/train-url-model2.js draws with seed 7 (160,000 draws, same skip rule); (b) every PhiUSIIL phishing row (a superset of what training used, so the exclusion is conservative); (c) the OpenPhish validation and test windows (from 4 Oct).
3. **Judge:** judgeOffline only, with no network. Strict = phishing verdict; cautious = phishing or suspicious. Recall with a 95% bootstrap interval (1,000 resamples, seed 20261124).
4. **Not measured here:** the false-alarm rate on unseen legitimate sites. The held-out figure (0.58 %) stands, and the limit is stated.
5. **Limit:** Phishing.Database has no dates, so this is a domain-disjoint test, not a time-disjoint one.

### Test B: new domains, early detection

1. **Population:** the raw new-domain lists of 22 and 23 Nov 2026 (data_raw/nrd, one registrable domain per line). Local only: no name is published; only counts and medians are written.
2. **Judge:** judgeOffline on https://NAME/ at the list date, with no network.
3. **Confirmation:** a name is confirmed if OpenPhish has any URL on its registrable domain dated on or after its list date, up to 24 Nov.
4. **Report:** how many names the judge flags (strict and cautious); how many flagged names are confirmed (precision); the base rate of confirmation over all names; recall (confirmed and flagged, over all confirmed); and the lead time in days (median and range) for confirmed names.
5. **Limit:** the window after each list is only one to two days, so the confirmed count will be small. Report it as small-n, with its interval.

### Rules for both tests

No threshold or rule changes on the basis of these tests. If a defect is found and fixed, it is logged separately, and the fixed code is run once more on the same test. Every result is logged, including weak ones.

### Test C: the new-domain watch on its own output (early detection)

Why: Test B applied the URL judge to every new domain, which is not how the watch works. The watch looks only for names that imitate one of the 77 rulebook institutions. Test C measures the watch itself.

1. **Population:** the watch's suspects on the raw lists of 22 and 23 Nov, computed by the production function suspectsIn in server/nrd.js with the production thresholds (look-alike letters or a brand token, risk at least 0.6, weak tokens only as look-alikes). Local only; no name is written.
2. **Confirmation and lead time:** as in Test B. A suspect is confirmed if OpenPhish has a URL on its registrable domain dated on or after its list date, up to 24 Nov.
3. **Report:** suspects per list; precision (confirmed suspects over suspects); base rate (confirmed names over all names in the same list); lift (precision over base rate); recall on confirmed names; lead time in days (median and range).
4. **Limit:** the confirmation window is one to two days, so the counts are small. Lead time is claimed only for confirmed cases.
5. **Rule:** no threshold or rule changes on the basis of this test.

## Results of the unseen-data tests (24 Nov, late; each run once; numbers in project/data/unseen-report.json and project/data/watch-report.json)

**Test A, Phishing.Database, unseen by domain**
- Population 789,052 lines. Excluded 496,615, because their registrable domain was seen in training, validation or test. Unseen: 292,437.
- Recall, strict: 88.96 % (95 % interval 88.85 % to 89.08 %). Cautious: 93.12 % (93.03 % to 93.22 %).
- Limits: domain-disjoint, not time-disjoint. No unseen legitimate sites, so no false-alarm figure here.

**Test B, new domains through the judge (not the watch)**
- 140,000 names (22 and 23 Nov). Flagged strict: 24,025 (17.2 %). Flagged phishing or suspicious: 31,881 (22.8 %).
- Confirmed later in OpenPhish within one to two days: 330 names (0.24 %). Precision of strict flags: 0.49 %, about twice the base rate.
- Reading: the judge is built for URLs with paths and for messages, not for bare lists of new domains. The population is unlabelled, so these flags are not accuracy evidence and must not be presented as accuracy.

**Test C, the new-domain watch on its own output**
- 68 suspects (25 on 22 Nov, 43 on 23 Nov): the same 68 as in the earlier audit.
- Confirmed: 1 suspect, on the same day (lead 0 days). Precision 1.5 %, base rate 0.24 %, lift about 6 on one event. Recall on the 330 confirmed names: 0.3 %.
- Reading: the watch sees only look-alikes of the 77 institutions, so it cannot see most phishing. The sample is too small to measure precision or lead time. Lead time is not claimed.

**No-error tests (five new, run in npm test)**
- 3,000 seeded random inputs through the judge; 1,500 through the model and the analyser; 30 hostile edge cases; a messy list file; a 20,000-URL list.
- One expectation was corrected, not the code: an input that is not a web address carries score null by design.
- Full suite: 92 of 92 pass.

**Code change, behaviour unchanged:** server/nrd.js. The per-list check moved into suspectsIn, so Test C runs the production code. It reproduces the 68 suspects.
