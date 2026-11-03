# PhishLens

A Chrome extension that warns Gmail users about phishing emails and explains *why* an email
looks suspicious.

The classifier runs in a small Python API on your own machine, so email content never leaves
your computer.

> **Status:** early development. The model can be trained and evaluated; the API and the
> extension are not built yet. See [Roadmap](#roadmap).

## How it works

```
Gmail tab ─> content script (reads the open email)
          ─> service worker
          ─> local API (127.0.0.1:8000)
          ─> rules + ML model
          ─> verdict + reasons
          ─> warning banner shown inside Gmail
```

1. When you open an email, the extension reads what Gmail shows on the page: sender name and
   address, subject, body text, links (visible text and the real destination), and
   attachment file names. Attachments themselves are never downloaded or opened.
2. It sends that to a FastAPI server running locally on `127.0.0.1`.
3. The server combines rule-based checks (lookalike domains, mismatched links, urgency
   phrases, requests for passwords or gift cards, and more) with a TF-IDF + Logistic
   Regression classifier.
4. The extension shows a banner above the email: **red** for phishing, **amber** for
   suspicious, **green** for safe, with a list of human-readable reasons.

## Privacy and security

- The API only listens on `127.0.0.1`, never on your network.
- No email content is logged, stored, or sent anywhere. No analytics or telemetry.
- The extension asks for the minimum permissions it needs and ships no remote code.
- Email content is treated as untrusted and is never inserted into the page as HTML.

## Roadmap

| Phase | What | Status |
| ----- | ---- | ------ |
| 1 | Model: preprocessing, rule-based signals, scikit-learn classifier | In progress (training done; `predict.analyze()` next) |
| 2 | Local API: FastAPI `POST /analyze` and `GET /health` | Not started |
| 3 | Chrome extension (Manifest V3): Gmail banner and popup | Not started |
| 4 | Polish: link highlighting, toolbar badge, sensitivity setting, demo GIF | Optional |

## Model results (v1)

> **Read with care.** The test set comes from the same two datasets as the training
> set, so it shares their biases (see [Known limitations](#known-limitations)). These
> scores say the model separates *these* datasets well. Real-world accuracy on a modern
> inbox will be lower, especially on marketing and transactional email.

**Setup.** 6,776 English emails (2,753 phishing, 4,023 safe) after cleaning. Emails whose
text is at least 80% similar (TF-IDF cosine) are grouped into one campaign: 6,031
campaigns, the largest a 29-email "your mailbox will be deactivated" campaign spanning
2016–2022. `GroupShuffleSplit` puts 80% of campaigns in train and 20% in test, so no
campaign is on both sides: 5,417 train emails and 1,359 test emails (584 phishing).

**Scoring.** All three approaches are Logistic Regression with `class_weight="balanced"`.
The text model reads the subject and body only (TF-IDF of words and word pairs, letters
only). An email is *flagged* when its verdict is phishing (score ≥ 0.8) or suspicious
(0.5–0.8), i.e. when it would get a red or amber banner. A single medium-severity rule
(such as urgency) can't make an email "phishing" on its own: that needs a high-severity
rule, two medium ones, or a text score over 0.8 without the rules' help.

| Approach | Precision | Recall | F1 | False positives | Missed phishing |
| --- | --- | --- | --- | --- | --- |
| Rules only | 0.925 | 0.719 | 0.809 | 34 | 164 |
| **Text only** (saved) | **0.991** | **0.979** | **0.985** | 5 | 12 |
| Text + rules | 0.995 | 0.971 | 0.983 | 3 | 17 |

Confusion matrices (rows = true label, columns = prediction):

| | Rules only: flagged | not flagged | Text only: flagged | not flagged | Text + rules: flagged | not flagged |
| --- | --- | --- | --- | --- | --- | --- |
| Phishing | 420 | 164 | 572 | 12 | 567 | 17 |
| Safe | 34 | 741 | 5 | 770 | 3 | 772 |

No safe test email got a red "phishing" verdict from the text or text + rules
models; all their false positives were amber "suspicious".

**False positives by source.** `hard_ham` is legitimate mail that looks spammy
(newsletters, promotions), the closest thing in the data to modern marketing email:

| Source | Safe test emails | Rules only | Text only | Text + rules |
| --- | --- | --- | --- | --- |
| easy_ham | 462 | 9 (1.9%) | 0 (0.0%) | 0 (0.0%) |
| easy_ham_2 | 264 | 3 (1.1%) | 1 (0.4%) | 0 (0.0%) |
| **hard_ham** | **49** | **22 (44.9%)** | **4 (8.2%)** | **3 (6.1%)** |

The hard_ham false positives are promotions: a software release announcement, an
online-store offer, a SourceForge update. With only 49 hard_ham test emails these rates
are rough, but the pattern is clear: marketing email is where false positives will
come from. Rules alone flag almost half of it, because urgency and offers ("act now",
"30 dollar thank you") read like pressure tactics.

**Which approach is saved.** Text only, by F1. It is effectively a tie with text +
rules (0.985 vs 0.983: 5 vs 3 false positives, 12 vs 17 missed phishing). The rules
still run on every email and are shown as the reasons in the banner either way.

**Top 20 words of the text model.**

- Phishing: your, account, please, email, you, your account, dear, below, password,
  click, notification, document, update, payment, you have, this email, attached, we,
  our, mailbox
- Safe: it, that, the, but, there, they, of, my, what, just, so, like, one, which,
  linux, at, when, razor, then, think

The phishing words are genuine phishing language. The safe words show what survived
cleaning: conversational style (it, but, think) and mailing-list topics (linux, razor,
the Razor spam filter). Formal, impersonal legitimate email (receipts, alerts) doesn't
look like either list, which is another reason to expect more false positives there.

In the text + rules model, urgency has the largest rule weight (+3.4 log-odds), which
is why the "one medium rule can't make it phishing" safeguard matters.

## Known limitations

The model is trained on public datasets: the
[Nazario phishing corpus](https://monkey.org/~jose/phishing/) (2015–2025) and the
[SpamAssassin ham corpus](https://spamassassin.apache.org/old/publiccorpus/) (2002–2003).
Preprocessing removes signals that only reveal *which dataset* an email came from:
dates, years, anonymised names, mailing-list footers, quoted replies, copyright
footers. Some biases can't be cleaned away:

- **Topic bias.** The legitimate emails are mostly 2002-era tech mailing lists (Linux,
  Perl, spam filtering). Everyday legitimate mail such as bank alerts, receipts,
  deliveries, and work email is barely represented. Expect more false positives on that
  kind of mail than the test scores suggest.
- **English only.** All the legitimate emails are in English, so non-English phishing
  would teach the model "foreign language = phishing". v1 drops non-English emails
  from training (158 phishing, 8 legitimate). Results on non-English email are not
  reliable.
- **Brand clusters.** Many phishing emails copy real brand templates (USAA, DocuSign,
  WeTransfer, Google), and there are no genuine emails from those brands in the
  legitimate set. The model may treat a brand's name or footer as a phishing sign. To
  keep test scores honest, near-duplicate campaigns are kept together on one side of
  the train/test split.

After changing preprocessing, re-check for shortcuts with
`python -m model.src.audit_shortcuts`.

## Project layout

```
phishlens/
├── model/       # Python: preprocessing, rules, training, predict.py
├── api/         # FastAPI wrapper around the model
├── extension/   # Chrome extension (vanilla JS, no build step)
└── docs/        # screenshots and notes
```

## How to run

### Model (Phase 1)

Requires Python 3.11+. From the repo root on Windows:

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -r model/requirements.txt
```

Download the datasets as described in [model/data/README.md](model/data/README.md), then:

```bash
.venv\Scripts\python -m model.src.preprocess        # dataset summary
.venv\Scripts\python -m model.src.audit_shortcuts   # check for dataset shortcuts
.venv\Scripts\python -m model.src.features          # how often each rule fires
.venv\Scripts\python -m model.src.train             # train, evaluate, save the model
.venv\Scripts\python -m pytest                      # run the tests
```

Training saves `model/artifacts/phishlens.joblib` (about 1 MB). It is not committed;
run the training step to create it.

## License

[MIT](LICENSE) © 2026 Senura Nimthaka
