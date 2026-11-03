# PhishLens

A Chrome extension that warns Gmail users about phishing emails and explains *why* an email
looks suspicious.

The classifier runs in a small Python API on your own machine, so email content never leaves
your computer.

> **Status:** early development. Nothing is runnable yet. See [Roadmap](#roadmap).

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
   address, subject, body text, and links (visible text and the real destination).
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
| 1 | Model: preprocessing, rule-based signals, scikit-learn classifier | Not started |
| 2 | Local API: FastAPI `POST /analyze` and `GET /health` | Not started |
| 3 | Chrome extension (Manifest V3): Gmail banner and popup | Not started |
| 4 | Polish: link highlighting, toolbar badge, sensitivity setting, demo GIF | Optional |

## Project layout

```
phishlens/
├── model/       # Python: preprocessing, rules, training, predict.py
├── api/         # FastAPI wrapper around the model
├── extension/   # Chrome extension (vanilla JS, no build step)
└── docs/        # screenshots and notes
```

## How to run

Instructions will be added as each phase is completed.

## License

[MIT](LICENSE) © 2026 Senura Nimthaka
