# PhishLens — CLAUDE.md

## What this project is
PhishLens is a Chrome extension that warns Gmail users about phishing emails and explains *why*
an email looks suspicious. A local Python API runs the classifier, so email content never leaves
the user's machine.

Portfolio project by Senura Nimthaka. I'm learning as I build: briefly explain new concepts when
you introduce them, and prefer simple, readable code over clever code.

## Architecture
```
Gmail tab ─> content script (reads the open email)
          ─> service worker
          ─> local API (127.0.0.1:8000)
          ─> rules + ML model
          ─> verdict + reasons
          ─> warning banner shown inside Gmail
```

Built in this order:
1. `model/`: Python preprocessing, rule-based signals, scikit-learn classifier
2. `api/`: FastAPI wrapper around `model/src/predict.py`
3. `extension/`: Chrome Manifest V3 extension, vanilla JS, no build step

## Folder structure
```
phishlens/
├── CLAUDE.md
├── README.md
├── .gitignore
├── model/
│   ├── data/                  # datasets (gitignored)
│   │   └── README.md          # where to download the data
│   ├── notebooks/
│   │   └── exploration.ipynb
│   ├── src/
│   │   ├── preprocess.py      # parse .eml / text, clean, extract links
│   │   ├── features.py        # rule-based signals that produce reasons
│   │   ├── train.py           # train, evaluate, save model
│   │   └── predict.py         # analyze(email) -> verdict + reasons
│   ├── artifacts/             # saved model files
│   ├── tests/
│   └── requirements.txt
├── api/
│   ├── main.py                # FastAPI: POST /analyze, GET /health
│   ├── schemas.py             # Pydantic request/response models
│   └── tests/
├── extension/
│   ├── manifest.json
│   ├── content/
│   │   ├── selectors.js       # ALL Gmail DOM selectors live here
│   │   ├── gmail.js           # detect opened email, extract content
│   │   ├── banner.js          # render the warning banner
│   │   └── banner.css
│   ├── background/
│   │   └── service-worker.js  # talks to the local API
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.js
│   │   └── popup.css
│   └── icons/
└── docs/
    └── screenshots/
```

## Build phases
Work one phase at a time. Don't start the next phase until the current one works and its tests
pass. At the end of each phase, update the README with what was built and how to run it.

### Phase 1: Model
- Data: combine a phishing corpus (e.g. Nazario) with legitimate emails (e.g. SpamAssassin ham or
  Enron). Raw data is gitignored; `model/data/README.md` explains where to get it.
- IMPORTANT: use only inputs the extension can actually read from Gmail's page: sender name,
  sender address, subject, body text, links (visible text + real href), and attachment file
  names. Ignore raw headers
  (SPF/DKIM, Received) in v1. The extension can't see them, so the model must not depend on them.
- Rule-based signals in `features.py`, each producing a human-readable reason:
  - lookalike / misspelled brand domains (paypa1.com)
  - link text shows one domain but href points to another
  - raw-IP links or URL shorteners
  - urgency or threat phrases ("suspended", "within 24 hours")
  - requests for passwords, card details, gift cards
  - risky attachment mentions (.exe, .zip, .docm)
  - sender display name doesn't match the address domain
- Classifier: TF-IDF + Logistic Regression baseline, combined with rule signals. Save with
  joblib to `model/artifacts/`.
- Evaluate on a held-out test set: precision, recall, F1, confusion matrix. Put results in the
  README. Watch false positives: a tool that flags every newsletter is useless.
- `predict.py` exposes one function, `analyze(email: dict) -> dict`, matching the API contract.

### Phase 2: Local API
- FastAPI app with `POST /analyze` and `GET /health`. Load the model once at startup.
- Pydantic validation; reject bodies over 100 KB.
- Do NOT add CORS middleware. The extension calls the API from its service worker using
  `host_permissions`, which doesn't need CORS. Leaving CORS off stops random websites from
  using the local API.
- Tests with FastAPI's TestClient.
- Run: `uvicorn api.main:app --host 127.0.0.1 --port 8000`

### Phase 3: Chrome extension (Manifest V3)
- `manifest.json`: content scripts on `https://mail.google.com/*`, a background service worker,
  `host_permissions` for `https://mail.google.com/*` and `http://127.0.0.1:8000/*`, a popup.
- Content scripts can't use ES module imports, so list them in order in the manifest
  (selectors.js, banner.js, gmail.js).
- Gmail is a single-page app: use a MutationObserver to detect when an email is opened. Extract
  sender name/address, subject, body text, links, and attachment file names (names only, never
  download or open attachments), then send them to the service worker with
  `chrome.runtime.sendMessage`.
- The service worker calls the API and returns the result. If the API is offline, return a
  clear "server not running" state instead of failing silently.
- Banner above the email body: red = phishing, amber = suspicious, green = safe. Expandable
  list of reasons, dismiss button. Offline state shows a neutral grey banner.
- When the verdict is "safe", show any reasons as collapsed grey "minor notes", not as
  warnings. A lone rule hit on a safe email is usually harmless (a newsletter's
  click-tracking link, a brand name sent from an email-service domain), and warning
  styling there would teach users to ignore the banner.
- Popup: API status (via /health), short explanation, link to the GitHub repo.
- Load for testing: chrome://extensions → Developer mode → Load unpacked → `extension/`

### Phase 4: Polish (optional)
- Highlight dangerous links directly inside the email
- Toolbar badge with the last verdict
- Sensitivity setting in the popup
- Demo GIF and screenshots in the README

## API contract
`POST /analyze`
```json
{
  "sender_name": "PayPal Support",
  "sender_email": "support@paypa1-secure.com",
  "subject": "Your account will be suspended",
  "body_text": "...",
  "links": [{ "text": "paypal.com/login", "href": "http://185.22.10.4/login" }],
  "attachments": ["Invoice_2291.pdf.exe"]
}
```
`attachments` is optional: a list of attachment file names as Gmail shows them (names only,
never file contents). Missing or empty means no attachments are known.

Response:
```json
{
  "verdict": "phishing",
  "score": 0.92,
  "reasons": [
    { "id": "lookalike_domain", "severity": "high",
      "message": "Sender domain 'paypa1-secure.com' imitates paypal.com" }
  ]
}
```
`verdict` is one of `phishing`, `suspicious`, `safe`. Starting thresholds (tune after
evaluation): score ≥ 0.8 → phishing, 0.5–0.8 → suspicious, below 0.5 → safe.

## Security rules (non-negotiable)
This is a security tool, so it must not introduce its own vulnerabilities.
- Never insert email content or API responses with `innerHTML`. Use `textContent` and
  `createElement` (email content is attacker-controlled).
- The API binds to 127.0.0.1 only, never 0.0.0.0.
- Never log, store, or send email content anywhere. No analytics or telemetry.
- Minimal extension permissions: no `<all_urls>`, no `tabs` or `storage` unless a feature
  truly needs it.
- No remote code: all JS ships inside the extension.
- Never commit datasets, large model files, `.env` files, or API keys.

## Conventions
- Python 3.11+, type hints, black formatting, pytest
- Pin dependency versions in `requirements.txt`
- JS: `const`/`let`, no frameworks, no bundler
- Keep every Gmail DOM selector in `extension/content/selectors.js`. Gmail changes its markup,
  so selectors must be easy to update in one place. Prefer stable attributes over
  obfuscated class names.
- Small commits with clear messages, e.g. `feat(model): add lookalike-domain rule`
- Edit files with the file-editing tools, not sed/echo/heredocs; shell escapes like \n have
  corrupted files before.

## How to run
(Fill in as each phase is completed.)
