# Store listing materials (Microsoft Edge Add-ons)

Text and answers for the Microsoft Edge Add-ons listing in Partner Center. The same
text works for the Chrome Web Store. Check field limits against Partner Center when
submitting: they can change.

## Package

- Zip the **contents** of `extension/` (so `manifest.json` is at the top level of the
  zip). `extension/` holds only files that ship; tests and fixtures live in `tests/js/`.
- Version: `2.0.0` (from `manifest.json`; raise it for every new upload). 1.0.0 was
  the server-based release on GitHub; 2.0.0 is the first browser-only version.
- Before zipping, run the tests (README, "For developers").

## Name

PhishLens

## Short description

(Also the manifest's `description`, at most 132 characters.)

> Warns about phishing emails in Gmail and explains why. Emails are analysed inside
> your browser and never sent anywhere.

## Description

> PhishLens warns you about phishing emails in Gmail, and tells you why.
>
> When you open an email, PhishLens shows a banner above it:
>
> - Red: this email is likely phishing.
> - Amber: this email shows signs of phishing. Check carefully before clicking links or
>   replying.
> - Green: no signs of phishing found.
> - Grey: the email couldn't be checked, or only partly.
>
> Every warning comes with plain reasons you can check yourself, for example:
>
> - a link that shows one website but really goes to another,
> - a sender domain that imitates a well-known brand (paypa1.com),
> - links to raw IP addresses or URL shorteners,
> - look-alike letters from other alphabets hidden in words or domains,
> - pressure tactics ("your account will be suspended within 24 hours"),
> - requests for passwords, card details or gift cards,
> - risky attachments, such as "Invoice.pdf.exe".
>
> Private by design: PhishLens analyses emails inside your browser. It never sends
> your emails anywhere, never stores them, and has no servers, accounts, analytics or
> tracking. It only runs on mail.google.com.
>
> How it works: rule-based checks are combined with a machine-learning model (TF-IDF
> and Logistic Regression) trained on public phishing and legitimate email datasets.
> The project is open source: https://github.com/senura111/phishlens
>
> Limitations: PhishLens is an aid, not a guarantee. It can miss phishing and can
> sometimes warn about legitimate email, such as newsletters whose links go through
> tracking services. It works in English and with Gmail in the browser only.

## Category

Productivity

## Search terms

phishing, Gmail, email security, scam detector, fraud, privacy, safe email

## Website and support

- Website: https://github.com/senura111/phishlens
- Support: https://github.com/senura111/phishlens/issues
- Privacy policy URL: https://senura111.github.io/phishlens/privacy-policy.html
  ([privacy-policy.md](privacy-policy.md), published by GitHub Pages from `main`'s
  `docs/` folder).

## Privacy answers

- **Does the extension collect, transmit or store personal information?** It reads the
  email open in Gmail (sender, subject, body, links, attachment names) to analyse it
  locally in the browser. Nothing is collected, transmitted to anyone, or stored. No
  analytics or telemetry.
- **Permissions and why each is needed:**
  - Content scripts on `https://mail.google.com/*`: to read the email the user opens
    and show the warning banner above it. No other sites.
  - No `permissions` and no `host_permissions` are requested. The service worker only
    loads the model file bundled inside the extension.
- **Remote code:** none. All JavaScript and the model ship in the package; nothing is
  downloaded or evaluated at run time.

## Notes for certification

> PhishLens adds a banner above emails in Gmail (https://mail.google.com). To test:
> sign in to any Gmail account, open an email, and a coloured banner appears above it
> within a second. A phishing-style test email (for example one whose link text shows
> "paypal.com" while the link goes to an IP address such as http://203.0.113.5/) gets
> a red or amber banner with reasons. Clicking the toolbar icon opens a popup that says
> "Ready: emails are checked inside your browser." The extension makes no network
> requests; it needs no account and no configuration.

## Images still to make

- **Store logo**: 300 x 300 PNG, from `docs/icon.svg` (the extension icons in
  `extension/icons/` come from the same artwork).
- **Screenshots**: 1280 x 800 or 640 x 480 PNGs (up to 6). The README's Gmail
  screenshots in `docs/screenshots/` show the right states but need cropping or
  padding to one of those sizes, and must show only test data (no real inbox).
- Optional promotional tiles: 440 x 280 (small) and 1400 x 560 (large).
