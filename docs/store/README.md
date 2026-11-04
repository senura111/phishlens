# Microsoft Edge Add-ons submission

Everything needed to submit PhishLens 2.0.0 in Partner Center, in the order of the
Partner Center pages. It follows Microsoft's
[Publish a Microsoft Edge extension](https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension)
(page last updated 12 August 2026) and the
[Developer policies for the Microsoft Edge Add-ons website](https://learn.microsoft.com/en-us/legal/microsoft-edge/extensions/developer-policies)
(last updated 24 July 2026), both checked on 5 November 2026. Limits can change, so
check them again in Partner Center when submitting.

## Files

| File | Partner Center field | Size | Pixels |
| --- | --- | --- | --- |
| `phishlens-edge-v2.0.0.zip` | Packages: the extension package | 817,679 bytes | |
| `description.txt` | Store listings: Description | 2,583 characters | |
| `certification-notes.txt` | Submit: Notes for certification | 2,515 characters | |
| `logo-300.png` | Store listings: Extension logo | 12,681 bytes | 300 x 300 |
| `promo-small-440x280.png` | Store listings: Small promotional tile | 13,013 bytes | 440 x 280 |
| `screenshot-1-red-phishing.png` | Store listings: Screenshots (1 of 2) | 172,851 bytes | 1280 x 800 |
| `screenshot-2-amber-suspicious.png` | Store listings: Screenshots (2 of 2) | 98,279 bytes | 1280 x 800 |

## 1. Packages

Upload `phishlens-edge-v2.0.0.zip`.

- It holds the contents of `extension/` exactly as committed (22 files, built from
  commit `df568f1` with `git cat-file`, so no line endings are converted).
  `manifest.json` is at the top level of the zip. There are no tests, docs or Python
  files in it: those live outside `extension/`.
- It is byte for byte the same as the GitHub release zip
  (`phishlens-extension-v2.0.0.zip`, see the README's "For developers").
- Version `2.0.0`, from `manifest.json`. Every new upload needs a higher version.
- The name and short description in Partner Center come from `manifest.json` and
  can't be edited there: changing them means a new package.

## 2. Availability

- Visibility: **Public**
- Markets: **all markets** (the default)

## 3. Properties

- Category: **Productivity**
- Website: https://github.com/senura111/phishlens
- Support contact: https://github.com/senura111/phishlens/issues
- Mature content: **no** (leave unticked)

## 4. Privacy

**Single purpose description:**

> Warns Gmail users about phishing emails: it analyses the email they open, inside the
> browser, and shows a banner above it with the verdict and the reasons.

**Permission justification.** `manifest.json` declares no `permissions` and no
`host_permissions`. Its only site access is one content script match:

| Manifest entry | Justification |
| --- | --- |
| `content_scripts` match `https://mail.google.com/*` | Reads the email the user opens in Gmail and shows the phishing warning banner above it; the scripts run on no other site. |

If Partner Center lists the Gmail match as host access, paste the same line. The
background service worker and the toolbar popup are not permissions; the service
worker only loads the model file that ships inside the package.

**Are you using remote code?** **No, I am not using remote code.** All JavaScript and
the model ship in the package; nothing is downloaded or evaluated at run time. (Remote
code isn't allowed in Manifest V3 anyway.)

**Data usage.** What PhishLens does, for the checkboxes:

- It **reads**, on the user's device, the email the user opens: sender name and
  address, subject, body text, links and attachment file names. That is personal
  communications and website content.
- It **doesn't collect** any of it: nothing leaves the browser, nothing is stored, and
  there are no servers, analytics or tracking.

I couldn't see the Partner Center form itself (it needs your sign-in). If the form
asks what data the extension *collects* (sends or keeps), tick none. If it asks what
the extension *handles or accesses* on the device, tick "Personal communications"
(and "Website content" if listed), because that matches the privacy policy, which
lists what PhishLens reads. Tick all the certification statements (data not sold,
not used for unrelated purposes, not used for creditworthiness or lending): they are
true because no data is collected.

**Privacy policy URL:** https://senura111.github.io/phishlens/privacy-policy.html
([privacy-policy.md](../privacy-policy.md), published by GitHub Pages from `main`'s
`docs/` folder). Open the link before submitting: Microsoft requires that it works.

## 5. Store listings (English)

- **Extension name:** PhishLens (from `manifest.json`)
- **Short description** (from `manifest.json`, 119 characters):

  > Warns about phishing emails in Gmail and explains why. Emails are analysed inside
  > your browser and never sent anywhere.

- **Description:** paste [description.txt](description.txt) (2,583 characters;
  Microsoft allows 250 to 10,000).
- **Extension logo:** `logo-300.png` (1:1, 300 x 300 recommended, at least 128 x 128).
  Made from [docs/icon.svg](../icon.svg), the artwork the toolbar icons come from, with
  transparent corners.
- **Small promotional tile:** `promo-small-440x280.png` (must be 440 x 280).
- **Large promotional tile** (optional, 1400 x 560): not made.
- **Screenshots** (optional, at most 6, 640 x 480 or 1280 x 800):
  1. `screenshot-1-red-phishing.png`: a red banner on a test email whose link shows
     paypal.com but goes to a raw IP address.
  2. `screenshot-2-amber-suspicious.png`: the same words with an honest link get
     amber, and a key to the four colours.
- **YouTube video URL:** none.
- **Search terms** (at most 7 terms, 21 words, 30 characters each):
  `phishing`, `Gmail`, `email security`, `scam detector`, `fraud`, `privacy`,
  `safe email` (7 terms, 10 words).

## 6. Notes for certification

Paste [certification-notes.txt](certification-notes.txt). It tells testers that no
PhishLens account is needed, and gives two test emails to send to themselves, one
for a red banner and one for a green one. The red one links to `203.0.113.5`, an
address reserved for documentation, so testers never get a link to a real server.

## How the screenshots were made

Both screenshots are our own test emails from `docs/screenshots/`
(`banner-red-phishing.png` and `banner-amber-honest-link.png`), sent to ourselves.
They were placed on a 1280 x 800 page with a headline and rendered with Microsoft
Edge in headless mode. They are only scaled down (0.8 and 0.58), never up or
stretched, as the policy asks ("must not be stretched or blurry").

- The sender's name, address and photo were already blurred in the originals; there
  are no other account details on screen. The red screenshot shows the IP address
  `185.22.10.4` used when it was taken; the tester notes use `203.0.113.5` instead.
- The other screenshots in `docs/screenshots/` (the green Reddit email, and the
  amber university and Microsoft emails) are real emails, so they aren't used here.
  That's why there's no green screenshot yet.
- The Gmail interface in them is in Sinhala; only the PhishLens banner is in English.

## Policy points this listing follows

- **No other browsers are named** in the description, screenshots or tile (policy
  1.1.1: the listing "must not reference other browsers").
- **Limitations are stated** in the description, including that it depends on Gmail
  on the web (policy 1.1: disclose important limitations and dependencies on other
  products).
- **No permissions beyond the Gmail content script** (policy 1.6).
- **No obfuscated code**: the generated files in `extension/analyzer/generated/` are
  readable, with comments (policy 1.1.7).
- **At most seven search terms** (policy 1.1.4).
