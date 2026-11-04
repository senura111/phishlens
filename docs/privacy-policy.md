# PhishLens privacy policy

*Last updated: 4 November 2026. Applies to PhishLens 1.0.0 and later (the browser-only
version).*

PhishLens is a browser extension that warns you about phishing emails in Gmail and
explains why an email looks suspicious. It is built so that your email never leaves
your computer.

## What PhishLens reads

When you open an email in Gmail (`https://mail.google.com`), PhishLens reads what Gmail
shows on the page for that email:

- the sender's display name and email address,
- the subject,
- the body text,
- the links (their visible text and where they really go),
- the file names of attachments.

PhishLens never downloads or opens attachments, and it doesn't read any other website,
your other tabs, or your browsing history.

## What PhishLens does with it

The email is analysed **inside your browser**, by code and a model that ship with the
extension. The result (a coloured banner and a list of reasons) is shown above the
email and kept only in that Gmail tab's memory, so it isn't analysed twice. It is
forgotten when you close or reload the tab.

PhishLens:

- **does not send** your emails, or anything about them, to the developer, to a server,
  or to anyone else. The extension makes no network requests at all; the only file it
  loads is its own model, from inside the extension.
- **does not store** your emails or the results, in the browser or anywhere else.
- **does not log** email content. The browser's developer console shows only the
  verdict, score and rule names for each email, never its text.
- **has no analytics, telemetry, advertising or tracking**, and no accounts.
- **does not sell or share** any data, because it collects none.

## Permissions

PhishLens asks for no browser permissions beyond running its scripts on
`https://mail.google.com/*`, which it needs to read the email you open and show the
banner. It has no access to other sites and no network access.

## Children

PhishLens doesn't collect personal information from anyone, including children.

## Changes

If a future version changes how data is handled, this policy will be updated before
that version is published, and the "Last updated" date above will change.

## Contact

PhishLens is an open-source project by Senura Nimthaka. The source code, which shows
exactly what the extension does, is at <https://github.com/senura111/phishlens>.
Questions can be asked by opening an issue there.
