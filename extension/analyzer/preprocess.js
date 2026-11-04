// Cleaning used at prediction time: the JavaScript twin of the "training AND
// prediction" part of model/src/preprocess.py (prepare_email and what it calls).
// The training-only cleaning there (dataset artefacts, boilerplate) isn't needed.
//
// Every pattern is copied from the Python file; pyRegex() makes it match the same
// text in JavaScript. Keep the two files in step: tests/js/parity.test.mjs checks
// that both give the same cleaned email.

import {
  LINE_SPACES,
  pyRegex,
  pySplitlines,
  pyStrip,
  unique,
} from "./python-compat.js";

export const URL_RE = pyRegex(String.raw`(?:https?://|www\.)[^\s<>\"'()\[\]]+`, "ig");
// An email address. The lookbehind starts a match only at the beginning of a run of
// address characters, which keeps long runs fast (see preprocess.py).
const EMAIL_RE = pyRegex(String.raw`(?<![\w.+-])([.+-]*)\w[\w.+-]*@[\w-]+(?:\.[\w-]+)+\b`, "g");

// Replace each email address with a space.
function removeEmails(text) {
  return text.replace(EMAIL_RE, "$1 ");
}

const MONTH = String.raw`(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?`;
const YEAR = String.raw`(?:19[5-9]\d|20[0-4]\d)`;
const DATE_PATTERNS = [
  // ISO timestamps: 2002-09-30, 2002-09-30T00:15:00Z
  String.raw`\b${YEAR}-\d{1,2}-\d{1,2}(?:t\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?z?)?`,
  // "Aug 22, 2002", "May 5th", "August 2002"
  String.raw`\b${MONTH}\s+\d{1,2}(?:st|nd|rd|th)?\b(?:,?\s+${YEAR}\b)?`,
  String.raw`\b\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?${MONTH}(?:,?\s+${YEAR}\b)?`,
  String.raw`\b${MONTH},?\s+${YEAR}\b`,
  // Weekdays: full names anywhere, short names only before a comma.
  String.raw`\b(?:mon|tues|wednes|thurs|fri|satur|sun)day\b`,
  String.raw`\b(?:mon|tue|wed|thu|fri|sat|sun)\.?,`,
  // 22/08/2002, 2002-08-22, 8.22.02
  String.raw`\b\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4}\b`,
  // 14:38:22, 9:44 pm, and time zones (+0100, GMT, PDT)
  String.raw`\b\d{1,2}:\d{2}(?::\d{2})?(?:\s*[ap]\.?m\.?\b)?`,
  String.raw`(?<![\w$])[+-]\d{4}\b`,
  String.raw`\b(?:gmt|utc|[ecmp][sd]t|bst|cet|cest)\b`,
  // Any remaining standalone year
  String.raw`\b${YEAR}\b`,
];
const DATE_RE = pyRegex(DATE_PATTERNS.join("|"), "ig");

// Copyright footers: "(c) 2024 PayPal, Inc.", "All rights reserved". \xa9 is the
// copyright sign, written as a literal character in preprocess.py.
const COPYRIGHT_RE = pyRegex(
  [
    String.raw`\bcopyright\b\s*(?:(?:\(c\)|\xa9)\s*)?(?:${YEAR}\b|by\b)[^\n.|]{0,80}`,
    String.raw`\(c\)\s*${YEAR}\b[^\n.|]{0,80}`,
    String.raw`\xa9[^\n.|]{0,80}`,
    String.raw`\ball\s+rights\s+reserved\b\.?`,
  ].join("|"),
  "ig"
);

// Zero-width characters and other invisible formatting characters.
const INVISIBLE_RE = pyRegex(
  "[\\u{200b}-\\u{200f}\\u{2028}-\\u{202f}\\u{2060}-\\u{206f}\\u{feff}\\xad]",
  "g"
);
const SPACES_RE = pyRegex(String.raw`\s+`, "g");

// Unicode normalisation, invisible characters removed, spaces collapsed.
export function normalizeText(text) {
  text = text.normalize("NFKC").replace(INVISIBLE_RE, "");
  return pyStrip(text.replace(SPACES_RE, " "));
}

// Normalise text and remove anything that dates an email.
export function cleanText(text) {
  text = text.normalize("NFKC").replace(INVISIBLE_RE, "");
  text = text.replace(URL_RE, " ");
  text = removeEmails(text);
  text = text.replace(COPYRIGHT_RE, " "); // before dates: it uses the year to match
  text = text.replace(DATE_RE, " ");
  return tidyLines(text);
}

// Collapse spaces within each line and drop empty lines, but keep line breaks:
// they're sentence boundaries for the rules.
export function tidyLines(text) {
  return pySplitlines(text)
    .map((line) => pyStrip(line.replace(LINE_SPACES, " ")))
    .filter((line) => line)
    .join("\n");
}

// Single-word tags in square brackets ("[SPAM]") and "Re:" / "Fwd:" prefixes.
const SUBJECT_TAG_RE = pyRegex(String.raw`\[[^\s\]]+\]`, "g");
const REPLY_PREFIX_RE = pyRegex(String.raw`^\s*(?:(?:re|fwd?|aw|sv)\s*(?:\[\d+\])?\s*:\s*)+`, "i");

export function cleanSubject(subject) {
  subject = subject.replace(SUBJECT_TAG_RE, " ");
  return cleanText(pyStrip(subject).replace(REPLY_PREFIX_RE, ""));
}

// Plain-text emails have no <a> tags. Gmail turns bare URLs into links, so do the same.
function bareUrlLinks(text) {
  const links = [];
  for (const match of text.matchAll(URL_RE)) {
    const url = match[0].replace(/[.,;:!?]+$/, "");
    const href = url.toLowerCase().startsWith("http") ? url : "http://" + url;
    links.push({ text: url, href });
  }
  return links;
}

function linkKey(link) {
  return JSON.stringify([link.text, link.href]);
}

// preprocess.prepare_email(): clean one email's fields. Missing fields count as empty.
export function prepareEmail(fields) {
  const links = [...(fields.links ?? [])];
  const seen = new Set(links.map(linkKey));
  for (const link of bareUrlLinks(fields.body_text ?? "")) {
    const key = linkKey(link);
    if (!seen.has(key)) {
      seen.add(key);
      links.push(link);
    }
  }
  return {
    // Only normalised: an address or domain in the display name is exactly what
    // the sender_name_mismatch rule looks for.
    sender_name: normalizeText(fields.sender_name ?? ""),
    sender_email: pyStrip(fields.sender_email ?? "").toLowerCase(),
    subject: cleanSubject(fields.subject ?? ""),
    body_text: cleanText(fields.body_text ?? ""),
    links,
    // Names only, in order, without blanks or repeats.
    attachments: unique((fields.attachments ?? []).map(normalizeText).filter((name) => name)),
  };
}
