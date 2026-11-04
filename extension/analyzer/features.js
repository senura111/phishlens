// Rule-based phishing signals: the JavaScript twin of model/src/features.py.
//
// Each rule looks at one email (already cleaned by prepareEmail) and, if it fires,
// returns a reason { id, severity, message }. The messages are the ones Python
// writes, word for word, and the banner shows them with textContent.
//
// Keep this file in step with features.py: same rules, same order, same patterns
// and messages. tests/js/parity.test.mjs checks both give the same reasons.

import {
  afterLast,
  isAscii,
  pyHead,
  pyLen,
  pyRegex,
  pyRsplit,
  pySplit,
  pySplitlines,
  scriptOf,
  unique,
} from "./python-compat.js";
import { hostOf, isIp, registrableDomain, unquote, urlsplit, UrlError } from "./urls.js";

export const HIGH = "high";
export const MEDIUM = "medium";
export const LOW = "low";
const MAX_QUOTE = 60; // longest piece of email text quoted in a message
const ELLIPSIS = String.fromCodePoint(0x2026);

export function makeReason(id, severity, message) {
  return { id, severity, message };
}

// Shorten attacker-controlled text before putting it in a message.
function quote(value) {
  value = pySplit(value).join(" ");
  return pyLen(value) <= MAX_QUOTE ? value : pyHead(value, MAX_QUOTE - 1) + ELLIPSIS;
}

// One reason per rule: the first finding, plus how many more there were.
function summarise(id, severity, findings) {
  if (findings.length === 0) {
    return [];
  }
  let message = findings[0];
  if (findings.length > 1) {
    message += ` (and ${findings.length - 1} more)`;
  }
  return [makeReason(id, severity, message)];
}

// --- Domain helpers -----------------------------------------------------------------

// Domains written in visible text ("paypal.com/login"). Only common TLDs count.
const COMMON_TLDS = (
  "com net org edu gov mil info biz io co me us uk ca au de fr it es nl be ch at se " +
  "no dk fi pl ru cn jp kr in br mx ar za nz ie pt gr tr il sg hk tw my ph id vn th " +
  "lk ng ke app dev xyz top online site shop store club live ly"
).split(" ");
const TEXT_DOMAIN_SOURCE =
  String.raw`(?<![\w@./-])(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:` +
  COMMON_TLDS.join("|") +
  String.raw`))(?![\w-])`;
const TEXT_DOMAIN_RE = pyRegex(TEXT_DOMAIN_SOURCE, "ig");
const URL_START_RE = pyRegex("https?://", "ig");

// _TEXT_DOMAIN_RE.findall(text): the domains as written.
function writtenDomains(text) {
  return Array.from(text.matchAll(TEXT_DOMAIN_RE), (match) => match[1]);
}

function domainsInText(text) {
  return writtenDomains(text).map((domain) => domain.toLowerCase());
}

// Registrable domains of URLs nested inside a link, e.g. the q= of a redirect:
// google.com/url?q=https://paypal.com -> {"paypal.com"}.
function redirectTargets(href) {
  const decoded = unquote(href);
  const starts = Array.from(decoded.matchAll(URL_START_RE), (m) => m.index).slice(1);
  const hosts = starts.map((start) => hostOf(decoded.slice(start)));
  return new Set(hosts.filter((host) => host).map(registrableDomain));
}

// --- Rule 1: link text shows one domain, href goes to another ----------------------

// Email-service click trackers: a newsletter link showing "brand.com" really goes
// to the tracker first. Not counted as a mismatch.
const CLICK_TRACKERS = new Set([
  "sendgrid.net", "list-manage.com", "mcsv.net", "mailchimp.com", "rs6.net",
  "exct.net", "hubspotlinks.com", "hs-sites.com", "mandrillapp.com", "mailgun.org",
  "sparkpostmail.com", "awstrack.me", "constantcontact.com", "cmail19.com",
  "cmail20.com", "createsend.com", "klclick.com", "mailjet.com",
  "online.com", // CNET's 2002 tracker (clickthru.online.com), common in the ham
]);

function linkTextMismatch(email) {
  const findings = [];
  for (const link of email.links ?? []) {
    const realHost = hostOf(link.href);
    if (!realHost) {
      continue;
    }
    const real = registrableDomain(realHost);
    if (CLICK_TRACKERS.has(real)) {
      continue;
    }
    for (const written of writtenDomains(link.text)) {
      const shown = registrableDomain(written.toLowerCase());
      // A redirect that ends up at the shown domain is not a mismatch.
      if (shown !== real && !redirectTargets(link.href).has(shown)) {
        findings.push(`A link shows '${quote(written)}' but goes to '${quote(realHost)}'`);
        break;
      }
    }
  }
  return summarise("link_text_mismatch", HIGH, findings);
}

// --- Rule 2: raw-IP links and URL shorteners ----------------------------------------

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
  "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "bit.do", "s.id", "t.ly", "v.gd",
  "short.io", "tiny.one", "shorte.st", "adf.ly", "qrco.de", "lnkd.in",
]);

function ipOrShortenedLinks(email) {
  const ipHosts = [];
  const shortened = [];
  for (const link of email.links ?? []) {
    const host = hostOf(link.href);
    if (isIp(host)) {
      ipHosts.push(`A link goes to a raw IP address (${quote(host)})`);
    } else if (URL_SHORTENERS.has(host.startsWith("www.") ? host.slice(4) : host)) {
      shortened.push(`A link uses the URL shortener ${quote(host)}, which hides where it goes`);
    }
  }
  return [
    ...summarise("ip_link", HIGH, ipHosts),
    ...summarise("url_shortener", MEDIUM, shortened),
  ];
}

// --- Rule 3: lookalike or misspelled brand domains ----------------------------------

// Brand name -> the domains it really owns (the first one is shown in messages).
const MICROSOFT = [
  "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com",
  "microsoftonline.com", "sharepoint.com", "onedrive.com", "hotmail.com",
];
const GOOGLE = [
  "google.com", "gmail.com", "googlemail.com", "youtube.com", "googleapis.com",
  "googleusercontent.com", "googlegroups.com", "gstatic.com", "goo.gl",
];
// A Map keeps the same order as Python's dict: brands are checked in this order.
export const BRANDS = new Map([
  ["paypal", ["paypal.com", "paypal.me", "paypalobjects.com"]],
  ["apple", ["apple.com", "icloud.com", "me.com"]],
  ["icloud", ["icloud.com", "apple.com"]],
  ["microsoft", MICROSOFT],
  ["outlook", MICROSOFT],
  ["office365", MICROSOFT],
  ["onedrive", MICROSOFT],
  ["sharepoint", MICROSOFT],
  ["google", GOOGLE],
  ["gmail", GOOGLE],
  ["amazon", ["amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.de"]],
  ["netflix", ["netflix.com"]],
  ["facebook", ["facebook.com", "fb.com", "facebookmail.com"]],
  ["instagram", ["instagram.com"]],
  ["linkedin", ["linkedin.com", "licdn.com"]],
  ["dhl", ["dhl.com", "dhl.de"]],
  ["fedex", ["fedex.com"]],
  ["ups", ["ups.com"]],
  ["usps", ["usps.com"]],
  ["chase", ["chase.com"]],
  ["wellsfargo", ["wellsfargo.com", "wf.com"]],
  ["bankofamerica", ["bankofamerica.com", "bofa.com"]],
  ["usaa", ["usaa.com"]],
  ["docusign", ["docusign.com", "docusign.net"]],
  ["dropbox", ["dropbox.com", "dropboxmail.com"]],
  ["wetransfer", ["wetransfer.com", "we.tl"]],
  ["adobe", ["adobe.com"]],
  ["ebay", ["ebay.com"]],
  ["coinbase", ["coinbase.com"]],
]);
const OFFICIAL_DOMAINS = new Set([...BRANDS.values()].flat());
// Brand names this long are also matched inside a longer word and one typo away.
const MIN_FUZZY_BRAND_LENGTH = 6;

// Characters attackers swap in for letters: paypa1, g00gle, rnicrosoft, vvetransfer.
const LOOKALIKE_SWAPS = [
  ["rn", "m"], ["vv", "w"], ["0", "o"], ["1", "l"], ["3", "e"], ["4", "a"],
  ["5", "s"], ["7", "t"], ["8", "b"], ["@", "a"], ["$", "s"],
];

function undoSwaps(word) {
  for (const [fake, real] of LOOKALIKE_SWAPS) {
    word = word.replaceAll(fake, real);
  }
  return word;
}

// True if a and b differ by one inserted, deleted, replaced, or swapped letter.
// Works on characters (code points), like Python.
function withinOneEdit(aText, bText) {
  const a = Array.from(aText);
  const b = Array.from(bText);
  if (aText === bText || Math.abs(a.length - b.length) > 1) {
    return false;
  }
  if (a.length === b.length) {
    const diffs = [];
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        diffs.push(i);
      }
    }
    if (diffs.length === 1) {
      return true;
    }
    const i = diffs[0];
    const j = diffs[diffs.length - 1];
    return diffs.length === 2 && j === i + 1 && a[i] === b[j] && a[j] === b[i];
  }
  const [short, long] = a.length < b.length ? [a, b] : [b, a];
  const shortText = short.join("");
  for (let i = 0; i < long.length; i++) {
    if ([...long.slice(0, i), ...long.slice(i + 1)].join("") === shortText) {
      return true;
    }
  }
  return false;
}

// The words of a host without its suffix: secure.paypal-login.co.uk ->
// {"secure", "paypal-login", "paypal", "login"}.
function hostWords(host) {
  const domain = registrableDomain(host);
  const dot = domain.indexOf(".");
  const suffix = dot >= 0 ? domain.slice(dot + 1) : "";
  const hostChars = Array.from(host);
  const name = suffix ? hostChars.slice(0, -(pyLen(suffix) + 1)).join("") : host;
  const labels = new Set(name.split("."));
  const words = new Set(labels);
  for (const label of labels) {
    for (const part of label.split("-")) {
      words.add(part);
    }
  }
  return words;
}

// If host imitates a brand, return that brand's real domain, else null.
function imitatedBrand(host) {
  if (!host || isIp(host) || OFFICIAL_DOMAINS.has(registrableDomain(host))) {
    return null;
  }
  const words = hostWords(host);
  for (const [brand, domains] of BRANDS) {
    for (const word of words) {
      const unswapped = undoSwaps(word);
      if (word === brand || unswapped === brand) {
        return domains[0];
      }
      if (
        pyLen(brand) >= MIN_FUZZY_BRAND_LENGTH &&
        (unswapped.includes(brand) || withinOneEdit(unswapped, brand))
      ) {
        return domains[0];
      }
    }
  }
  return null;
}

function lookalikeDomain(email) {
  const findings = [];
  const senderHost = afterLast(email.sender_email ?? "", "@").toLowerCase();
  const senderBrand = imitatedBrand(senderHost);
  if (senderBrand) {
    findings.push(`Sender domain '${quote(senderHost)}' imitates ${senderBrand}`);
  }
  for (const link of email.links ?? []) {
    // The href's host first, then domains written in the text.
    for (const host of unique([hostOf(link.href), ...domainsInText(link.text)])) {
      const brandDomain = imitatedBrand(host);
      if (brandDomain) {
        findings.push(`A link goes to '${quote(host)}', which imitates ${brandDomain}`);
        break;
      }
    }
  }
  return summarise("lookalike_domain", HIGH, findings);
}

// --- Rule 4: homoglyphs (look-alike Greek or Cyrillic letters) ----------------------

const WORD_RE = pyRegex(String.raw`[^\W\d_]+`, "g");
const LOOKALIKE_SCRIPTS = new Set(["GREEK", "CYRILLIC"]);
// A whole Greek/Cyrillic word only counts inside mostly-English text.
const MIN_LATIN_WORDS = 2;
const LATIN_WORDS_PER_FOREIGN_WORD = 2;

function homoglyphWords(text) {
  const words = Array.from(text.matchAll(WORD_RE), (match) => match[0]);
  const scripts = words.map((word) => new Set(Array.from(word, scriptOf)));
  const isOnlyLatin = (s) => s.size === 1 && s.has("LATIN");
  const isOnlyLookalike = (s) => [...s].every((name) => LOOKALIKE_SCRIPTS.has(name));
  const latinWords = scripts.filter(isOnlyLatin).length;
  const foreignWords = scripts.filter((s) => s.size > 0 && isOnlyLookalike(s)).length;
  const mostlyLatin =
    latinWords >= MIN_LATIN_WORDS && latinWords >= LATIN_WORDS_PER_FOREIGN_WORD * foreignWords;
  const found = [];
  words.forEach((word, i) => {
    const wordScripts = scripts[i];
    const lookalike = [...wordScripts].some((name) => LOOKALIKE_SCRIPTS.has(name));
    const mixed = lookalike && wordScripts.has("LATIN");
    const disguised = lookalike && isOnlyLookalike(wordScripts) && mostlyLatin;
    if (mixed || (disguised && pyLen(word) >= 2)) {
      found.push(word);
    }
  });
  return found;
}

function isInternationalHost(host) {
  return !isAscii(host) || host.split(".").some((part) => part.startsWith("xn--"));
}

function homoglyphs(email) {
  const findings = [];
  const texts = [email.sender_name ?? "", email.subject ?? "", email.body_text ?? ""];
  texts.push(...(email.links ?? []).map((link) => link.text));
  const words = texts.flatMap(homoglyphWords);
  if (words.length > 0) {
    findings.push(
      `The word '${quote(words[0])}' uses look-alike letters from another ` +
        "alphabet (Greek or Cyrillic) to imitate English"
    );
  }
  const senderHost = afterLast(email.sender_email ?? "", "@");
  const hosts = [senderHost, ...(email.links ?? []).map((link) => hostOf(link.href))];
  for (const host of hosts) {
    if (host && isInternationalHost(host)) {
      findings.push(
        `The domain '${quote(host)}' uses international characters that can ` +
          "look like normal letters"
      );
      break;
    }
  }
  return summarise("homoglyphs", HIGH, findings);
}

// --- Rule 5: sender display name doesn't match the address domain -------------------

const NAME_EMAIL_RE = pyRegex(String.raw`(?<![\w.+-])[\w.+-]+@([\w-]+(?:\.[\w-]+)+)`, "g");
// Multi-word brands are matched with spaces removed ("Bank of America").
const MIN_JOINED_BRAND_LENGTH = 8;

function brandsInName(name) {
  const lower = name.toLowerCase();
  const words = new Set(lower.match(/[a-z0-9]+/g) ?? []);
  const joined = lower.replace(/[^a-z0-9]/gu, "");
  return [...BRANDS.keys()].filter(
    (brand) =>
      words.has(brand) || (pyLen(brand) >= MIN_JOINED_BRAND_LENGTH && joined.includes(brand))
  );
}

function senderNameMismatch(email) {
  const name = email.sender_name ?? "";
  const senderHost = afterLast(email.sender_email ?? "", "@").toLowerCase();
  if (!name || !senderHost) {
    return [];
  }
  const real = registrableDomain(senderHost);

  // "service@paypal.com <x@evil.ru>" or "paypal.com Support <x@evil.ru>"
  const shown = [
    ...Array.from(name.matchAll(NAME_EMAIL_RE), (match) => match[1]),
    ...domainsInText(name),
  ];
  for (const domain of shown) {
    if (registrableDomain(domain.toLowerCase()) !== real) {
      return summarise("sender_name_mismatch", HIGH, [
        `The sender name shows '${quote(domain.toLowerCase())}' but the email ` +
          `comes from '${quote(senderHost)}'`,
      ]);
    }
  }

  // "PayPal Support <x@gmail.com>"
  for (const brand of brandsInName(name)) {
    if (!BRANDS.get(brand).includes(real)) {
      return summarise("sender_name_mismatch", MEDIUM, [
        `The sender name says '${quote(name)}' but the address is from ` +
          `'${quote(senderHost)}', not ${BRANDS.get(brand)[0]}`,
      ]);
    }
  }
  return [];
}

// --- Rule 6: urgency or threat phrases ----------------------------------------------

const ACCOUNT_WORDS = String.raw`(?:account|access|mailbox|e-?mail|service|card|profile|subscription)`;
const THREAT_WORDS =
  String.raw`(?:suspend\w*|lock(?:ed)?|disabl\w*|deactivat\w*|terminat\w*|limit(?:ed)?|` +
  String.raw`restrict\w*|block(?:ed)?|clos(?:ed|ure)|on hold|delet\w*)`;
const URGENCY_PATTERNS = [
  // "your account has been suspended", "mailbox will be deactivated"
  String.raw`\b${ACCOUNT_WORDS}\b[^.!?\n]{0,40}\b${THREAT_WORDS}`,
  // Deadlines: "within 24 hours", "in the next 48 hours"
  String.raw`\b(?:within|in the next)\s+\d+\s*(?:hours?|hrs?|days?|minutes?)\b`,
  String.raw`\b(?:expires?|expiring)\s+(?:today|soon|in\s+\d+)`,
  String.raw`\b(?:password|mailbox|account)\b[^.!?\n]{0,30}\bexpir\w*`,
  // Alarms
  String.raw`\burgent(?:ly)?\b`,
  String.raw`\b(?:immediate(?:ly)?|prompt)\s+(?:action|attention|response)\b`,
  String.raw`\baction\s+(?:is\s+)?required\b`,
  String.raw`\bact\s+(?:now|immediately|fast)\b`,
  String.raw`\b(?:final|last)\s+(?:notice|warning|reminder)\b`,
  String.raw`\bfailure\s+to\s+(?:comply|verify|update|confirm|respond)\b`,
  String.raw`\b(?:unusual|suspicious|unauthori[sz]ed)\s+(?:sign-?in\s+|login\s+)?` +
    String.raw`(?:activity|attempts?|access)\b`,
  String.raw`\bwill\s+be\s+(?:permanently\s+)?(?:deleted|lost|suspended|terminated|closed|` +
    String.raw`deactivated|disabled|blocked)\b`,
];
const URGENCY_RE = pyRegex(URGENCY_PATTERNS.map((p) => `(?:${p})`).join("|"), "ig");
const MAX_PHRASES_SHOWN = 2;

// Distinct matches in the subject and body, in order, lowercased. Matched one line
// at a time, so a phrase can't run from one line into the next.
function foundPhrases(regex, email) {
  const lines = [email.subject ?? "", ...pySplitlines(email.body_text ?? "")];
  const phrases = [];
  for (const line of lines) {
    for (const match of line.matchAll(regex)) {
      phrases.push(pySplit(match[0].toLowerCase()).join(" "));
    }
  }
  return unique(phrases);
}

function urgency(email) {
  const phrases = foundPhrases(URGENCY_RE, email);
  if (phrases.length === 0) {
    return [];
  }
  const shown = phrases
    .slice(0, MAX_PHRASES_SHOWN)
    .map((phrase) => `'${quote(phrase)}'`)
    .join(", ");
  return summarise("urgency", MEDIUM, [`Uses pressure or threats to rush you: ${shown}`]);
}

// --- Rule 7: requests for passwords, card details or gift cards ---------------------

const ASK_VERBS =
  String.raw`(?:enter|confirm|verify|update|provide|re-?enter|validate|submit|send|type|` +
  String.raw`input|fill in|log ?in with)`;
const SENSITIVE_PATTERNS = [
  [
    "your password",
    [
      String.raw`\b${ASK_VERBS}\b[^.!?\n]{0,30}\b(?:password|passcode|pin|login details|` +
        String.raw`credentials)\b`,
    ],
  ],
  [
    "card or bank details",
    [
      String.raw`\b(?:credit|debit)\s+card\s+(?:number|details|information|info)\b`,
      String.raw`\bcard\s+(?:number|details|verification)\b`,
      String.raw`\b(?:cvv2?|cvc|card security code)\b`,
      String.raw`\bbank\s+(?:account\s+)?(?:details|login|credentials|information)\b`,
      String.raw`\bbilling\s+(?:information|details)\b`,
      String.raw`\b(?:social security number|ssn)\b`,
    ],
  ],
  [
    "gift cards",
    [String.raw`\bgift\s*cards?\b`, String.raw`\b(?:itunes|google play|steam|apple)\s+cards?\b`],
  ],
];
const SENSITIVE_RES = SENSITIVE_PATTERNS.map(([what, patterns]) => [
  what,
  pyRegex(patterns.map((p) => `(?:${p})`).join("|"), "ig"),
]);

function sensitiveRequest(email) {
  const asked = SENSITIVE_RES.filter(([, regex]) => foundPhrases(regex, email).length > 0).map(
    ([what]) => what
  );
  if (asked.length === 0) {
    return [];
  }
  return summarise("sensitive_request", HIGH, [
    `Asks for ${asked.join(" and ")}. Real companies never ask for these by email`,
  ]);
}

// --- Rule 8: risky attachment mentions ----------------------------------------------

// File type -> [severity, why it's risky]. Insertion order matters: it's the order
// of the alternatives in FILE_NAME_RE, as in Python.
const RISKY_FILE_TYPES = new Map();
function addRiskyTypes(types, severity, why) {
  for (const type of types.split(" ")) {
    RISKY_FILE_TYPES.set(type, [severity, why]);
  }
}
addRiskyTypes(
  "exe scr pif bat cmd js jse vbs vbe wsf jar msi ps1 hta lnk",
  HIGH,
  "it's a program that can run on your computer"
);
addRiskyTypes(
  "docm xlsm pptm dotm xlam",
  HIGH,
  "it's an Office file with macros, which can run code"
);
addRiskyTypes("zip rar 7z iso img cab", MEDIUM, "archives and disk images can hide malware");
addRiskyTypes("html htm shtml", MEDIUM, "HTML attachments are often fake login pages");

// Web pages end in .html, so .html only counts in the text, not in link addresses.
const NOT_RISKY_IN_LINKS = new Set(["html", "htm", "shtml"]);
const FILE_NAME_SOURCE =
  String.raw`(?<![\w\-()\[\]])[\w\-()\[\]]+\.(` +
  [...RISKY_FILE_TYPES.keys()].join("|") +
  String.raw`)\b`;
const FILE_NAME_RE = pyRegex(FILE_NAME_SOURCE, "ig");
// FILE_NAME_RE.fullmatch(): the whole text must be one file name.
const WHOLE_FILE_NAME_RE = new RegExp(`^(?:${pyRegex(FILE_NAME_SOURCE, "i").source})$`, "iu");
// Words containing "/" are URL paths, not attachments.
const PATH_WORD_RE = pyRegex(String.raw`(?<!\S)\S*/\S*`, "g");

// "Invoice.pdf.exe": a harmless-looking extension in front of a risky one.
const DECOY_FILE_TYPES = new Set(["pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "jpeg", "png"]);

// The risky extension of a file name ("Scan.ZIP" -> "zip"), or null.
function riskyType(fileName) {
  const ext = fileName.includes(".") ? afterLast(fileName, ".").toLowerCase() : "";
  return RISKY_FILE_TYPES.has(ext) ? ext : null;
}

// The decoy extension ("Invoice.pdf.exe" -> "pdf"), or null if there isn't one.
function decoyType(fileName) {
  const parts = pyRsplit(fileName.toLowerCase(), ".", 2);
  return parts.length === 3 && DECOY_FILE_TYPES.has(parts[1]) ? parts[1] : null;
}

// The path of a link, or "" if it has none or can't be parsed (features._url_path).
function urlPath(href) {
  if (!href.includes("://")) {
    return "";
  }
  try {
    return urlsplit(href).path;
  } catch (error) {
    if (error instanceof UrlError) {
      return "";
    }
    throw error;
  }
}

function riskyAttachment(email) {
  const found = []; // [file name, extension, is a real attachment]
  for (const name of email.attachments ?? []) {
    const ext = riskyType(name);
    if (ext) {
      found.push([name, ext, true]);
    }
  }
  const texts = [email.subject ?? "", email.body_text ?? ""];
  texts.push(...(email.links ?? []).map((link) => link.text));
  for (const text of texts) {
    for (const match of text.replace(PATH_WORD_RE, " ").matchAll(FILE_NAME_RE)) {
      found.push([match[0], match[1].toLowerCase(), false]);
    }
  }
  for (const link of email.links ?? []) {
    const name = afterLast(urlPath(link.href), "/");
    const ext = WHOLE_FILE_NAME_RE.test(name) ? riskyType(name) : null;
    if (ext && !NOT_RISKY_IN_LINKS.has(ext)) {
      found.push([name, ext, false]);
    }
  }
  if (found.length === 0) {
    return [];
  }

  // Report the most dangerous file: disguised, then high severity, then a real
  // attachment over a mention. Like Python's max(), the first of equals wins.
  const danger = ([name, ext, isAttachment]) => [
    decoyType(name) !== null,
    RISKY_FILE_TYPES.get(ext)[0] === HIGH,
    isAttachment,
  ];
  let worst = found[0];
  for (const item of found.slice(1)) {
    if (compareFlags(danger(item), danger(worst)) > 0) {
      worst = item;
    }
  }
  const [name, ext, isAttachment] = worst;
  let [severity, why] = RISKY_FILE_TYPES.get(ext);
  const where = isAttachment ? "Has the attachment" : "Mentions the file";
  const decoy = decoyType(name);
  let message;
  if (decoy) {
    severity = HIGH;
    message =
      `${where} '${quote(name)}', which pretends to be a .${decoy} but is really ` +
      `a .${ext}: ${why}`;
  } else {
    message = `${where} '${quote(name)}', which is risky: ${why}`;
  }
  return summarise("risky_attachment", severity, [message]);
}

// Compares two lists of booleans the way Python compares tuples (false < true).
function compareFlags(a, b) {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return a[i] ? 1 : -1;
    }
  }
  return 0;
}

// --- All rules ----------------------------------------------------------------------

const RULES = [
  linkTextMismatch,
  ipOrShortenedLinks,
  lookalikeDomain,
  homoglyphs,
  senderNameMismatch,
  urgency,
  sensitiveRequest,
  riskyAttachment,
];

export const REASON_IDS = [
  "link_text_mismatch",
  "ip_link",
  "url_shortener",
  "lookalike_domain",
  "homoglyphs",
  "sender_name_mismatch",
  "urgency",
  "sensitive_request",
  "risky_attachment",
];

// Run every rule on one cleaned email and return all the reasons that fired.
export function findReasons(email) {
  return RULES.flatMap((rule) => rule(email));
}

const SEVERITY_VALUE = { [LOW]: 1 / 3, [MEDIUM]: 2 / 3, [HIGH]: 1.0 };

// Rule results as model input: one number per REASON_IDS entry, 0 if the rule
// didn't fire, else its severity (low 1/3, medium 2/3, high 1).
export function ruleVector(reasons) {
  const values = new Map(REASON_IDS.map((id) => [id, 0]));
  for (const reason of reasons) {
    values.set(reason.id, Math.max(values.get(reason.id), SEVERITY_VALUE[reason.severity]));
  }
  return REASON_IDS.map((id) => values.get(id));
}

// Exported for tests that compare single helpers with Python.
export const _internal = { quote, domainsInText, imitatedBrand, homoglyphWords };
