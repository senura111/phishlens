"""Rule-based phishing signals.

Each rule looks at one email and, if it fires, returns a reason:
{"id": ..., "severity": "low" | "medium" | "high", "message": ...}.
The messages are shown to the user in the Gmail banner, so they must be plain and specific.

Rules expect an email already cleaned by preprocess.prepare_email(): sender_name,
sender_email, subject, body_text, links (each {"text": ..., "href": ...}), and the
optional attachments (a list of file names).
Everything in an email is attacker-controlled, so messages quote it only in short,
truncated pieces, and the extension must display them with textContent.

Run `python -m model.src.features` from the repo root to see how often each rule fires
on the phishing and safe emails in the dataset.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit

HIGH, MEDIUM, LOW = "high", "medium", "low"
MAX_QUOTE = 60  # longest piece of email text quoted in a message


def make_reason(rule_id: str, severity: str, message: str) -> dict:
    return {"id": rule_id, "severity": severity, "message": message}


def quote(value: str) -> str:
    """Shorten attacker-controlled text before putting it in a message."""
    value = " ".join(value.split())
    return value if len(value) <= MAX_QUOTE else value[: MAX_QUOTE - 1] + "…"


def _summarise(rule_id: str, severity: str, findings: list[str]) -> list[dict]:
    """One reason per rule: the first finding, plus how many more there were."""
    if not findings:
        return []
    message = findings[0]
    if len(findings) > 1:
        message += f" (and {len(findings) - 1} more)"
    return [make_reason(rule_id, severity, message)]


# --- Domain helpers ------------------------------------------------------------------

# Suffixes where a registrable domain has three parts, e.g. bbc.co.uk. (A full list is
# the Public Suffix List; these cover the common cases without a dependency.)
_TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "ne.jp", "co.za", "com.br", "com.mx", "com.cn", "com.tr", "co.in",
    "co.kr", "com.sg", "com.ar", "co.id", "com.my", "com.ph", "com.pk", "com.ng",
    "com.sa", "com.lk", "com.hk", "com.tw",
}  # fmt: skip


def host_of(url: str) -> str:
    """The lowercase host of a URL, or '' if it can't be parsed."""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:  # e.g. a malformed IPv6 address
        return ""
    return host.rstrip(".").lower()


def is_ip(host: str) -> bool:
    """True for 185.22.10.4, ::1, and all-digit hosts (browsers read 3232235777 as an IP)."""
    if host.isdigit():
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    """The part of a host you have to buy: login.paypal.com -> paypal.com."""
    if is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# Domains written in visible text ("paypal.com/login"). Only common TLDs count, so
# file names such as invoice.pdf are not mistaken for domains. The lookbehind skips
# emails (x@paypal.com) and anything after a "/", which is a path such as
# /article.pl?sid=1 (a Perl script, not a Polish domain).
_COMMON_TLDS = (
    "com net org edu gov mil info biz io co me us uk ca au de fr it es nl be ch at se "
    "no dk fi pl ru cn jp kr in br mx ar za nz ie pt gr tr il sg hk tw my ph id vn th "
    "lk ng ke app dev xyz top online site shop store club live ly"
).split()
_TEXT_DOMAIN_RE = re.compile(
    r"(?<![\w@./-])(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:"
    + "|".join(_COMMON_TLDS)
    + r"))(?![\w-])",
    re.IGNORECASE,
)
_URL_START_RE = re.compile(r"https?://", re.IGNORECASE)


def domains_in_text(text: str) -> list[str]:
    return [m.lower() for m in _TEXT_DOMAIN_RE.findall(text)]


def _redirect_targets(href: str) -> set[str]:
    """Registrable domains of URLs nested inside a link, e.g. the q= of a redirect:
    google.com/url?q=https://paypal.com -> {"paypal.com"}."""
    decoded = unquote(href)
    starts = [m.start() for m in _URL_START_RE.finditer(decoded)][1:]  # [0] = the link
    hosts = [host_of(decoded[start:]) for start in starts]
    return {registrable_domain(host) for host in hosts if host}


# --- Rule 1: link text shows one domain, href goes to another ------------------------

# Legitimate newsletters route links through email-service click trackers, so a link
# showing "brand.com" really goes to the tracker first. Not counted as a mismatch.
CLICK_TRACKERS = {
    "sendgrid.net", "list-manage.com", "mcsv.net", "mailchimp.com", "rs6.net",
    "exct.net", "hubspotlinks.com", "hs-sites.com", "mandrillapp.com", "mailgun.org",
    "sparkpostmail.com", "awstrack.me", "constantcontact.com", "cmail19.com",
    "cmail20.com", "createsend.com", "klclick.com", "mailjet.com",
    "online.com",  # CNET's 2002 tracker (clickthru.online.com), common in the ham
}  # fmt: skip


def link_text_mismatch(email: dict) -> list[dict]:
    """The visible text of a link names a domain, but the link really goes elsewhere."""
    findings = []
    for link in email.get("links", []):
        real_host = host_of(link["href"])
        if not real_host:
            continue
        real = registrable_domain(real_host)
        if real in CLICK_TRACKERS:
            continue
        # The domain as written in the text ("www.ecu.edu.lk") goes in the message, so
        # the user sees what the link showed; the comparison uses its registrable part.
        for written in _TEXT_DOMAIN_RE.findall(link["text"]):
            shown = registrable_domain(written.lower())
            # A redirect that ends up at the shown domain is not a mismatch.
            if shown != real and shown not in _redirect_targets(link["href"]):
                findings.append(
                    f"A link shows '{quote(written)}' but goes to '{quote(real_host)}'"
                )
                break
    return _summarise("link_text_mismatch", HIGH, findings)


# --- Rule 2: raw-IP links and URL shorteners -----------------------------------------

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "bit.do", "s.id", "t.ly", "v.gd",
    "short.io", "tiny.one", "shorte.st", "adf.ly", "qrco.de", "lnkd.in",
}  # fmt: skip


def ip_or_shortened_links(email: dict) -> list[dict]:
    """Links to a raw IP address (real companies use domain names) or through a URL
    shortener (which hides where the link really goes)."""
    ip_hosts, shortened = [], []
    for link in email.get("links", []):
        host = host_of(link["href"])
        if is_ip(host):
            ip_hosts.append(f"A link goes to a raw IP address ({quote(host)})")
        elif host.removeprefix("www.") in URL_SHORTENERS:
            shortened.append(
                f"A link uses the URL shortener {quote(host)}, which hides where it goes"
            )
    return _summarise("ip_link", HIGH, ip_hosts) + _summarise(
        "url_shortener", MEDIUM, shortened
    )


# --- Rule 3: lookalike or misspelled brand domains -----------------------------------

# Brand name -> the domains it really owns (the first one is shown in messages).
# Several names can map to one company (outlook, office365 -> Microsoft).
_MICROSOFT = (
    "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com",
    "microsoftonline.com", "sharepoint.com", "onedrive.com", "hotmail.com",
)  # fmt: skip
_GOOGLE = (
    "google.com", "gmail.com", "googlemail.com", "youtube.com", "googleapis.com",
    "googleusercontent.com", "googlegroups.com", "gstatic.com", "goo.gl",
)  # fmt: skip
BRANDS = {
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com"),
    "apple": ("apple.com", "icloud.com", "me.com"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": _MICROSOFT,
    "outlook": _MICROSOFT,
    "office365": _MICROSOFT,
    "onedrive": _MICROSOFT,
    "sharepoint": _MICROSOFT,
    "google": _GOOGLE,
    "gmail": _GOOGLE,
    "amazon": ("amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.de"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com", "facebookmail.com"),
    "instagram": ("instagram.com",),
    "linkedin": ("linkedin.com", "licdn.com"),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "usps": ("usps.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com", "wf.com"),
    "bankofamerica": ("bankofamerica.com", "bofa.com"),
    "usaa": ("usaa.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "dropbox": ("dropbox.com", "dropboxmail.com"),
    "wetransfer": ("wetransfer.com", "we.tl"),
    "adobe": ("adobe.com",),
    "ebay": ("ebay.com",),
    "coinbase": ("coinbase.com",),
}
_OFFICIAL_DOMAINS = {domain for domains in BRANDS.values() for domain in domains}
# Brand names this long are also matched inside a longer word ("securepaypal") and
# one typo away ("paypai"). Shorter names (ups, dhl, apple, chase) only match a whole
# word, so "purchase" doesn't look like "chase" and "apply" doesn't look like "apple".
MIN_FUZZY_BRAND_LENGTH = 6

# Characters attackers swap in for letters: paypa1, g00gle, rnicrosoft, vvetransfer.
_LOOKALIKE_SWAPS = [
    ("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"),
    ("5", "s"), ("7", "t"), ("8", "b"), ("@", "a"), ("$", "s"),
]  # fmt: skip


def _undo_swaps(word: str) -> str:
    for fake, real in _LOOKALIKE_SWAPS:
        word = word.replace(fake, real)
    return word


def _within_one_edit(a: str, b: str) -> bool:
    """True if a and b differ by one inserted, deleted, replaced, or swapped letter."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        i, j = diffs[0], diffs[-1]
        return len(diffs) == 2 and j == i + 1 and a[i] == b[j] and a[j] == b[i]
    short, long_ = sorted((a, b), key=len)
    return any(long_[:i] + long_[i + 1 :] == short for i in range(len(long_)))


def _host_words(host: str) -> set[str]:
    """The words of a host without its suffix: secure.paypal-login.co.uk ->
    {"secure", "paypal-login", "paypal", "login"}."""
    domain = registrable_domain(host)
    suffix = domain.split(".", 1)[1] if "." in domain else ""
    name = host[: -len(suffix) - 1] if suffix else host
    labels = set(name.split("."))
    return labels | {part for label in labels for part in label.split("-")}


def imitated_brand(host: str) -> str | None:
    """If host imitates a brand, return that brand's real domain, else None."""
    if not host or is_ip(host) or registrable_domain(host) in _OFFICIAL_DOMAINS:
        return None
    words = _host_words(host)
    for brand, domains in BRANDS.items():
        for word in words:
            unswapped = _undo_swaps(word)
            if word == brand or unswapped == brand:
                return domains[0]
            if len(brand) >= MIN_FUZZY_BRAND_LENGTH and (
                brand in unswapped or _within_one_edit(unswapped, brand)
            ):
                return domains[0]
    return None


def lookalike_domain(email: dict) -> list[dict]:
    """The sender or a link uses a domain that imitates a well-known brand."""
    findings = []
    sender_host = email.get("sender_email", "").rpartition("@")[2].lower()
    if brand_domain := imitated_brand(sender_host):
        findings.append(f"Sender domain '{quote(sender_host)}' imitates {brand_domain}")
    for link in email.get("links", []):
        for host in {host_of(link["href"]), *domains_in_text(link["text"])}:
            if brand_domain := imitated_brand(host):
                findings.append(
                    f"A link goes to '{quote(host)}', which imitates {brand_domain}"
                )
                break
    return _summarise("lookalike_domain", HIGH, findings)


# --- Rule 4: homoglyphs (look-alike Greek or Cyrillic letters) -----------------------

# Many Greek and Cyrillic letters look exactly like Latin ones, so "PayPal" written with
# a Cyrillic "a" (U+0430) looks normal but slips past filters. Scripts are read from each
# character's Unicode name ("CYRILLIC SMALL LETTER A"), never from how it looks.
_WORD_RE = re.compile(r"[^\W\d_]+")
_LOOKALIKE_SCRIPTS = {"GREEK", "CYRILLIC"}
# A whole Greek/Cyrillic word only counts inside mostly-English text: at least this
# many Latin words, and this many times more Latin words than Greek/Cyrillic ones.
MIN_LATIN_WORDS = 2
LATIN_WORDS_PER_FOREIGN_WORD = 2


def _script(char: str) -> str:
    if char.isascii():
        return "LATIN"
    return unicodedata.name(char, "OTHER").split(" ")[0]


def _homoglyph_words(text: str) -> list[str]:
    words = _WORD_RE.findall(text)
    scripts = [{_script(c) for c in word} for word in words]
    latin_words = sum(s == {"LATIN"} for s in scripts)
    foreign_words = sum(bool(s) and s <= _LOOKALIKE_SCRIPTS for s in scripts)
    mostly_latin = (
        latin_words >= MIN_LATIN_WORDS
        and latin_words >= LATIN_WORDS_PER_FOREIGN_WORD * foreign_words
    )
    found = []
    for word, word_scripts in zip(words, scripts):
        lookalike = word_scripts & _LOOKALIKE_SCRIPTS
        mixed = lookalike and "LATIN" in word_scripts
        disguised = lookalike and word_scripts <= _LOOKALIKE_SCRIPTS and mostly_latin
        if mixed or (disguised and len(word) >= 2):
            found.append(word)
    return found


def _is_international_host(host: str) -> bool:
    return not host.isascii() or any(p.startswith("xn--") for p in host.split("."))


def homoglyphs(email: dict) -> list[dict]:
    """Greek or Cyrillic look-alike letters hidden in English text or in a domain."""
    findings = []
    texts = [email.get(k, "") for k in ("sender_name", "subject", "body_text")]
    texts += [link["text"] for link in email.get("links", [])]
    words = [word for text in texts for word in _homoglyph_words(text)]
    if words:
        findings.append(
            f"The word '{quote(words[0])}' uses look-alike letters from another "
            "alphabet (Greek or Cyrillic) to imitate English"
        )

    sender_host = email.get("sender_email", "").rpartition("@")[2]
    hosts = [sender_host] + [host_of(link["href"]) for link in email.get("links", [])]
    for host in hosts:
        if host and _is_international_host(host):
            findings.append(
                f"The domain '{quote(host)}' uses international characters that can "
                "look like normal letters"
            )
            break
    return _summarise("homoglyphs", HIGH, findings)


# --- Rule 5: sender display name doesn't match the address domain --------------------

# The lookbehind starts a match only at the beginning of a run of address characters,
# so a long run without "@" isn't tried again from every position (see _FILE_NAME_RE).
_NAME_EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
# Multi-word brands are matched with spaces removed ("Bank of America", "Office 365").
MIN_JOINED_BRAND_LENGTH = 8


def _brands_in_name(name: str) -> list[str]:
    words = set(re.findall(r"[a-z0-9]+", name.lower()))
    joined = re.sub(r"[^a-z0-9]", "", name.lower())
    return [
        brand
        for brand in BRANDS
        if brand in words or (len(brand) >= MIN_JOINED_BRAND_LENGTH and brand in joined)
    ]


def sender_name_mismatch(email: dict) -> list[dict]:
    """The display name claims a different domain or brand than the real address."""
    name = email.get("sender_name", "")
    sender_host = email.get("sender_email", "").rpartition("@")[2].lower()
    if not name or not sender_host:
        return []
    real = registrable_domain(sender_host)

    # "service@paypal.com <x@evil.ru>" or "paypal.com Support <x@evil.ru>"
    shown = [*_NAME_EMAIL_RE.findall(name), *domains_in_text(name)]
    for domain in shown:
        if registrable_domain(domain.lower()) != real:
            return _summarise(
                "sender_name_mismatch",
                HIGH,
                [
                    f"The sender name shows '{quote(domain.lower())}' but the email "
                    f"comes from '{quote(sender_host)}'"
                ],
            )

    # "PayPal Support <x@gmail.com>"
    for brand in _brands_in_name(name):
        if real not in BRANDS[brand]:
            return _summarise(
                "sender_name_mismatch",
                MEDIUM,
                [
                    f"The sender name says '{quote(name)}' but the address is from "
                    f"'{quote(sender_host)}', not {BRANDS[brand][0]}"
                ],
            )
    return []


# --- Rule 6: urgency or threat phrases -----------------------------------------------

_ACCOUNT_WORDS = r"(?:account|access|mailbox|e-?mail|service|card|profile|subscription)"
_THREAT_WORDS = (
    r"(?:suspend\w*|lock(?:ed)?|disabl\w*|deactivat\w*|terminat\w*|limit(?:ed)?|"
    r"restrict\w*|block(?:ed)?|clos(?:ed|ure)|on hold|delet\w*)"
)
URGENCY_PATTERNS = [
    # "your account has been suspended", "mailbox will be deactivated"
    rf"\b{_ACCOUNT_WORDS}\b[^.!?\n]{{0,40}}\b{_THREAT_WORDS}",
    # Deadlines: "within 24 hours", "in the next 48 hours"
    r"\b(?:within|in the next)\s+\d+\s*(?:hours?|hrs?|days?|minutes?)\b",
    r"\b(?:expires?|expiring)\s+(?:today|soon|in\s+\d+)",
    r"\b(?:password|mailbox|account)\b[^.!?\n]{0,30}\bexpir\w*",
    # Alarms
    r"\burgent(?:ly)?\b",
    r"\b(?:immediate(?:ly)?|prompt)\s+(?:action|attention|response)\b",
    r"\baction\s+(?:is\s+)?required\b",
    r"\bact\s+(?:now|immediately|fast)\b",
    r"\b(?:final|last)\s+(?:notice|warning|reminder)\b",
    r"\bfailure\s+to\s+(?:comply|verify|update|confirm|respond)\b",
    r"\b(?:unusual|suspicious|unauthori[sz]ed)\s+(?:sign-?in\s+|login\s+)?"
    r"(?:activity|attempts?|access)\b",
    r"\bwill\s+be\s+(?:permanently\s+)?(?:deleted|lost|suspended|terminated|closed|"
    r"deactivated|disabled|blocked)\b",
]
_URGENCY_RE = re.compile("|".join(f"(?:{p})" for p in URGENCY_PATTERNS), re.IGNORECASE)
MAX_PHRASES_SHOWN = 2


def _found_phrases(regex: re.Pattern, email: dict) -> list[str]:
    """Distinct matches in the subject and body, in order, lowercased.

    Matched one line at a time, so a phrase can't run from one line into the next
    (e.g. a "Reset password" button followed by "This link expires in 24 hours").
    """
    lines = [email.get("subject", ""), *email.get("body_text", "").splitlines()]
    phrases = [
        " ".join(m.group().lower().split())
        for line in lines
        for m in regex.finditer(line)
    ]
    return list(dict.fromkeys(phrases))


def urgency(email: dict) -> list[dict]:
    """Pressure tactics: deadlines, threats to close the account, alarm words."""
    phrases = _found_phrases(_URGENCY_RE, email)
    if not phrases:
        return []
    shown = ", ".join(f"'{quote(p)}'" for p in phrases[:MAX_PHRASES_SHOWN])
    return _summarise(
        "urgency", MEDIUM, [f"Uses pressure or threats to rush you: {shown}"]
    )


# --- Rule 7: requests for passwords, card details or gift cards ----------------------

# "Reset" and "change your password" are left out on purpose: real password-reset
# emails use them. Phishing asks you to *give* the password.
_ASK_VERBS = (
    r"(?:enter|confirm|verify|update|provide|re-?enter|validate|submit|send|type|"
    r"input|fill in|log ?in with)"
)
SENSITIVE_PATTERNS = {
    "your password": [
        rf"\b{_ASK_VERBS}\b[^.!?\n]{{0,30}}\b(?:password|passcode|pin|login details|"
        r"credentials)\b",
    ],
    "card or bank details": [
        r"\b(?:credit|debit)\s+card\s+(?:number|details|information|info)\b",
        r"\bcard\s+(?:number|details|verification)\b",
        r"\b(?:cvv2?|cvc|card security code)\b",
        r"\bbank\s+(?:account\s+)?(?:details|login|credentials|information)\b",
        r"\bbilling\s+(?:information|details)\b",
        r"\b(?:social security number|ssn)\b",
    ],
    "gift cards": [
        r"\bgift\s*cards?\b",
        r"\b(?:itunes|google play|steam|apple)\s+cards?\b",
    ],
}
_SENSITIVE_RES = {
    what: re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)
    for what, patterns in SENSITIVE_PATTERNS.items()
}


def sensitive_request(email: dict) -> list[dict]:
    """Asks for a password, card or bank details, or gift cards."""
    asked = [
        what for what, regex in _SENSITIVE_RES.items() if _found_phrases(regex, email)
    ]
    if not asked:
        return []
    return _summarise(
        "sensitive_request",
        HIGH,
        [
            f"Asks for {' and '.join(asked)}. Real companies never ask for these by email"
        ],
    )


# --- Rule 8: risky attachment mentions -----------------------------------------------

# File type -> (severity, why it's risky).
RISKY_FILE_TYPES = {
    **dict.fromkeys(
        "exe scr pif bat cmd js jse vbs vbe wsf jar msi ps1 hta lnk".split(),
        (HIGH, "it's a program that can run on your computer"),
    ),
    **dict.fromkeys(
        "docm xlsm pptm dotm xlam".split(),
        (HIGH, "it's an Office file with macros, which can run code"),
    ),
    **dict.fromkeys(
        "zip rar 7z iso img cab".split(),
        (MEDIUM, "archives and disk images can hide malware"),
    ),
    **dict.fromkeys(
        "html htm shtml".split(),
        (MEDIUM, "HTML attachments are often fake login pages"),
    ),
}
# Web pages end in .html, so .html only counts in the text, not in link addresses.
_NOT_RISKY_IN_LINKS = {"html", "htm", "shtml"}
# Both regexes below start a match only at the beginning of a name or word (the
# lookbehind). Without it, a long run of letters with no dot or "/" was tried again
# from every position, each attempt scanning to the end of the run: 100 KB of
# "xxx..." took 48 seconds. The matches found are the same either way.
_FILE_NAME_RE = re.compile(
    r"(?<![\w\-()\[\]])[\w\-()\[\]]+\.(" + "|".join(RISKY_FILE_TYPES) + r")\b",
    re.IGNORECASE,
)
# Words containing "/" are URL paths (example.com/story/0,1,00.html): web pages,
# not attachments. They're removed before looking for file names.
_PATH_WORD_RE = re.compile(r"(?<!\S)\S*/\S*")


# "Invoice.pdf.exe": a harmless-looking extension in front of a risky one. Windows
# hides known extensions by default, so the user only sees "Invoice.pdf".
_DECOY_FILE_TYPES = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "jpeg", "png"}


def _risky_type(file_name: str) -> str | None:
    """The risky extension of a file name ("Scan.ZIP" -> "zip"), or None."""
    ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    return ext if ext in RISKY_FILE_TYPES else None


def _decoy_type(file_name: str) -> str | None:
    """The decoy extension ("Invoice.pdf.exe" -> "pdf"), or None if there isn't one."""
    parts = file_name.lower().rsplit(".", 2)
    return parts[1] if len(parts) == 3 and parts[1] in _DECOY_FILE_TYPES else None


def risky_attachment(email: dict) -> list[dict]:
    """Has an attachment, mentions a file, or links a download of a type that is often
    used to deliver malware. Real attachments (from the optional "attachments" field)
    count more than names mentioned in the text."""
    found = []  # (file name, extension, is a real attachment)
    for name in email.get("attachments") or []:
        if ext := _risky_type(name):
            found.append((name, ext, True))

    texts = [email.get("subject", ""), email.get("body_text", "")]
    texts += [link["text"] for link in email.get("links", [])]
    for text in texts:
        for m in _FILE_NAME_RE.finditer(_PATH_WORD_RE.sub(" ", text)):
            found.append((m.group(), m.group(1).lower(), False))
    for link in email.get("links", []):
        path = urlsplit(link["href"]).path if "://" in link["href"] else ""
        name = path.rsplit("/", 1)[-1]
        ext = _risky_type(name) if _FILE_NAME_RE.fullmatch(name) else None
        if ext and ext not in _NOT_RISKY_IN_LINKS:
            found.append((name, ext, False))
    if not found:
        return []

    # Report the most dangerous file: disguised, then high severity, then a real
    # attachment over a mention.
    def danger(item):
        name, ext, is_attachment = item
        return (
            bool(_decoy_type(name)),
            RISKY_FILE_TYPES[ext][0] == HIGH,
            is_attachment,
        )

    name, ext, is_attachment = max(found, key=danger)
    severity, why = RISKY_FILE_TYPES[ext]
    where = "Has the attachment" if is_attachment else "Mentions the file"
    if decoy := _decoy_type(name):
        severity = HIGH
        message = (
            f"{where} '{quote(name)}', which pretends to be a .{decoy} but is really "
            f"a .{ext}: {why}"
        )
    else:
        message = f"{where} '{quote(name)}', which is risky: {why}"
    return _summarise("risky_attachment", severity, [message])


# --- All rules -----------------------------------------------------------------------

RULES = [
    link_text_mismatch,
    ip_or_shortened_links,
    lookalike_domain,
    homoglyphs,
    sender_name_mismatch,
    urgency,
    sensitive_request,
    risky_attachment,
]


REASON_IDS = [
    "link_text_mismatch",
    "ip_link",
    "url_shortener",
    "lookalike_domain",
    "homoglyphs",
    "sender_name_mismatch",
    "urgency",
    "sensitive_request",
    "risky_attachment",
]


def find_reasons(email: dict) -> list[dict]:
    """Run every rule on one email and return all the reasons that fired."""
    return [reason for rule in RULES for reason in rule(email)]


SEVERITY_VALUE = {LOW: 1 / 3, MEDIUM: 2 / 3, HIGH: 1.0}


def rule_vector(reasons: list[dict]) -> list[float]:
    """Rule results as model input: one number per REASON_IDS entry, 0 if the rule
    didn't fire, else its severity (low 1/3, medium 2/3, high 1). Only rule results
    go in: nothing like "has attachments", which is normal for legitimate email."""
    values = dict.fromkeys(REASON_IDS, 0.0)
    for reason in reasons:
        value = SEVERITY_VALUE[reason["severity"]]
        values[reason["id"]] = max(values[reason["id"]], value)
    return [values[rid] for rid in REASON_IDS]


# --- Measuring the rules on the dataset ----------------------------------------------

# A rule that fires on more than this share of safe emails would cause false positives.
MAX_SAFE_FIRE_RATE = 0.05


def fire_rates(emails: list[dict], labels: list[int]) -> dict[str, tuple[float, float]]:
    """For each reason id (plus "any rule"): (share of phishing, share of safe) it fires on."""
    counts = {rid: [0, 0] for rid in [*REASON_IDS, "any rule"]}
    totals = [0, 0]  # [phishing, safe]
    for email, label in zip(emails, labels):
        side = 0 if label == 1 else 1
        totals[side] += 1
        fired = {reason["id"] for reason in find_reasons(email)}
        for rid in fired | ({"any rule"} if fired else set()):
            counts[rid][side] += 1
    return {
        rid: (phish / max(totals[0], 1), safe / max(totals[1], 1))
        for rid, (phish, safe) in counts.items()
    }


def main() -> None:
    from model.src.preprocess import load_dataset

    df, _ = load_dataset()
    rates = fire_rates(df.to_dict("records"), df["label"].tolist())
    print(f"{'rule':22} {'phishing':>9} {'safe':>7}")
    for rid, (phish, safe) in rates.items():
        flag = "  <-- over 5% of safe emails" if safe > MAX_SAFE_FIRE_RATE else ""
        print(f"{rid:22} {phish:9.1%} {safe:7.1%}{flag}")


if __name__ == "__main__":
    main()
