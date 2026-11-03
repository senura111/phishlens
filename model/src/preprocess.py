"""Turn raw emails (.eml / mbox messages or plain text) into the fields the extension can see.

Output fields: sender_name, sender_email, subject, body_text, and links
(each link as {"text": ..., "href": ...}). Raw headers such as SPF/DKIM or Received
are deliberately dropped, because the extension can't read them from Gmail.

There are two layers of cleaning:

- prepare_email() is used for training AND at prediction time. It strips dates, years
  and URLs from the text so the model can't tell old emails from new ones.
- remove_corpus_artifacts() is used for training only. It removes things that exist only
  in these datasets (anonymised names, 2002-era mailing-list footers) and would let the
  model learn "which dataset is this from?" instead of "is this phishing?".

Run `python -m model.src.preprocess` from the repo root to print a dataset summary.
"""

from __future__ import annotations

import hashlib
import mailbox
import re
import unicodedata
import warnings
from collections import Counter
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

import pandas as pd
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

RAW_DIR = Path(__file__).resolve().parents[1] / "data" / "raw"
COLUMNS = [
    "sender_name",
    "sender_email",
    "subject",
    "body_text",
    "links",
    "label",
    "source",
]
PHISHING, SAFE = 1, 0
HAM_FOLDERS = ["easy_ham", "easy_ham_2", "hard_ham"]

# Some phishing emails are a bare URL, which BeautifulSoup warns about. That's expected.
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

# --- Parsing -------------------------------------------------------------------------

_PARSER = BytesParser(policy=policy.default)


def parse_email_bytes(data: bytes) -> EmailMessage:
    """Parse one raw email (the bytes of an .eml file or an mbox message)."""
    return _PARSER.parsebytes(data)


def _part_text(part: EmailMessage) -> str:
    """Decode one text part. Old emails often lie about (or omit) their charset, so try
    the declared one, then UTF-8, then cp1252 (the usual Western-European encoding)."""
    payload = part.get_payload(decode=True) or b""
    for charset in (part.get_content_charset(), "utf-8"):
        if charset:
            try:
                return payload.decode(charset)
            except (LookupError, UnicodeError):
                pass
    return payload.decode("cp1252", errors="replace")


def _header(msg: EmailMessage, name: str) -> str:
    """Read a header as text. Malformed headers in old spam can raise, so be defensive."""
    try:
        return str(msg.get(name, "") or "")
    except Exception:  # noqa: BLE001 - any parse error just means "no usable header"
        return ""


def html_to_text_and_links(html: str) -> tuple[str, list[dict]]:
    """Return the visible text of an HTML body and its links (visible text + real href)."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "head", "title"]):
        tag.decompose()
    links = [
        {"text": a.get_text(" ", strip=True), "href": a["href"].strip()}
        for a in soup.find_all("a", href=True)
        if a["href"].strip().lower().startswith(("http://", "https://", "www."))
    ]
    # One line per block of text, so line-based cleaning below works on HTML too.
    return soup.get_text("\n"), links


_LOOKS_LIKE_HTML_RE = re.compile(r"<(?:html|body|div|table|p|br|span|img|a)\b", re.I)


def extract_fields(msg: EmailMessage) -> dict:
    """Pull out only what Gmail shows on the page. Attachments are never decoded."""
    sender_name, sender_email = parseaddr(_header(msg, "From"))

    html_parts, plain_parts = [], []
    for part in msg.walk():
        if part.is_multipart() or part.is_attachment():
            continue
        if part.get_content_type() == "text/html":
            html_parts.append(_part_text(part))
        elif part.get_content_type() == "text/plain":
            plain_parts.append(_part_text(part))

    # Gmail renders the HTML version when there is one, so prefer it. Some old emails
    # send HTML labelled as plain text; treat those as HTML too.
    plain = "\n".join(plain_parts)
    if html_parts:
        body_text, links = html_to_text_and_links("\n".join(html_parts))
    elif _LOOKS_LIKE_HTML_RE.search(plain):
        body_text, links = html_to_text_and_links(plain)
    else:
        body_text, links = plain, []

    return {
        "sender_name": sender_name,
        "sender_email": sender_email,
        "subject": _header(msg, "Subject"),
        "body_text": body_text,
        "links": links,
    }


# --- Cleaning used for training AND prediction ---------------------------------------

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")

_MONTH = (
    r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
    r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?"
)
_YEAR = r"(?:19[5-9]\d|20[0-4]\d)"
_DATE_PATTERNS = [
    # ISO timestamps: 2002-09-30, 2002-09-30T00:15:00Z
    rf"\b{_YEAR}-\d{{1,2}}-\d{{1,2}}(?:t\d{{1,2}}:\d{{2}}(?::\d{{2}})?(?:\.\d+)?z?)?",
    # "Aug 22, 2002", "May 5th", "August 2002". Words like "may" or "march" are only
    # removed next to a number, so "you may lose access" is left alone.
    rf"\b{_MONTH}\s+\d{{1,2}}(?:st|nd|rd|th)?\b(?:,?\s+{_YEAR}\b)?",
    rf"\b\d{{1,2}}(?:st|nd|rd|th)?\s+(?:of\s+)?{_MONTH}(?:,?\s+{_YEAR}\b)?",
    rf"\b{_MONTH},?\s+{_YEAR}\b",
    # Weekdays: full names anywhere, short names only before a comma ("Thu, 22 ...").
    r"\b(?:mon|tues|wednes|thurs|fri|satur|sun)day\b",
    r"\b(?:mon|tue|wed|thu|fri|sat|sun)\.?,",
    # 22/08/2002, 2002-08-22, 8.22.02
    r"\b\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4}\b",
    # 14:38:22, 9:44 pm, and time zones (+0100, GMT, PDT)
    r"\b\d{1,2}:\d{2}(?::\d{2})?(?:\s*[ap]\.?m\.?\b)?",
    r"(?<![\w$])[+-]\d{4}\b",
    r"\b(?:gmt|utc|[ecmp][sd]t|bst|cet|cest)\b",
    # Any remaining standalone year
    rf"\b{_YEAR}\b",
]
DATE_RE = re.compile("|".join(_DATE_PATTERNS), re.IGNORECASE)

# Zero-width characters and other invisible formatting characters.
_INVISIBLE_RE = re.compile(r"[​-‏ - ⁠-⁯﻿­]")
_SPACES_RE = re.compile(r"\s+")


def clean_text(text: str) -> str:
    """Normalise text and remove anything that dates an email."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE_RE.sub("", text)
    # Links are kept separately in `links`, so URLs and addresses are removed from the
    # text. Old plain-text mail shows raw URLs while modern HTML mail hides them behind
    # link text, so even a placeholder word would hint at the email's age.
    text = URL_RE.sub(" ", text)
    text = EMAIL_RE.sub(" ", text)
    text = DATE_RE.sub(" ", text)
    return _SPACES_RE.sub(" ", text).strip()


# Single-word tags in square brackets, added by mailing lists ("[ILUG]") or spam filters
# ("[SPAM]"). Tags with spaces such as "[Action Required]" are kept.
_SUBJECT_TAG_RE = re.compile(r"\[[^\s\]]+\]")
# "Re:", "Fwd:", "RE[2]:" prefixes. In the training data almost all replies are ham
# (mailing-list threads), but phishers can add "Re:" to anything, so don't learn from it.
_REPLY_PREFIX_RE = re.compile(r"^\s*(?:(?:re|fwd?|aw|sv)\s*(?:\[\d+\])?\s*:\s*)+", re.I)


def clean_subject(subject: str) -> str:
    subject = _SUBJECT_TAG_RE.sub(" ", subject)
    return clean_text(_REPLY_PREFIX_RE.sub("", subject.strip()))


def _bare_url_links(text: str) -> list[dict]:
    """Plain-text emails have no <a> tags. Gmail turns bare URLs into links, so do the same."""
    links = []
    for match in URL_RE.finditer(text):
        url = match.group().rstrip(".,;:!?")
        href = url if url.lower().startswith("http") else "http://" + url
        links.append({"text": url, "href": href})
    return links


def prepare_email(fields: dict) -> dict:
    """Clean one email's fields. Use this on training data and on emails from Gmail."""
    links = list(fields.get("links") or [])
    seen = {(link["text"], link["href"]) for link in links}
    for link in _bare_url_links(fields.get("body_text", "")):
        if (link["text"], link["href"]) not in seen:
            seen.add((link["text"], link["href"]))
            links.append(link)

    return {
        "sender_name": clean_text(fields.get("sender_name", "")),
        "sender_email": fields.get("sender_email", "").strip().lower(),
        "subject": clean_subject(fields.get("subject", "")),
        "body_text": clean_text(fields.get("body_text", "")),
        "links": links,
    }


# --- Cleaning used for training only -------------------------------------------------


_CORPUS_ARTIFACTS = re.compile(
    "|".join(
        [
            # Nazario's recipient is always jose@monkey.org, and phishing personalises
            # with it ("Dear jose", "monkey.org Mail Admin", "monkey's mail server").
            # Deleting it matches prediction time, where the real user's name is just
            # an unknown word to the model.
            r"jose@monkey\.org",
            r"monkey\.org",
            r"\bjose\b",
            r"\bmonkey\b",
            # SpamAssassin anonymised names, addresses and list names as zzzz / yyyy /
            # qqqq, and the corpus owner's name and domain appear in many messages.
            r"\S*(?:zzzz|yyyy|qqqq)\S*",
            r"\S*taint\.org\S*",
            r"\bspamassassin\b",
            r"\bjmason\b",
            # Image placeholders written by the RSS-to-email gateway in easy_ham.
            r"\[IMG:[^\]]*\]+",
        ]
    ),
    re.IGNORECASE,
)
# In links the anonymised recipient is replaced rather than deleted, so URLs stay
# parseable for the rules (e.g. "http://login.monkey.org.evil.com/#jose@monkey.org").
_LINK_ARTIFACTS = [
    (re.compile(pattern, re.IGNORECASE), replacement)
    for pattern, replacement in [
        (r"monkey\.org", "example.com"),
        (r"\bmonkey\b", "example"),
        (r"\bjose(?=@|%40|\b)", "user"),  # %40 is a URL-encoded "@"
    ]
]

# Header-style lines inside the body (forwards, digests, RSS items): "Date: ...",
# "From: ...". With dates and addresses stripped, only the labels would be left.
_EMBEDDED_HEADER_RE = re.compile(
    r"^[ \t]*(?:date|from|to|cc|sent|subject|url):.*$", re.IGNORECASE | re.MULTILINE
)

# Quoted replies. Gmail hides quoted text behind "...", so the extension won't see it,
# and in the ham it repeats other messages from the same mailing list.
_QUOTED_LINE_RE = re.compile(r"^[ \t]*>.*$", re.MULTILINE)
_ATTRIBUTION_RE = re.compile(r"^.*\bwrote:[ \t]*$", re.MULTILINE)
_FORWARDED_RE = re.compile(
    r"^[ \t>]*-{3,}\s*(?:Original Message|Forwarded message)\s*-{3,}.*",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)

# Footers that 2002-era mailing lists appended to every message. Each pattern removes
# the footer through to the end of the body.
_LIST_FOOTERS = [
    re.compile(p, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    for p in [
        r"^_{10,}\s*\n[^\n]*mailing list.*",  # Mailman
        r"^-{10,}[^\n]*\n[^\n]*sf\.net email is sponsored by.*",  # SourceForge ads
        r"^-{5,}\s*Yahoo! Groups Sponsor.*",  # Yahoo! Groups
        r"^To unsubscribe from this group, send an email to.*",
        r"^Irish Linux Users' Group.*",  # ILUG list
    ]
]


def remove_corpus_artifacts(fields: dict) -> dict:
    """Remove patterns that only exist in the training datasets. Training only."""
    body = fields["body_text"]
    for pattern in [
        *_LIST_FOOTERS,
        _FORWARDED_RE,
        _QUOTED_LINE_RE,
        _ATTRIBUTION_RE,
        _EMBEDDED_HEADER_RE,
    ]:
        body = pattern.sub("", body)

    cleaned = {**fields, "body_text": body}
    # sender_email is left alone: it's for the rules, not the text model.
    for key in ("sender_name", "subject", "body_text"):
        cleaned[key] = _CORPUS_ARTIFACTS.sub("", cleaned[key])
    cleaned["links"] = [
        {key: _scrub_link(value) for key, value in link.items()}
        for link in fields["links"]
    ]
    return cleaned


def _scrub_link(value: str) -> str:
    for pattern, replacement in _LINK_ARTIFACTS:
        value = pattern.sub(replacement, value)
    return value


# A line that repeats across many ham emails but (almost) never in phishing is
# boilerplate: a personal signature, newsletter menu, or list footer. The model would
# memorise it instead of learning anything about phishing. Short lines such as
# "Thanks," are left alone.
BOILERPLATE_MIN_HAM = 10
BOILERPLATE_MAX_PHISHING = 2
BOILERPLATE_MIN_CHARS = 16


def line_key(line: str) -> str:
    return _SPACES_RE.sub(" ", line).strip().lower()


def find_boilerplate_lines(bodies: list[str], labels: list[int]) -> set[str]:
    """Return the lines that only repeat in ham. Training only."""
    counts = {SAFE: Counter(), PHISHING: Counter()}
    for body, label in zip(bodies, labels):
        keys = {line_key(line) for line in body.splitlines()}
        counts[label].update(k for k in keys if len(k) >= BOILERPLATE_MIN_CHARS)
    return {
        line
        for line, n in counts[SAFE].items()
        if n >= BOILERPLATE_MIN_HAM
        and counts[PHISHING][line] <= BOILERPLATE_MAX_PHISHING
    }


def remove_boilerplate_lines(body: str, boilerplate: set[str]) -> str:
    return "\n".join(l for l in body.splitlines() if line_key(l) not in boilerplate)


# --- Loading the datasets ------------------------------------------------------------


def _is_mbox_placeholder(msg: EmailMessage) -> bool:
    """Nazario's files each start with a fake 'FOLDER INTERNAL DATA' message."""
    return "X-IMAP" in msg or "FOLDER INTERNAL DATA" in _header(msg, "Subject")


def _iter_nazario(raw_dir: Path):
    for path in sorted((raw_dir / "phishing").glob("phishing-*")):
        box = mailbox.mbox(path, create=False)
        for key in box.iterkeys():
            yield parse_email_bytes(
                box.get_bytes(key)
            ), PHISHING, f"nazario-{path.name[-4:]}"


def _iter_spamassassin(raw_dir: Path):
    for folder in HAM_FOLDERS:
        for path in sorted((raw_dir / "ham" / folder).iterdir()):
            if path.name == "cmds":  # a list of shell commands, not an email
                continue
            yield parse_email_bytes(path.read_bytes()), SAFE, folder


def load_dataset(raw_dir: Path = RAW_DIR) -> tuple[pd.DataFrame, dict]:
    """Load, clean and de-duplicate both datasets.

    Returns the table (one row per email, columns COLUMNS) and a dict of counts
    describing what was dropped along the way.
    """
    return build_table(*load_raw_emails(raw_dir))


def load_raw_emails(
    raw_dir: Path = RAW_DIR,
) -> tuple[list[tuple[dict, int, str]], dict]:
    """Parse both datasets and apply the training-only cleaning.

    Returns (fields, label, source) for every real email, with line breaks still in
    body_text, plus a dict of counts. build_table() finishes the job.
    """
    stats = {"parsed": 0, "placeholder": 0}
    raw = []
    for source_iter in (_iter_nazario(raw_dir), _iter_spamassassin(raw_dir)):
        for msg, label, source in source_iter:
            stats["parsed"] += 1
            if _is_mbox_placeholder(msg):
                stats["placeholder"] += 1
                continue
            raw.append((remove_corpus_artifacts(extract_fields(msg)), label, source))

    # Boilerplate needs counts over the whole dataset, so it's a second pass.
    boilerplate = find_boilerplate_lines(
        [fields["body_text"] for fields, _, _ in raw], [label for _, label, _ in raw]
    )
    stats["boilerplate_lines"] = len(boilerplate)
    for fields, _, _ in raw:
        fields["body_text"] = remove_boilerplate_lines(fields["body_text"], boilerplate)
    return raw, stats


def build_table(
    raw: list[tuple[dict, int, str]], stats: dict
) -> tuple[pd.DataFrame, dict]:
    """Clean the output of load_raw_emails() into one de-duplicated table."""
    stats = {**stats, "empty_body": 0}
    rows = []
    for fields, label, source in raw:
        fields = prepare_email(fields)
        if not fields["body_text"]:
            stats["empty_body"] += 1
            continue
        rows.append({**fields, "label": label, "source": source})

    df = pd.DataFrame(rows, columns=COLUMNS)

    # Duplicates: the same campaign is often collected many times. Compare cleaned
    # subject + body, ignoring case and spacing.
    key = (df["subject"] + "\n" + df["body_text"]).str.lower()
    df["_key"] = key.map(lambda s: hashlib.sha1(s.encode("utf-8")).hexdigest())
    before = len(df)
    # Drop texts that appear with BOTH labels: they would teach the model nothing.
    conflicting = df.groupby("_key")["label"].transform("nunique") > 1
    stats["conflicting_labels"] = int(conflicting.sum())
    df = df[~conflicting].drop_duplicates("_key")
    stats["duplicates"] = before - stats["conflicting_labels"] - len(df)

    return df.drop(columns="_key").reset_index(drop=True), stats


def main() -> None:
    df, stats = load_dataset()
    print("Dropped:", stats)
    print(f"Emails after cleaning: {len(df)}")
    print(
        df["label"].map({PHISHING: "phishing", SAFE: "safe"}).value_counts().to_string()
    )
    print(df["source"].value_counts().sort_index().to_string())


if __name__ == "__main__":
    main()
