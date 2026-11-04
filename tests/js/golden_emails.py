"""Our own example emails for the JavaScript parity tests (tests/js/parity.test.mjs).

Every email here was written for PhishLens; none is taken from the Nazario or
SpamAssassin datasets. Together they make every rule fire, and they include the
awkward inputs where JavaScript and Python could disagree: invisible characters,
look-alike letters, non-Latin scripts, emoji, odd line breaks, unusual URLs.

Invisible and non-ASCII characters are built with chr() and unicodedata.lookup(), so
this file stays plain ASCII and every input is visible when reading it.
"""

from __future__ import annotations

from unicodedata import lookup

from model.tests.example_emails import EXAMPLES

ZWSP = chr(0x200B)  # zero-width space
SOFT_HYPHEN = chr(0xAD)
BOM = chr(0xFEFF)
LINE_SEPARATOR = chr(0x2028)
NEL = chr(0x85)  # "next line", a line break to str.splitlines()
NBSP = chr(0xA0)
IDEOGRAPHIC_SPACE = chr(0x3000)
EM_SPACE = chr(0x2003)
COPYRIGHT = chr(0xA9)
EMOJI = chr(0x1F600)
CYRILLIC_A = lookup("CYRILLIC SMALL LETTER A")
CYRILLIC_O = lookup("CYRILLIC SMALL LETTER O")
CYRILLIC_ES = lookup("CYRILLIC SMALL LETTER ES")
GREEK_OMICRON = lookup("GREEK SMALL LETTER OMICRON")
DOTLESS_I = lookup("LATIN SMALL LETTER DOTLESS I")
DOTTED_CAPITAL_I = lookup("LATIN CAPITAL LETTER I WITH DOT ABOVE")
KELVIN = lookup("KELVIN SIGN")
FULLWIDTH_P = lookup("FULLWIDTH LATIN CAPITAL LETTER P")
SUPERSCRIPT_TWO = lookup("SUPERSCRIPT TWO")
E_ACUTE = lookup("LATIN SMALL LETTER E WITH ACUTE")
# "Sri Lanka" in Sinhala: letters, vowel signs (combining marks) and a zero-width
# joiner. Python's \w doesn't count combining marks as word characters.
SINHALA = "".join(
    lookup(name)
    for name in [
        "SINHALA LETTER TAALUJA SAYANNA",
        "SINHALA SIGN AL-LAKUNA",
        "ZERO WIDTH JOINER",
        "SINHALA LETTER RAYANNA",
        "SINHALA VOWEL SIGN DIGA IS-PILLA",
        "SPACE",
        "SINHALA LETTER DANTAJA LAYANNA",
        "SINHALA SIGN ANUSVARAYA",
        "SINHALA LETTER ALPAPRAANA KAYANNA",
        "SINHALA VOWEL SIGN AELA-PILLA",
    ]
)


def email(
    sender_name="",
    sender_email="someone@example.org",
    subject="",
    body="",
    links=(),
    attachments=None,
) -> dict:
    fields = {
        "sender_name": sender_name,
        "sender_email": sender_email,
        "subject": subject,
        "body_text": body,
        "links": [{"text": text, "href": href} for text, href in links],
    }
    if attachments is not None:  # optional in the API contract
        fields["attachments"] = list(attachments)
    return fields


GOLDEN_EMAILS: dict[str, dict] = {
    **{f"example: {name}": fields for name, (fields, _) in EXAMPLES.items()},
    "ip link and url shortener": email(
        sender_name="IT Helpdesk",
        sender_email="helpdesk@campus-it.example",
        subject="Mailbox quota",
        body="Your mailbox is almost full. Upgrade your quota here.",
        links=[
            ("Upgrade quota", "http://185.22.10.4/upgrade"),
            ("Details", "https://bit.ly/3xYz12"),
            ("More details", "https://www.tinyurl.com/abc"),
            ("Numeric host", "http://3232235777/login"),
        ],
    ),
    "ipv6, userinfo and unparseable links": email(
        subject="Shared files",
        body="Three files were shared with you.",
        links=[
            ("File one", "http://[2001:db8::1]:8080/file"),
            ("File two", "http://paypal.com@203.0.113.9/login"),
            ("File three", "http://[oops/Scan.exe"),
            ("File four", "https://a]b.example/x.zip"),
            ("Zone", "http://[fe80::1%25eth0]/"),
            ("Mapped", "http://[::ffff:192.0.2.1]/"),
            ("Bad IPv6", "http://[1:2:3]/"),
        ],
    ),
    "lookalike sender and links": email(
        sender_name="Microsoft 365",
        sender_email="no-reply@rnicrosoft-alerts.com",
        subject="Password expiry notice",
        body="Your password expires today. Keep your current password below.",
        links=[
            ("Keep password", "https://login.micros0ft-support.com/keep"),
            ("paypa1.com", "http://g00gle.com/x"),
            ("www.paypal.com", "https://www.paypal.com/"),
            ("Wells", "https://we11sfargo-secure.co.uk/"),
        ],
    ),
    "link text mismatch, redirects and trackers": email(
        sender_name="Bank Alerts",
        sender_email="alerts@bank.example",
        subject="Statement ready",
        body="Your statement is ready.",
        links=[
            ("https://www.paypal.com/statement", "https://paypal.statement-view.net/s"),
            (
                "paypal.com",
                "https://www.google.com/url?q=https%3A%2F%2Fwww.paypal.com%2Flogin",
            ),
            ("bank.example", "https://u12.ct.sendgrid.net/ls/click?upn=xyz"),
            ("Visit www.ecu.edu.lk now", "https://evil.edu.lk/"),
            ("CO.UK shop", "https://shop.example.co.uk/"),
        ],
    ),
    "homoglyphs in text and domains": email(
        sender_name="P" + CYRILLIC_A + "yPal",
        sender_email="service@xn--pypal-4ve.com",
        subject="Your " + CYRILLIC_A + "ccount needs attention",
        body=(
            "Please review the recent "
            + CYRILLIC_ES
            + CYRILLIC_O
            + " activity on your account today.\n"
            + "The word "
            + GREEK_OMICRON
            + "k"
            + " looks odd."
        ),
        links=[("Review", "https://p" + CYRILLIC_A + "ypal.example/review")],
    ),
    "sender name shows another domain": email(
        sender_name="service@paypal.com",
        sender_email="x@evil-mailer.example",
        subject="Receipt",
        body="Thanks for your payment.",
    ),
    "sender name claims a brand": email(
        sender_name="Bank of America Alerts",
        sender_email="alerts@secure-mail.example",
        subject="Please verify",
        body="Please verify your identity.",
    ),
    # A domain followed by "-" is part of a longer name, not a domain on its own.
    # (A JS translation bug once matched "support.my" inside "support.my-free...".)
    "domains followed by a hyphen": email(
        sender_name="Help desk.store-team",
        sender_email="help@ever-desk.store",
        subject="Upgrade",
        body="Upgrade at upgrade.my-free.example today.",
        links=[("upgrade.my-free.example", "https://upgrade.my-free.example/go")],
    ),
    "sender name domain matches": email(
        sender_name="paypal.com Support",
        sender_email="support@mail.paypal.com",
        subject="Hello",
        body="A normal message from a normal sender.",
    ),
    "urgency and sensitive requests": email(
        sender_name="Security Team",
        sender_email="security@account-check.example",
        subject="URGENT: final notice",
        body=(
            "Your account will be permanently suspended within 24 hours.\n"
            "Immediate action required. Act now to avoid closure.\n"
            "Please confirm your password and enter your credit card number.\n"
            "Also send us two Google Play cards and your social security number.\n"
            "Failure to verify will result in your mailbox being deleted.\n"
            "We noticed unusual sign-in activity and unauthorized access attempts."
        ),
    ),
    "invisible characters inside words": email(
        sender_name="Pay" + ZWSP + "Pal" + BOM,
        sender_email="  Support@Example-Pay.COM ",
        subject="Con" + SOFT_HYPHEN + "firm your pass" + ZWSP + "word",
        body=(
            "Please con"
            + ZWSP
            + "firm your pass"
            + SOFT_HYPHEN
            + "word now."
            + LINE_SEPARATOR
            + "Your acc"
            + ZWSP
            + "ount is lo"
            + chr(0x200D)
            + "cked."
        ),
        links=[("Con" + ZWSP + "firm", "https://example-pay.com/c")],
    ),
    "turkish i and other case-folding letters": email(
        subject="Unusual act" + DOTLESS_I + "vity detected",
        body=(
            "We saw susp"
            + DOTLESS_I
            + "cious log"
            + DOTLESS_I
            + "n attempts.\n"
            + DOTTED_CAPITAL_I
            + "MMED"
            + DOTTED_CAPITAL_I
            + "ATE ACT"
            + DOTTED_CAPITAL_I
            + "ON REQU"
            + DOTTED_CAPITAL_I
            + "RED\n"
            + "Visit www."
            + KELVIN
            + "ayak.com today. "
            + FULLWIDTH_P
            + "ay now with a g"
            + DOTLESS_I
            + "ft card."
        ),
    ),
    "dates, copyright, addresses and urls are removed": email(
        sender_name="Northwind Team",
        sender_email="news@northwind.example",
        subject="[News] Re: Fwd: RE[2]: Weekly update",
        body=(
            "Sent: Thu, 22 Aug 2002 14:38:22 +0100 (GMT)\n"
            "Meeting on Monday, March 3rd at 9:44 pm PDT, or 2002-09-30T00:15:00Z.\n"
            "You may lose nothing; may 5th is fine. 22/08/2002 and 8.22.02 too.\n"
            "Write to jo.e+news@mail.northwind.example or ..dots@x.example.\n"
            "Read more at www.northwind.example/news. Or https://northwind.example/a?b=c,\n"
            + COPYRIGHT
            + " 2024 Northwind, Inc. All rights reserved. Copyright (c) 2019 by Northwind\n"
            "Price went up 2009 to 2010 and $+1234 stayed."
        ),
        links=[("Read more", "https://northwind.example/news")],
    ),
    "risky attachments and file mentions": email(
        sender_name="Accounts",
        sender_email="accounts@billing.example",
        subject="Invoice_2291.pdf.exe attached",
        body=(
            "Open the attached Invoice_2291.pdf.exe and Scan.ZIP today.\n"
            "See example.com/story/0,1,00.html (a web page, not a file).\n"
            "Also report.docm and payroll(1).xlsm."
        ),
        links=[
            ("Download", "https://files.billing.example/download/Statement.zip"),
            ("Web page", "https://billing.example/help/index.html"),
            ("setup.msi", "https://billing.example/setup.msi?x=1"),
        ],
        attachments=[
            "Invoice_2291.pdf.exe",
            "  notes.txt ",
            "",
            "notes.txt",
            "Photo.jpg.js",
            "Archive.7z",
            "page.html",
        ],
    ),
    "plain-text body with bare urls and duplicate links": email(
        subject="Links",
        body=(
            "Go to www.example-shop.com/login. Then http://example-shop.com/cart!\n"
            "Again: www.example-shop.com/login.\n"
            "And (https://bit.ly/abc)."
        ),
        links=[("www.example-shop.com/login", "http://www.example-shop.com/login")],
    ),
    "odd whitespace and line breaks": email(
        sender_name="  Maya" + NBSP + NBSP + "Perera\t",
        subject="  Weekend\tplans" + IDEOGRAPHIC_SPACE + " ",
        body=(
            "Line one\r\nLine two\rLine three\x0bLine four\x0cLine five"
            + NEL
            + "Line six\x1cLine seven"
            + EM_SPACE
            + "end\n\n\n   \n\tIndented line\x1f"
        ),
    ),
    "non-latin scripts, accents and emoji": email(
        sender_name="Nimal " + EMOJI,
        sender_email="nimal@example.lk",
        subject=SINHALA + " trip " + EMOJI,
        body=(
            "Caf"
            + E_ACUTE
            + " plans for the "
            + SINHALA
            + " trip.\n"
            + "Bring x"
            + SUPERSCRIPT_TWO
            + " snacks "
            + EMOJI * 3
            + " and r"
            + E_ACUTE
            + "sum"
            + E_ACUTE
            + ".\n"
            + "A quote with an emoji at the end of a long line that goes on and on "
            + EMOJI
            + " and on."
        ),
        links=[
            (
                "A very long link text that will have to be shortened in the message "
                + EMOJI,
                "http://203.0.113.50/" + "a" * 80,
            ),
            ("caf" + E_ACUTE + ".example", "https://xn--caf-dma.example/"),
        ],
    ),
    "brand names are masked for the text model": email(
        sender_name="Bank of America",
        sender_email="alerts@bankofamerica.com",
        subject="Your PayPal and Pay  Pal and Wells\nFargo update",
        body=(
            "Office 365 and office365 users, plus Bank of   America and LinkedIn "
            "members: Dropbox, DocuSign and Apple news."
        ),
    ),
    "typical phishing wording": email(
        sender_name="Account Services",
        sender_email="service@secure-verify.example",
        subject="Verify your account information",
        body=(
            "Dear valued customer,\n"
            "We are unable to verify your account information. Kindly click on the "
            "link below to verify your account and restore full access. "
            "Your account will be suspended if not verified.\n"
            "Click here to verify\n"
            "Thank you for your cooperation."
        ),
        links=[("Click here to verify", "http://verify-account.example/login")],
    ),
    "short friendly note": email(
        sender_name="Priya",
        sender_email="priya@example.lk",
        subject="Thanks!",
        body="Thanks for dinner yesterday, it was lovely. See you soon.",
    ),
    "empty email": email(sender_email="nobody@example.org"),
    "missing optional fields": {"sender_email": "someone@example.org"},
    "gift card scam": email(
        sender_name="The Principal",
        sender_email="principal.office@gmail.com",
        subject="Quick favour",
        body=(
            "Are you available? I need you to buy some gift cards for the staff today. "
            "Get 5 iTunes cards and send me the codes. It's urgent."
        ),
    ),
}

# Single helper inputs, compared one by one (host_of, is_ip, registrable_domain,
# unquote, quote): URL shapes the email examples don't all cover.
GOLDEN_URLS = [
    "https://login.paypal.com/x",
    "paypal.com/login",
    "  HTTPS://WWW.Example.CO.UK./path ",
    "http://user:pass@Example.com:8080/",
    "http://[::1]/",
    "http://[v1.fe]/",
    "http://[vz.x]/",
    "http://[1.2.3.4]/",
    "http://[::1]x/",
    "http://x[::1]/",
    "http://[oops",
    "http://a]b",
    "http://192.168.001.1/",
    "http://256.1.1.1/",
    "http://1.2.3.4./",
    "http://3232235777/",
    "http://" + SUPERSCRIPT_TWO + "/",
    "http://ex" + chr(0x2100) + "mple.com/",
    "http://www.city.kobe.jp/",
    "http://a.b.kobe.jp/",
    "http://foo.ck/",
    "http://www.ck/",
    "http://user.github.io/",
    "http://github.io/",
    "http://co.uk/",
    "http://a..com/",
    "http://localhost/",
    "http://xn--caf-dma.example/",
    "http://caf" + E_ACUTE + ".example/",
    "mailto:someone@example.com",
    "javascript:alert(1)",
    "//cdn.example.com/x.js",
    "http://example.com\t/\npath",
    "\x00\x01 http://example.com/",
    "http://[fe80::1%eth0]/",
    "http://[fe80::1%]/",
    "http://[::ffff:1.2.3.4]/",
    "http://[1::2::3]/",
    "http://[1:2:3:4:5:6:7:8:9]/",
    "http://[::1:2:3:4:5:6:7:8]/",
    "http://[1:2:3:4:5:6:7::]/",
    "http://[:1:2:3:4:5:6:7]/",
    "http://[12345::]/",
    "http://[g::]/",
    "http://[" + chr(0xFF11) + "::]/",
]

GOLDEN_UNQUOTE = [
    "https://www.google.com/url?q=https%3A%2F%2Fpaypal.com",
    "%E2%82%AC and %e2%82%ac",
    "%E2%82 broken",
    "%FF%FE%41",
    "%EF%BB%BFbom",
    "100% sure %zz %4",
    "caf" + E_ACUTE + "%20bar%C3%A9",
    "no escapes",
]

GOLDEN_QUOTES = [
    "short",
    "  spaced   out\ttext\n",
    "x" * 60,
    "x" * 61,
    EMOJI * 61,
    "word " * 20,
]
