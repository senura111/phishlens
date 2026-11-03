import unicodedata

import pytest

from model.src import features as ft


def make_email(
    sender_name="", sender_email="someone@example.org", subject="", body="", links=()
):
    return {
        "sender_name": sender_name,
        "sender_email": sender_email,
        "subject": subject,
        "body_text": body,
        "links": [{"text": text, "href": href} for text, href in links],
    }


def ids(reasons):
    return [r["id"] for r in reasons]


# --- Helpers -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host, expected",
    [
        ("login.paypal.com", "paypal.com"),
        ("paypal.com", "paypal.com"),
        ("www.bbc.co.uk", "bbc.co.uk"),
        ("185.22.10.4", "185.22.10.4"),
    ],
)
def test_registrable_domain(host, expected):
    assert ft.registrable_domain(host) == expected


def test_host_of_handles_missing_scheme_ports_and_garbage():
    assert ft.host_of("www.PayPal.com/login") == "www.paypal.com"
    assert ft.host_of("https://evil.ru:8080/x") == "evil.ru"
    assert ft.host_of("http://[not-an-ip/") == ""


def test_domains_in_text_ignores_file_names_and_email_addresses():
    assert ft.domains_in_text("Go to https://www.paypal.com/login") == [
        "www.paypal.com"
    ]
    assert ft.domains_in_text("Open invoice.pdf or mail help@paypal.com") == []
    assert ft.domains_in_text("Click here") == []


def test_quote_shortens_long_text():
    assert len(ft.quote("x" * 500)) == ft.MAX_QUOTE


# --- Rule 1: link text vs href -------------------------------------------------------


def test_link_text_mismatch_fires_when_shown_domain_differs():
    email = make_email(links=[("paypal.com/login", "http://185.22.10.4/login")])
    reasons = ft.link_text_mismatch(email)
    assert reasons == [
        {
            "id": "link_text_mismatch",
            "severity": "high",
            "message": "A link shows 'paypal.com' but goes to '185.22.10.4'",
        }
    ]


def test_link_text_mismatch_counts_extra_links():
    email = make_email(
        links=[
            ("paypal.com", "http://evil.ru/a"),
            ("apple.com", "http://evil.ru/b"),
        ]
    )
    assert ft.link_text_mismatch(email)[0]["message"].endswith("(and 1 more)")


@pytest.mark.parametrize(
    "text, href",
    [
        ("Click here", "http://evil.ru/login"),  # text shows no domain
        ("www.paypal.com", "https://login.paypal.com/x"),  # same registrable domain
        ("paypal.com", "https://www.google.com/url?q=https%3A%2F%2Fpaypal.com%2F"),
    ],
)
def test_link_text_mismatch_does_not_fire(text, href):
    assert ft.link_text_mismatch(make_email(links=[(text, href)])) == []


def test_find_reasons_runs_all_rules():
    email = make_email(links=[("paypal.com", "http://evil.ru/")])
    assert "link_text_mismatch" in ids(ft.find_reasons(email))


# --- Rule 2: raw-IP links and URL shorteners -----------------------------------------


@pytest.mark.parametrize(
    "href", ["http://185.22.10.4/login", "http://[2001:db8::1]/x", "http://3232235777/"]
)
def test_ip_link_fires_for_ip_hosts(href):
    reasons = ft.ip_or_shortened_links(make_email(links=[("Log in", href)]))
    assert ids(reasons) == ["ip_link"]
    assert reasons[0]["severity"] == "high"


@pytest.mark.parametrize("href", ["https://bit.ly/3xYz", "http://www.tinyurl.com/abc"])
def test_url_shortener_fires_for_known_shorteners(href):
    reasons = ft.ip_or_shortened_links(make_email(links=[("Track parcel", href)]))
    assert ids(reasons) == ["url_shortener"]
    assert reasons[0]["severity"] == "medium"


def test_ip_and_shortener_can_both_fire():
    email = make_email(links=[("a", "http://10.0.0.1/"), ("b", "https://bit.ly/x")])
    assert ids(ft.ip_or_shortened_links(email)) == ["ip_link", "url_shortener"]


@pytest.mark.parametrize(
    "href", ["https://www.paypal.com/", "https://notbit.ly.example.com/", "mailto:x"]
)
def test_ip_or_shortened_links_does_not_fire_for_normal_links(href):
    assert ft.ip_or_shortened_links(make_email(links=[("x", href)])) == []


# --- Rule 3: lookalike brand domains -------------------------------------------------


@pytest.mark.parametrize(
    "host, brand",
    [
        ("paypa1-secure.com", "paypal.com"),  # 1 for l, plus brand + extra word
        ("paypal.com.evil.ru", "paypal.com"),  # brand as a subdomain
        ("securepaypal.net", "paypal.com"),  # brand inside a longer word
        ("paypai.com", "paypal.com"),  # one typo
        ("rnicrosoft.com", "microsoft.com"),  # rn for m
        ("g00gle.com", "google.com"),  # zeros for o
        ("amazom.co.uk", "amazon.com"),  # typo with a two-part suffix
        ("dhl-delivery.info", "dhl.com"),  # short brand as a whole word
    ],
)
def test_imitated_brand_detects_lookalikes(host, brand):
    assert ft.imitated_brand(host) == brand


@pytest.mark.parametrize(
    "host",
    [
        "www.paypal.com",  # the real thing
        "mail.google.com",
        "docusign.net",
        "purchase-orders.com",  # contains "chase" but not as a word
        "apply-now.com",  # one letter from "apple", but apple is too short to fuzz
        "185.22.10.4",
        "",
    ],
)
def test_imitated_brand_ignores_real_and_unrelated_domains(host):
    assert ft.imitated_brand(host) is None


def test_within_one_edit():
    assert ft._within_one_edit("paypal", "paypai")  # replace
    assert ft._within_one_edit("paypal", "paypall")  # insert
    assert ft._within_one_edit("paypal", "papyal")  # swap
    assert not ft._within_one_edit("paypal", "paypal")
    assert not ft._within_one_edit("paypal", "pyapla")


def test_lookalike_domain_reason_matches_api_contract():
    email = make_email(sender_email="support@paypa1-secure.com")
    assert ft.lookalike_domain(email) == [
        {
            "id": "lookalike_domain",
            "severity": "high",
            "message": "Sender domain 'paypa1-secure.com' imitates paypal.com",
        }
    ]


def test_lookalike_domain_checks_link_hosts_and_link_text():
    email = make_email(
        links=[
            ("Sign in", "https://login.micros0ft-support.com/"),
            ("paypa1.com", "https://www.paypal.com/"),
        ]
    )
    reasons = ft.lookalike_domain(email)
    assert reasons[0]["message"].startswith("A link goes to 'login.micros0ft-support")
    assert reasons[0]["message"].endswith("(and 1 more)")


def test_lookalike_domain_does_not_fire_for_real_brand_mail():
    email = make_email(
        sender_email="service@paypal.com",
        links=[("paypal.com", "https://www.paypal.com/myaccount")],
    )
    assert ft.lookalike_domain(email) == []


# --- Rule 4: homoglyphs --------------------------------------------------------------

# Look-alike letters are built from their Unicode names so the tests stay readable.
CYR_A = unicodedata.lookup("CYRILLIC SMALL LETTER A")
CYR_O = unicodedata.lookup("CYRILLIC SMALL LETTER O")
CYR_TE = unicodedata.lookup("CYRILLIC CAPITAL LETTER TE")
CYR_HA = unicodedata.lookup("CYRILLIC SMALL LETTER HA")
GREEK_RHO = unicodedata.lookup("GREEK CAPITAL LETTER RHO")
GREEK_ALPHA = unicodedata.lookup("GREEK SMALL LETTER ALPHA")
RUSSIAN_HELLO = "".join(
    unicodedata.lookup(f"CYRILLIC SMALL LETTER {name}")
    for name in ["PE", "ER", "I", "VE", "IE", "TE"]
)


@pytest.mark.parametrize(
    "field, text",
    [
        ("subject", f"Your P{CYR_A}yPal account"),  # Cyrillic a inside a Latin word
        ("body", f"{GREEK_RHO}ay {GREEK_RHO}al security team"),  # Greek P
        ("body", f"{CYR_TE}{CYR_A}{CYR_HA} Refund available"),  # all-Cyrillic "Tax"
    ],
)
def test_homoglyphs_fires_for_lookalike_letters_in_english(field, text):
    reasons = ft.homoglyphs(make_email(**{field: text}))
    assert ids(reasons) == ["homoglyphs"]
    assert "look-alike letters" in reasons[0]["message"]


@pytest.mark.parametrize(
    "sender_email, href",
    [
        ("x@xn--pypal-4ve.com", "https://example.com/"),  # punycode sender domain
        ("x@example.org", f"https://p{CYR_A}ypal.com/login"),  # Cyrillic a in a link
    ],
)
def test_homoglyphs_fires_for_international_domains(sender_email, href):
    email = make_email(sender_email=sender_email, links=[("Log in", href)])
    reasons = ft.homoglyphs(email)
    assert ids(reasons) == ["homoglyphs"]
    assert "international characters" in reasons[0]["message"]


@pytest.mark.parametrize(
    "text",
    [
        "Your PayPal account",  # plain English
        "Caf\N{LATIN SMALL LETTER E WITH ACUTE} au lait for the r\N{LATIN SMALL LETTER E WITH ACUTE}sum\N{LATIN SMALL LETTER E WITH ACUTE} team",
        f"The p-value was below {GREEK_ALPHA} = 0.05",  # a single Greek letter
        f"{RUSSIAN_HELLO} {RUSSIAN_HELLO} {RUSSIAN_HELLO}",  # genuinely Russian text
        f"Microsoft Outlook {CYR_O}",  # one stray letter on its own isn't a word
    ],
)
def test_homoglyphs_does_not_fire_for_normal_text(text):
    assert ft.homoglyphs(make_email(body=text)) == []


# --- Rule 5: sender display name vs address ------------------------------------------


@pytest.mark.parametrize(
    "name, address, shown",
    [
        ("service@paypal.com", "x@evil.ru", "paypal.com"),
        ("paypal.com Support", "x@evil.ru", "paypal.com"),
    ],
)
def test_sender_name_mismatch_high_when_name_shows_another_domain(name, address, shown):
    reasons = ft.sender_name_mismatch(
        make_email(sender_name=name, sender_email=address)
    )
    assert reasons == [
        {
            "id": "sender_name_mismatch",
            "severity": "high",
            "message": f"The sender name shows '{shown}' but the email comes from 'evil.ru'",
        }
    ]


@pytest.mark.parametrize(
    "name", ["PayPal Support", "Bank of America Alerts", "Microsoft Office 365 Team"]
)
def test_sender_name_mismatch_medium_when_brand_name_from_other_domain(name):
    reasons = ft.sender_name_mismatch(
        make_email(sender_name=name, sender_email="alerts@gmail.com")
    )
    assert ids(reasons) == ["sender_name_mismatch"]
    assert reasons[0]["severity"] == "medium"
    assert "'gmail.com'" in reasons[0]["message"]


@pytest.mark.parametrize(
    "name, address",
    [
        ("PayPal", "service@intl.paypal.com"),  # subdomain of the real domain
        ("Amazon.com", "auto-confirm@amazon.com"),  # domain in the name matches
        ("Google Calendar", "calendar-notification@google.com"),
        ("Bob Smith", "bob@example.org"),  # no brand, no domain
        ("Purchase Department", "orders@example.org"),  # "chase" only inside a word
        ("", "x@evil.ru"),
    ],
)
def test_sender_name_mismatch_does_not_fire(name, address):
    assert (
        ft.sender_name_mismatch(make_email(sender_name=name, sender_email=address))
        == []
    )


# --- Rule 6: urgency -----------------------------------------------------------------


@pytest.mark.parametrize(
    "subject, body, phrase",
    [
        ("Your account will be suspended", "", "account will be suspended"),
        ("", "Verify within 24 hours or lose access.", "within 24 hours"),
        ("", "Your mailbox has been deactivated.", "mailbox has been deactivated"),
        ("URGENT: invoice", "", "urgent"),
        ("", "Immediate action required.", "immediate action"),
        ("", "We noticed unusual sign-in activity.", "unusual sign-in activity"),
        ("", "Your password will expire on .", "password will expire"),
        ("", "Failure to verify will result in closure.", "failure to verify"),
    ],
)
def test_urgency_fires_for_pressure_phrases(subject, body, phrase):
    reasons = ft.urgency(make_email(subject=subject, body=body))
    assert ids(reasons) == ["urgency"]
    assert reasons[0]["severity"] == "medium"
    assert f"'{phrase}'" in reasons[0]["message"]


def test_urgency_shows_at_most_two_phrases():
    body = "Urgent! Act now. Final notice. Within 2 days."
    message = ft.urgency(make_email(body=body))[0]["message"]
    assert message == "Uses pressure or threats to rush you: 'urgent', 'act now'"


@pytest.mark.parametrize(
    "body",
    [
        "Thanks for the update, see you at lunch.",
        "The meeting is in 2 weeks.",  # weeks, not hours or days
        "I closed the bug in the tracker.",  # no account word nearby
        "Lock the door when you leave the office.",
    ],
)
def test_urgency_does_not_fire_for_normal_text(body):
    assert ft.urgency(make_email(body=body)) == []


# --- Rule 7: sensitive requests ------------------------------------------------------


@pytest.mark.parametrize(
    "body, asked",
    [
        ("Please confirm your password below.", "your password"),
        ("Log in with your email credentials to continue.", "your password"),
        ("Update your credit card information today.", "card or bank details"),
        ("Enter the CVV on the back of your card.", "card or bank details"),
        ("Provide your bank account details for the refund.", "card or bank details"),
        ("Buy three Google Play cards and send me the codes.", "gift cards"),
        ("I need you to get some gift cards for a client.", "gift cards"),
    ],
)
def test_sensitive_request_fires(body, asked):
    reasons = ft.sensitive_request(make_email(body=body))
    assert ids(reasons) == ["sensitive_request"]
    assert reasons[0]["severity"] == "high"
    assert reasons[0]["message"].startswith(f"Asks for {asked}.")


def test_sensitive_request_lists_every_kind_asked_for():
    body = "Verify your password and your card number."
    message = ft.sensitive_request(make_email(body=body))[0]["message"]
    assert message.startswith("Asks for your password and card or bank details.")


@pytest.mark.parametrize(
    "body",
    [
        "Click here to reset your password.",  # a real reset email
        "I changed my password yesterday.",
        "The pin on the board was loose.",  # pin with no request
        "Payment received, thanks.",
    ],
)
def test_sensitive_request_does_not_fire(body):
    assert ft.sensitive_request(make_email(body=body)) == []


# --- Rule 8: risky attachments -------------------------------------------------------


@pytest.mark.parametrize(
    "body, name, severity",
    [
        ("Open the attached Invoice_2291.exe to view.", "Invoice_2291.exe", "high"),
        ("See Payroll.docm and enable content.", "Payroll.docm", "high"),
        ("Your documents are in scan(1).zip", "scan(1).zip", "medium"),
        ("Remittance-Advice.HTML is attached", "Remittance-Advice.HTML", "medium"),
    ],
)
def test_risky_attachment_fires_for_risky_file_names(body, name, severity):
    reasons = ft.risky_attachment(make_email(body=body))
    assert ids(reasons) == ["risky_attachment"]
    assert reasons[0]["severity"] == severity
    assert f"'{name}'" in reasons[0]["message"]


def test_risky_attachment_checks_link_paths_but_not_web_pages():
    download = make_email(links=[("Download", "https://evil.ru/files/update.exe?x=1")])
    assert ft.risky_attachment(download)[0]["severity"] == "high"
    page = make_email(links=[("Read more", "https://example.com/news/story.html")])
    assert ft.risky_attachment(page) == []


def test_risky_attachment_reports_the_most_dangerous_file():
    body = "Unzip files.zip and run setup.exe"
    reason = ft.risky_attachment(make_email(body=body))[0]
    assert reason["severity"] == "high" and "'setup.exe'" in reason["message"]


@pytest.mark.parametrize(
    "body",
    [
        "The report is in report.pdf and notes.docx",
        "Visit example.com for details",  # .com is a domain, not a program
        "We zipped the files",  # no file name
    ],
)
def test_risky_attachment_does_not_fire(body):
    assert ft.risky_attachment(make_email(body=body)) == []


# --- False positives found on the dataset --------------------------------------------


def test_domains_in_text_ignores_paths_like_perl_scripts():
    text = "http://use.perl.org/article.pl?sid=02/09/30"
    assert ft.domains_in_text(text) == ["use.perl.org"]


def test_link_text_mismatch_ignores_newsletter_click_trackers():
    email = make_email(
        links=[
            ("news.com", "http://clickthru.online.com/Click?q=8d-abc"),
            ("brand.com", "https://u123.ct.sendgrid.net/ls/click?upn=xyz"),
        ]
    )
    assert ft.link_text_mismatch(email) == []


def test_risky_attachment_ignores_web_pages_in_urls():
    body = "Read it at xent.com/pipermail/fork/index.html or example.org/a/setup.exe"
    links = [("http://www.example.com/news/story.htm", "http://www.example.com/x")]
    assert ft.risky_attachment(make_email(body=body, links=links)) == []


def test_risky_attachment_ignores_file_names_in_comma_separated_url_paths():
    body = "See www.zdnet.com/anchordesk/stories/story/0,10738,2880386,00.html"
    assert ft.risky_attachment(make_email(body=body)) == []
