import mailbox
from email.message import EmailMessage

from model.src import preprocess as pp


def make_email(
    sender="PayPal <service@paypa1.com>", subject="Hello", plain=None, html=None
):
    msg = EmailMessage()
    msg["From"] = sender
    msg["Subject"] = subject
    if plain is not None:
        msg.set_content(plain)
    if html is not None:
        if plain is None:
            msg.set_content(html, subtype="html")
        else:
            msg.add_alternative(html, subtype="html")
    return msg


# --- extract_fields ------------------------------------------------------------------


def test_extract_fields_reads_sender_subject_and_prefers_html():
    msg = make_email(
        plain="plain version",
        html='<p>Click <a href="http://185.22.10.4/login">paypal.com/login</a></p>',
    )
    fields = pp.extract_fields(msg)
    assert fields["sender_name"] == "PayPal"
    assert fields["sender_email"] == "service@paypa1.com"
    assert fields["subject"] == "Hello"
    assert "Click" in fields["body_text"] and "plain version" not in fields["body_text"]
    assert fields["links"] == [
        {"text": "paypal.com/login", "href": "http://185.22.10.4/login"}
    ]


def test_extract_fields_ignores_attachments():
    msg = make_email(plain="See attached.")
    msg.add_attachment(
        b"secret attachment text", maintype="text", subtype="plain", filename="a.txt"
    )
    assert "secret attachment text" not in pp.extract_fields(msg)["body_text"]


def test_extract_fields_treats_html_sent_as_plain_text_as_html():
    msg = make_email(plain="<html><body><p>Hi there</p></body></html>")
    assert pp.extract_fields(msg)["body_text"].strip() == "Hi there"


def test_extract_fields_falls_back_to_cp1252_for_wrong_charset():
    data = b"From: a@b.com\nSubject: x\nContent-Type: text/plain; charset=utf-8\n\ncaf\xe9\n"
    assert "café" in pp.extract_fields(pp.parse_email_bytes(data))["body_text"]


# --- clean_text / clean_subject / prepare_email --------------------------------------


def test_clean_text_removes_dates_times_and_years():
    text = "Sent Thu, 22 Aug 2002 14:38:22 +0100 (IST), updated 2002-09-30T00:15:00Z"
    assert pp.clean_text(text) == "Sent (IST), updated"
    assert pp.clean_text("Offer ends December 2024 or 12/31/2024") == "Offer ends or"
    assert pp.clean_text("See you Friday at 9:30 pm") == "See you at"


def test_clean_text_keeps_ordinary_words_and_urgency_phrases():
    text = "You may lose access within 24 hours. March forward."
    assert pp.clean_text(text) == text


def test_clean_text_removes_urls_emails_and_invisible_characters():
    text = "Log in at https://paypa1.com/x or write to help@paypa1.com pay​pal"
    assert pp.clean_text(text) == "Log in at or write to paypal"


def test_clean_subject_strips_list_tags_and_reply_prefixes():
    assert pp.clean_subject("Re: [ILUG] Re: Kernel panic") == "Kernel panic"
    assert pp.clean_subject("FWD: [SPAM] Invoice") == "Invoice"
    assert (
        pp.clean_subject("[Action Required] Verify now")
        == "[Action Required] Verify now"
    )


def test_prepare_email_adds_bare_urls_as_links_without_duplicates():
    fields = {
        "sender_name": "Bank",
        "sender_email": "  Alerts@Bank.COM ",
        "subject": "Alert",
        "body_text": "Go to www.bank-secure.co/login now. Or http://bit.ly/x.",
        "links": [{"text": "http://bit.ly/x", "href": "http://bit.ly/x"}],
    }
    out = pp.prepare_email(fields)
    assert out["sender_email"] == "alerts@bank.com"
    assert out["body_text"] == "Go to now. Or"
    assert out["links"] == [
        {"text": "http://bit.ly/x", "href": "http://bit.ly/x"},
        {"text": "www.bank-secure.co/login", "href": "http://www.bank-secure.co/login"},
    ]


# --- Training-only cleaning ----------------------------------------------------------


def fields_with(body, subject="s", sender_name=""):
    return {
        "sender_name": sender_name,
        "sender_email": "x@y.com",
        "subject": subject,
        "body_text": body,
        "links": [],
    }


def test_remove_corpus_artifacts_deletes_anonymised_recipients():
    out = pp.remove_corpus_artifacts(
        fields_with(
            "Dear jose, your jose@monkey.org mailbox at monkey's server.",
            subject="[zzzzteana] hello yyyy",
            sender_name="monkey.org Admin",
        )
    )
    assert "jose" not in out["body_text"] and "monkey" not in out["body_text"]
    assert "zzzz" not in out["subject"] and "yyyy" not in out["subject"]
    assert out["sender_name"].strip() == "Admin"


def test_remove_corpus_artifacts_replaces_recipient_inside_links():
    fields = fields_with("x")
    fields["links"] = [
        {"text": "monkey.org login", "href": "http://evil.co/#jose@monkey.org"},
        {
            "text": "Hello jose",
            "href": "http://Monkey.evil.co/?email=jose%40monkey.org",
        },
    ]
    assert pp.remove_corpus_artifacts(fields)["links"] == [
        {"text": "example.com login", "href": "http://evil.co/#user@example.com"},
        {
            "text": "Hello user",
            "href": "http://example.evil.co/?email=user%40example.com",
        },
    ]


def test_remove_corpus_artifacts_strips_quotes_footers_and_embedded_headers():
    body = (
        "My answer is yes.\n"
        "On Thu, Bob wrote:\n"
        "> the question\n"
        "Date: Not supplied\n"
        "_______________________________________________\n"
        "ILUG mailing list\n"
        "http://www.linux.ie/mailman/listinfo/ilug\n"
    )
    assert pp.remove_corpus_artifacts(fields_with(body))["body_text"].strip() == (
        "My answer is yes."
    )


def test_boilerplate_lines_only_repeated_ham_lines_are_removed():
    signature = "Matthias Saou -- System and Network Engineer"
    template = "Please verify your account to keep access"
    ham = [f"Message {i}\n{signature}" for i in range(pp.BOILERPLATE_MIN_HAM)]
    phishing = [template] * 5
    boilerplate = pp.find_boilerplate_lines(
        ham + phishing, [pp.SAFE] * len(ham) + [pp.PHISHING] * len(phishing)
    )
    assert boilerplate == {signature.lower()}
    assert pp.remove_boilerplate_lines(ham[0], boilerplate) == "Message 0"


# --- load_dataset --------------------------------------------------------------------


def test_load_dataset_skips_placeholders_and_cmds_and_removes_duplicates(tmp_path):
    (tmp_path / "phishing").mkdir()
    box = mailbox.mbox(tmp_path / "phishing" / "phishing-2020")
    placeholder = make_email(
        subject="DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA"
    )
    placeholder["X-IMAP"] = "1736101925 0000000402"
    box.add(placeholder)
    phish = make_email(subject="Account suspended", plain="Verify your password now.")
    box.add(phish)
    box.add(phish)  # duplicate
    box.flush()

    for folder in pp.HAM_FOLDERS:
        (tmp_path / "ham" / folder).mkdir(parents=True)
    ham_dir = tmp_path / "ham" / "easy_ham"
    (ham_dir / "cmds").write_text("mv 00001 00001\n")
    ham = make_email(sender="Bob <bob@example.org>", subject="Lunch?", plain="Pizza?")
    (ham_dir / "00001.abc").write_bytes(ham.as_bytes())

    df, stats = pp.load_dataset(tmp_path)

    assert list(df.columns) == pp.COLUMNS
    assert stats["placeholder"] == 1
    assert stats["duplicates"] == 1
    assert sorted(df["source"]) == ["easy_ham", "nazario-2020"]
    assert df.set_index("source").loc["nazario-2020", "label"] == pp.PHISHING
    assert df.set_index("source").loc["easy_ham", "subject"] == "Lunch?"
