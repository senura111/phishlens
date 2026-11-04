"""Inputs built to make the analysis slow ("ReDoS": regular expression denial of
service) must still be analysed quickly.

Some regexes used to retry a match from every position of a long run of characters,
and each attempt scanned to the end of the run. The time grew with the square of the
run's length: 100 KB of "1.1.1.1..." took over 30 seconds. An attacker could send
such an email to hang the analysis.

Each pattern below is sent at the largest size the API accepts, in every field, and
must be analysed in under BUDGET_SECONDS. On a normal machine each takes about 0.1
second or less, so the budget leaves plenty of room for a slow machine.
"""

import json
import time

import pytest

from api import main, schemas

BUDGET_SECONDS = 1.0

# Pattern name -> the text repeated to fill a field.
PATTERNS = {
    "letters": "x",  # _FILE_NAME_RE, _PATH_WORD_RE, _NAME_EMAIL_RE
    "letters and brackets": "x(",
    "letter dot": "a.",  # EMAIL_RE
    "digit dot": "1.",  # EMAIL_RE (the slowest: over 30 seconds for 100 KB)
    "hyphenated dot": "a-b.",  # EMAIL_RE
    "dashes": "-",
    "dots": ".",
    "spaces": " ",
    "slashes": "/",
    "letter at": "a@",
    "www dot": "www.",
    "http scheme": "http://",
    "newlines": "\n",
    "letter newline": "x\n",
    "cyrillic letters": chr(0x430),  # looks like a Latin "a"; slow in sender names
    "urgency phrase": "within 24 ",
    "password word": "password ",
}

BASE_EMAIL = {
    "sender_name": "Shop",
    "sender_email": "news@shop.example",
    "subject": "Hello",
    "body_text": "Hi",
    "links": [],
}
BASE_LINK = {"text": "Shop now", "href": "https://shop.example/"}


def json_size(value) -> int:
    """Bytes the value takes in a request body."""
    return len(json.dumps(value, ensure_ascii=False).encode())


def repeat_to(pattern: str, length: int) -> str:
    return (pattern * (length // len(pattern) + 1))[:length]


def fill_body(pattern: str) -> dict:
    """body_text as long as the 100 KB request limit allows."""
    room = main.MAX_BODY_BYTES - json_size({**BASE_EMAIL, "body_text": ""})
    repeats = room // (json_size(pattern) - 2)  # - 2: the quotes around a string
    return {**BASE_EMAIL, "body_text": pattern * repeats}


def fill_links(link: dict) -> dict:
    """As many copies of the link as fit in 100 KB (and the link count cap)."""
    room = main.MAX_BODY_BYTES - json_size(BASE_EMAIL)
    count = min(room // (json_size(link) + 2), schemas.MAX_LINKS)  # + 2: ", "
    return {**BASE_EMAIL, "links": [link] * count}


# Field -> a function that puts the pattern in that field at its largest size.
FIELDS = {
    "sender_name": lambda p: {
        **BASE_EMAIL,
        "sender_name": repeat_to(p, schemas.MAX_SENDER_NAME),
    },
    "sender_email": lambda p: {
        **BASE_EMAIL,
        "sender_email": repeat_to(p, schemas.MAX_SENDER_EMAIL),
    },
    "subject": lambda p: {**BASE_EMAIL, "subject": repeat_to(p, schemas.MAX_SUBJECT)},
    "body_text": fill_body,
    "link text": lambda p: fill_links(
        {**BASE_LINK, "text": repeat_to(p, schemas.MAX_LINK_TEXT)}
    ),
    "link href": lambda p: fill_links(
        {**BASE_LINK, "href": repeat_to(p, schemas.MAX_LINK_HREF)}
    ),
    "link href after https://": lambda p: fill_links(
        {**BASE_LINK, "href": "https://" + repeat_to(p, schemas.MAX_LINK_HREF - 8)}
    ),
    "attachment names": lambda p: {
        **BASE_EMAIL,
        "attachments": [repeat_to(p, schemas.MAX_ATTACHMENT_NAME)]
        * schemas.MAX_ATTACHMENTS,
    },
}


def test_the_fillers_make_requests_just_under_the_limit():
    for field in ("body_text", "link href"):
        size = json_size(FIELDS[field]("1."))
        assert main.MAX_BODY_BYTES - 2_100 < size <= main.MAX_BODY_BYTES


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("pattern", PATTERNS)
def test_slow_input_is_analysed_within_budget(client, pattern, field):
    email = FIELDS[field](PATTERNS[pattern])
    body = json.dumps(email, ensure_ascii=False).encode()
    assert len(body) <= main.MAX_BODY_BYTES

    start = time.perf_counter()
    response = client.post(
        "/analyze", content=body, headers={"Content-Type": "application/json"}
    )
    took = time.perf_counter() - start

    assert response.status_code == 200, "the request must reach the model"
    assert took < BUDGET_SECONDS, f"took {took:.2f} s"
