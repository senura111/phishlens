import json
import logging

import pytest

from api import main, schemas
from model.src import predict
from model.tests.example_emails import PHISHING_LOOKALIKE

# The fixtures `client` and `open_client` come from conftest.py.

EMPTY_EMAIL = {
    "sender_name": "",
    "sender_email": "news@shop.example",
    "subject": "",
    "body_text": "",
    "links": [],
}
REQUIRED = ["sender_name", "sender_email", "subject", "body_text", "links"]
# Stands in for email content: tests check it never comes back or reaches the logs.
SENTINEL = "SENTINEL-email-content-7f3a"


def post_raw(client, body: str, content_type="application/json"):
    return client.post(
        "/analyze", content=body.encode(), headers={"Content-Type": content_type}
    )


def has_cors_headers(response) -> bool:
    return any(h.lower().startswith("access-control-") for h in response.headers)


# --- Startup -------------------------------------------------------------------------


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_server_refuses_to_start_without_a_model(monkeypatch, tmp_path, open_client):
    missing = tmp_path / "missing.joblib"
    monkeypatch.setattr(main, "load_model", lambda: predict.load_model(missing))
    with pytest.raises(FileNotFoundError, match="python -m model.src.train"):
        with open_client():
            pass


# --- POST /analyze -------------------------------------------------------------------


def test_analyze_returns_the_api_contract(client):
    response = client.post("/analyze", json=PHISHING_LOOKALIKE)

    assert response.status_code == 200
    result = response.json()
    assert set(result) == {"verdict", "score", "reasons"}
    assert result["verdict"] in {"phishing", "suspicious", "safe"}
    assert 0.0 <= result["score"] <= 1.0
    for reason in result["reasons"]:
        assert set(reason) == {"id", "severity", "message"}


@pytest.mark.skipif(
    not predict.ARTIFACT_PATH.exists(),
    reason="no trained model; run: python -m model.src.train",
)
def test_the_real_model_flags_the_phishing_example(monkeypatch, open_client):
    monkeypatch.setattr(main, "load_model", predict.load_model)
    with open_client() as client:
        result = client.post("/analyze", json=PHISHING_LOOKALIKE).json()
    assert result["verdict"] == "phishing"
    ids = {r["id"] for r in result["reasons"]}
    assert {"lookalike_domain", "link_text_mismatch"} <= ids


# --- Required means present, not non-empty -------------------------------------------


@pytest.mark.parametrize("field", REQUIRED)
def test_a_missing_field_gives_422(client, field):
    email = {k: v for k, v in EMPTY_EMAIL.items() if k != field}
    response = client.post("/analyze", json=email)
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", field]


@pytest.mark.parametrize(
    "field, empty",
    [("sender_name", ""), ("subject", ""), ("body_text", ""), ("links", [])],
)
def test_an_empty_value_is_accepted(client, field, empty):
    email = {**PHISHING_LOOKALIKE, field: empty}
    assert client.post("/analyze", json=email).status_code == 200


def test_an_email_with_every_optional_value_empty_is_accepted(client):
    response = client.post("/analyze", json=EMPTY_EMAIL)
    assert response.status_code == 200
    assert response.json()["verdict"] == "safe"


def test_an_empty_sender_email_gives_422(client):
    response = client.post("/analyze", json={**EMPTY_EMAIL, "sender_email": ""})
    assert response.status_code == 422


def test_attachments_are_optional_and_accepted(client):
    email = {**EMPTY_EMAIL, "attachments": ["Invoice_2291.pdf.exe"]}
    response = client.post("/analyze", json=email)
    assert response.status_code == 200
    assert "risky_attachment" in {r["id"] for r in response.json()["reasons"]}


# --- Length and count caps -----------------------------------------------------------

LINK = {"text": "Shop now", "href": "https://shop.example/"}
# Cap name -> (the cap, a function that makes an email with a value of length n).
CAPS = {
    "sender_name": (
        schemas.MAX_SENDER_NAME,
        lambda n: {**EMPTY_EMAIL, "sender_name": "a" * n},
    ),
    "sender_email": (
        schemas.MAX_SENDER_EMAIL,
        lambda n: {**EMPTY_EMAIL, "sender_email": "a" * (n - 6) + "@x.com"},
    ),
    "subject": (
        schemas.MAX_SUBJECT,
        lambda n: {**EMPTY_EMAIL, "subject": "a" * n},
    ),
    "link text": (
        schemas.MAX_LINK_TEXT,
        lambda n: {**EMPTY_EMAIL, "links": [{**LINK, "text": "a" * n}]},
    ),
    "link href": (
        schemas.MAX_LINK_HREF,
        lambda n: {
            **EMPTY_EMAIL,
            "links": [{**LINK, "href": LINK["href"] + "a" * (n - 21)}],
        },
    ),
    "attachment name": (
        schemas.MAX_ATTACHMENT_NAME,
        lambda n: {**EMPTY_EMAIL, "attachments": ["a" * (n - 4) + ".pdf"]},
    ),
    "number of links": (
        schemas.MAX_LINKS,
        lambda n: {**EMPTY_EMAIL, "links": [LINK] * n},
    ),
    "number of attachments": (
        schemas.MAX_ATTACHMENTS,
        lambda n: {**EMPTY_EMAIL, "attachments": ["photo.jpg"] * n},
    ),
}


@pytest.mark.parametrize("cap", CAPS)
def test_a_value_at_the_cap_is_accepted(client, cap):
    limit, make_email = CAPS[cap]
    assert client.post("/analyze", json=make_email(limit)).status_code == 200


@pytest.mark.parametrize("cap", CAPS)
def test_one_over_the_cap_gives_422(client, cap):
    limit, make_email = CAPS[cap]
    assert client.post("/analyze", json=make_email(limit + 1)).status_code == 422


def test_caps_measure_the_values_they_claim_to():
    # Guards the CAPS helpers above: each makes a value exactly n long.
    assert len(CAPS["sender_email"][1](254)["sender_email"]) == 254
    assert len(CAPS["link href"][1](2048)["links"][0]["href"]) == 2048
    assert len(CAPS["attachment name"][1](255)["attachments"][0]) == 255


def test_an_unknown_field_gives_422(client):
    response = client.post("/analyze", json={**EMPTY_EMAIL, "senderEmail": "x@y.z"})
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "senderEmail"]


# --- Email content is never echoed back or logged ------------------------------------


def test_422_keeps_location_and_message_but_not_the_sent_value(client):
    email = {**EMPTY_EMAIL, "links": SENTINEL, "extra": SENTINEL}
    response = client.post("/analyze", json=email)

    assert response.status_code == 422
    assert SENTINEL not in response.text
    errors = response.json()["detail"]
    assert {tuple(e["loc"]) for e in errors} == {("body", "links"), ("body", "extra")}
    for error in errors:
        assert set(error) == {"loc", "msg", "type"}
        assert error["msg"]


def test_422_for_broken_json_does_not_echo_it(client):
    response = post_raw(client, '{"subject": "' + SENTINEL)
    assert response.status_code == 422
    assert SENTINEL not in response.text


def test_an_error_in_analyze_gives_a_generic_500_and_logs_only_its_type(
    client, monkeypatch, caplog
):
    def broken_analyze(email, model):
        raise ValueError(f"could not parse {email['body_text']}")

    monkeypatch.setattr(main, "analyze", broken_analyze)
    caplog.set_level(logging.DEBUG)

    response = client.post("/analyze", json={**EMPTY_EMAIL, "body_text": SENTINEL})

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert SENTINEL not in response.text
    assert SENTINEL not in caplog.text
    assert "ValueError" in caplog.text


# --- Request limits ------------------------------------------------------------------


def test_a_body_of_exactly_100_kb_is_accepted(client):
    body = json.dumps({**EMPTY_EMAIL, "body_text": ""})
    padding = main.MAX_BODY_BYTES - len(body.encode())
    body = json.dumps({**EMPTY_EMAIL, "body_text": "x" * padding})
    assert len(body.encode()) == main.MAX_BODY_BYTES
    assert post_raw(client, body).status_code == 200


def test_a_body_over_100_kb_gives_413(client):
    email = {**EMPTY_EMAIL, "body_text": "x" * main.MAX_BODY_BYTES}
    assert client.post("/analyze", json=email).status_code == 413


def test_a_chunked_body_without_content_length_gives_411(client):
    chunks = iter([json.dumps(EMPTY_EMAIL).encode()])
    response = client.post(
        "/analyze", content=chunks, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 411


# --- Protection from other websites --------------------------------------------------


@pytest.mark.parametrize(
    "content_type",
    ["text/plain", "text/plain;charset=UTF-8", "application/x-www-form-urlencoded"],
)
def test_a_post_a_webpage_can_send_without_preflight_gives_415(client, content_type):
    # Browsers send these cross-site without asking the server first (no CORS
    # preflight), so a webpage could send them; only JSON is accepted.
    response = post_raw(client, json.dumps(EMPTY_EMAIL), content_type)
    assert response.status_code == 415


def test_a_request_for_another_host_gives_400(client):
    response = client.get("/health", headers={"Host": "evil.com"})
    assert response.status_code == 400


@pytest.mark.parametrize("host", ["127.0.0.1:8000", "localhost:8000", "localhost"])
def test_requests_for_this_machine_are_accepted(client, host):
    assert client.get("/health", headers={"Host": host}).status_code == 200


def test_a_cross_origin_post_gets_no_cors_headers(client):
    response = client.post(
        "/analyze", json=EMPTY_EMAIL, headers={"Origin": "https://evil.example"}
    )
    # The server may answer, but without CORS headers the browser hides the answer
    # from the webpage.
    assert not has_cors_headers(response)


def test_a_cors_preflight_is_refused(client):
    response = client.options(
        "/analyze",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 405
    assert not has_cors_headers(response)
