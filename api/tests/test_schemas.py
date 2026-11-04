import pytest
from pydantic import ValidationError

from api.schemas import AnalyzeRequest, AnalyzeResponse

VALID = {
    "sender_name": "PayPal Support",
    "sender_email": "support@paypa1-secure.com",
    "subject": "Your account will be suspended",
    "body_text": "Confirm your details within 24 hours.",
    "links": [{"text": "paypal.com/login", "href": "http://185.22.10.4/login"}],
    "attachments": ["Invoice_2291.pdf.exe"],
}
REQUIRED = ["sender_name", "sender_email", "subject", "body_text", "links"]


def without(field: str) -> dict:
    return {k: v for k, v in VALID.items() if k != field}


def test_a_full_request_is_accepted():
    assert AnalyzeRequest.model_validate(VALID).model_dump() == VALID


# --- Required means present, not non-empty -------------------------------------------


@pytest.mark.parametrize("field", REQUIRED)
def test_a_missing_required_field_is_rejected(field):
    with pytest.raises(ValidationError, match=field):
        AnalyzeRequest.model_validate(without(field))


@pytest.mark.parametrize(
    "field, empty",
    [("sender_name", ""), ("subject", ""), ("body_text", ""), ("links", [])],
)
def test_an_empty_value_is_accepted(field, empty):
    request = AnalyzeRequest.model_validate({**VALID, field: empty})
    assert getattr(request, field) == empty


def test_an_image_only_email_with_nothing_but_a_sender_is_accepted():
    request = AnalyzeRequest.model_validate(
        {
            "sender_name": "",
            "sender_email": "news@shop.example",
            "subject": "",
            "body_text": "",
            "links": [],
        }
    )
    assert request.attachments == []


def test_an_empty_sender_email_is_rejected():
    with pytest.raises(ValidationError, match="sender_email"):
        AnalyzeRequest.model_validate({**VALID, "sender_email": ""})


@pytest.mark.parametrize("field", REQUIRED)
def test_null_is_not_the_same_as_empty(field):
    with pytest.raises(ValidationError, match=field):
        AnalyzeRequest.model_validate({**VALID, field: None})


# --- Attachments are optional ---------------------------------------------------------


def test_missing_attachments_means_none_known():
    assert AnalyzeRequest.model_validate(without("attachments")).attachments == []


def test_attachments_are_names_only():
    with pytest.raises(ValidationError, match="attachments"):
        AnalyzeRequest.model_validate({**VALID, "attachments": [{"name": "a.exe"}]})


# --- Shape checks ---------------------------------------------------------------------


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError, match="senderEmail"):
        AnalyzeRequest.model_validate({**VALID, "senderEmail": "x@example.com"})


def test_a_link_needs_both_text_and_href():
    with pytest.raises(ValidationError, match="href"):
        AnalyzeRequest.model_validate({**VALID, "links": [{"text": "Click"}]})


def test_numbers_are_not_turned_into_strings():
    with pytest.raises(ValidationError, match="subject"):
        AnalyzeRequest.model_validate({**VALID, "subject": 123})


def test_response_model_accepts_what_analyze_returns():
    response = {
        "verdict": "phishing",
        "score": 0.92,
        "reasons": [
            {"id": "lookalike_domain", "severity": "high", "message": "imitates"}
        ],
    }
    assert AnalyzeResponse.model_validate(response).model_dump() == response


def test_response_model_rejects_an_unknown_verdict():
    with pytest.raises(ValidationError):
        AnalyzeResponse.model_validate(
            {"verdict": "maybe", "score": 0.5, "reasons": []}
        )
