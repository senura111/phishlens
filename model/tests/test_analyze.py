import pytest

from model.src import features, predict
from model.tests.example_emails import EXAMPLES, PHISHING_LOOKALIKE
from model.tests.tiny_model import build_tiny_model


@pytest.fixture(scope="module")
def tiny_model():
    return build_tiny_model()


# --- API contract --------------------------------------------------------------------


def test_analyze_output_matches_the_api_contract(tiny_model):
    result = predict.analyze(PHISHING_LOOKALIKE, model=tiny_model)

    assert set(result) == {"verdict", "score", "reasons"}
    assert result["verdict"] in {"phishing", "suspicious", "safe"}
    assert isinstance(result["score"], float) and 0.0 <= result["score"] <= 1.0
    assert result["score"] == round(result["score"], 2)
    assert result["reasons"], "the lookalike sender should produce reasons"
    for reason in result["reasons"]:
        assert set(reason) == {"id", "severity", "message"}
        assert reason["id"] in [*features.REASON_IDS, predict.PHISHING_LANGUAGE]
        assert reason["severity"] in {"low", "medium", "high"}
        assert isinstance(reason["message"], str) and reason["message"]


def test_analyze_lists_the_most_severe_reasons_first(tiny_model):
    severities = [
        r["severity"]
        for r in predict.analyze(PHISHING_LOOKALIKE, tiny_model)["reasons"]
    ]
    order = {"high": 0, "medium": 1, "low": 2}
    assert severities == sorted(severities, key=order.get)


def test_analyze_accepts_missing_optional_fields(tiny_model):
    result = predict.analyze({"subject": "Lunch?"}, model=tiny_model)
    assert result["verdict"] == "safe" and result["reasons"] == []


def test_load_model_explains_how_to_create_a_missing_model(tmp_path):
    with pytest.raises(FileNotFoundError, match="python -m model.src.train"):
        predict.load_model(tmp_path / "missing.joblib")


# --- Modern example emails, scored by the real trained model -------------------------

needs_trained_model = pytest.mark.skipif(
    not predict.ARTIFACT_PATH.exists(),
    reason="no trained model; run: python -m model.src.train",
)


# Known limitation: the training ham (2002 mailing lists) has no modern transactional
# email, so its wording was only ever seen in phishing. Both still get an amber
# banner, never red. Fix: train on modern receipts, password resets, shipping notices.
KNOWN_WRONG = {
    "password reset": (
        "no modern transactional email in the training ham: reset wording ('your "
        "password', 'account') was only seen in phishing, and the urgency rule fires "
        "on the genuine 'This link expires in 24 hours'"
    ),
    "receipt with PDF invoice": (
        "no modern transactional email in the training ham: receipt wording ('your "
        "order', 'payment', 'invoice') was only seen in phishing; no rule fires"
    ),
}
EXAMPLE_PARAMS = [
    pytest.param(
        name,
        marks=(
            pytest.mark.xfail(reason=KNOWN_WRONG[name], strict=True)
            if name in KNOWN_WRONG
            else ()
        ),
    )
    for name in EXAMPLES
]


@needs_trained_model
@pytest.mark.parametrize("name", EXAMPLE_PARAMS)
def test_example_email_gets_the_expected_verdict(name):
    email, expected = EXAMPLES[name]
    assert predict.analyze(email)["verdict"] == expected


@needs_trained_model
def test_phishing_example_explains_itself():
    ids = {r["id"] for r in predict.analyze(PHISHING_LOOKALIKE)["reasons"]}
    assert {"lookalike_domain", "link_text_mismatch"} <= ids


# --- phishing_language reason --------------------------------------------------------

TEXT_ONLY_PHISHING = {
    "sender_name": "Support",
    "sender_email": "support@example.org",
    "subject": "Verify your account",
    "body_text": "Dear customer, verify your account password now",
    "links": [],
}


def test_flagged_email_gets_a_readable_phishing_language_reason(tiny_model):
    result = predict.analyze(TEXT_ONLY_PHISHING, model=tiny_model)
    assert result["verdict"] != "safe"
    language = [r for r in result["reasons"] if r["id"] == "phishing_language"]
    assert len(language) == 1
    reason = language[0]
    assert reason["severity"] == "low"
    assert reason["message"].startswith("The wording is similar to phishing emails")
    assert reason["message"].endswith("On its own this is a weak sign.")
    assert "brandname" not in reason["message"]


def test_phishing_language_examples_do_not_repeat_words(tiny_model):
    reason = predict.phishing_language_reason(
        tiny_model, "verify your account password now"
    )
    examples = reason["message"].split("(for example ")[1].split(")")[0]
    quoted = [e.strip(" '") for e in examples.split(",")]
    assert 1 <= len(quoted) <= predict.MAX_LANGUAGE_EXAMPLES
    for a in quoted:
        for b in quoted:
            if a != b:
                assert not set(a.split()) <= set(b.split())


def test_safe_email_gets_no_phishing_language_reason(tiny_model):
    result = predict.analyze(
        {"subject": "Lunch", "body_text": "Are we still on for lunch on the patio"},
        model=tiny_model,
    )
    assert result["verdict"] == "safe" and result["reasons"] == []


def test_no_phishing_language_reason_when_wording_points_to_safe(tiny_model):
    assert predict.phishing_language_reason(tiny_model, "lunch on the patio") is None


@needs_trained_model
@pytest.mark.parametrize("name", list(KNOWN_WRONG))
def test_known_wrong_examples_are_amber_never_red(name):
    # The limitation costs an amber banner, not a red one.
    assert predict.analyze(EXAMPLES[name][0])["verdict"] == "suspicious"
