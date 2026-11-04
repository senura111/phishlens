import pytest
from sklearn.feature_extraction.text import TfidfVectorizer

from model.src import predict as pr

URGENCY = {"id": "urgency", "severity": "medium", "message": "..."}
SHORTENER = {"id": "url_shortener", "severity": "medium", "message": "..."}
LOOKALIKE = {"id": "lookalike_domain", "severity": "high", "message": "..."}


@pytest.mark.parametrize(
    "score, verdict",
    [(0.1, "safe"), (0.49, "safe"), (0.5, "suspicious"), (0.79, "suspicious")],
)
def test_decide_verdict_uses_the_thresholds(score, verdict):
    assert pr.decide_verdict(score, []) == verdict


def test_one_medium_rule_alone_cannot_make_an_email_phishing():
    assert pr.decide_verdict(0.95, [URGENCY]) == "suspicious"


def test_phishing_with_a_high_rule_or_two_medium_rules():
    assert pr.decide_verdict(0.95, [LOOKALIKE]) == "phishing"
    assert pr.decide_verdict(0.95, [URGENCY, SHORTENER]) == "phishing"


def test_design_matrix_shapes():
    texts = ["verify your account", "lunch on friday"]
    rules = [[1.0, 0.0], [0.0, 0.0]]
    vectorizer = TfidfVectorizer().fit(texts)
    n_words = len(vectorizer.vocabulary_)

    assert pr.design_matrix(pr.RULES_ONLY, None, texts, rules).shape == (2, 2)
    assert pr.design_matrix(pr.TEXT_ONLY, vectorizer, texts, rules).shape == (
        2,
        n_words,
    )
    combined = pr.design_matrix(pr.TEXT_AND_RULES, vectorizer, texts, rules)
    assert combined.shape == (2, n_words + 2)
    assert combined[0, n_words] == 1.0


def test_email_text_is_subject_and_body_only():
    email = {"sender_name": "PayPal", "subject": "Hi", "body_text": "there"}
    assert pr.email_text(email) == "Hi there"


# --- Floor rules: ip_link and homoglyphs ---------------------------------------------

IP_LINK = {"id": "ip_link", "severity": "high", "message": "..."}
HOMOGLYPHS = {"id": "homoglyphs", "severity": "high", "message": "..."}


@pytest.mark.parametrize("reason", [IP_LINK, HOMOGLYPHS])
def test_floor_rule_lifts_a_low_score_to_suspicious(reason):
    assert pr.decide_verdict(0.05, [reason]) == "suspicious"


@pytest.mark.parametrize("reason", [IP_LINK, HOMOGLYPHS])
def test_floor_rule_never_goes_straight_to_phishing(reason):
    # A low or borderline score stays suspicious; only the model can reach phishing.
    assert pr.decide_verdict(0.05, [reason]) != "phishing"
    assert pr.decide_verdict(0.6, [reason]) == "suspicious"


def test_other_high_severity_rules_do_not_lift_a_low_score():
    assert pr.decide_verdict(0.05, [LOOKALIKE]) == "safe"


def test_floor_rules_are_only_ip_link_and_homoglyphs():
    assert pr.FLOOR_RULES == {"ip_link", "homoglyphs"}


# --- No red without a reason ---------------------------------------------------------


@pytest.mark.parametrize("score", [0.8, 0.95, 1.0])
def test_text_alone_can_make_an_email_amber_at_most(score):
    # No rule fired: however sure the text model is, the banner stays amber.
    assert pr.decide_verdict(score, []) == "suspicious"


def test_red_needs_at_least_one_rule():
    assert pr.decide_verdict(0.95, [LOOKALIKE]) == "phishing"


def test_no_reason_low_score_is_still_safe():
    assert pr.decide_verdict(0.2, []) == "safe"


# --- Brand masking -------------------------------------------------------------------


def test_mask_brands_replaces_brand_names_with_one_placeholder():
    text = "Your PayPal and Dropbox accounts at Bank of America"
    assert pr.mask_brands(text) == "Your brandname and brandname accounts at brandname"


def test_mask_brands_only_matches_whole_words():
    assert pr.mask_brands("paypalsecure upsetting pineapples") == (
        "paypalsecure upsetting pineapples"
    )


def test_email_text_masks_brands_only_when_asked():
    email = {"subject": "PayPal receipt", "body_text": "Thanks"}
    assert pr.email_text(email) == "PayPal receipt Thanks"
    assert pr.email_text(email, mask_brand_names=True) == "brandname receipt Thanks"


def test_brand_masking_does_not_affect_the_rules():
    from model.src import features

    email = {"sender_email": "service@paypa1-secure.com", "links": []}
    assert features.lookalike_domain(email)[0]["message"].endswith(
        "imitates paypal.com"
    )


# --- Red needs a high-severity rule or two different medium ones ---------------------

DISPLAY_NAME = {"id": "sender_name_mismatch", "severity": "medium", "message": "..."}


@pytest.mark.parametrize("score", [0.85, 0.95, 1.0])
def test_one_medium_rule_with_a_confident_score_stays_amber(score):
    # e.g. a real password reset: "this link expires in 24 hours" + reset wording.
    assert pr.decide_verdict(score, [URGENCY]) == "suspicious"


def test_two_different_medium_rules_make_it_red():
    assert pr.decide_verdict(0.9, [URGENCY, DISPLAY_NAME]) == "phishing"


def test_the_same_medium_rule_twice_counts_once():
    assert pr.decide_verdict(0.9, [URGENCY, URGENCY]) == "suspicious"


def test_one_high_rule_makes_it_red():
    assert pr.decide_verdict(0.9, [LOOKALIKE]) == "phishing"


@pytest.mark.parametrize("reasons", [[LOOKALIKE], [URGENCY, DISPLAY_NAME]])
def test_red_still_needs_the_phishing_threshold(reasons):
    assert pr.decide_verdict(0.79, reasons) == "suspicious"
