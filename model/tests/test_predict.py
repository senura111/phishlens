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
    assert pr.decide_verdict(score, [], score_without_rules=score) == verdict


def test_one_medium_rule_alone_cannot_make_an_email_phishing():
    # The rules pushed a borderline text score (0.6) up to 0.95.
    assert pr.decide_verdict(0.95, [URGENCY], score_without_rules=0.6) == "suspicious"


def test_phishing_when_text_alone_is_already_over_the_threshold():
    assert pr.decide_verdict(0.95, [URGENCY], score_without_rules=0.85) == "phishing"


def test_phishing_with_a_high_rule_or_two_medium_rules():
    assert pr.decide_verdict(0.95, [LOOKALIKE], score_without_rules=0.3) == "phishing"
    assert (
        pr.decide_verdict(0.95, [URGENCY, SHORTENER], score_without_rules=0.3)
        == "phishing"
    )


def test_design_matrix_shapes_and_without_rules():
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
    no_rules = pr.design_matrix(
        pr.TEXT_AND_RULES, vectorizer, texts, rules, without_rules=True
    )
    assert no_rules[:, n_words:].nnz == 0


def test_email_text_is_subject_and_body_only():
    email = {"sender_name": "PayPal", "subject": "Hi", "body_text": "there"}
    assert pr.email_text(email) == "Hi there"
