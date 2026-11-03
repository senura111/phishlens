import numpy as np

from model.src import train
from model.src.predict import RULES_ONLY, TEXT_AND_RULES, TEXT_ONLY


def test_campaign_groups_puts_near_duplicates_together():
    texts = [
        "Your USAA account is locked, sign in to verify your identity today",
        "Your USAA account is locked, sign in to verify your identity now",
        "Lunch at the Thai place on Friday with the whole team?",
        "The kernel patch fixes the scheduler bug in the network driver",
    ]
    groups = train.campaign_groups(texts)
    assert groups[0] == groups[1]
    assert len({groups[0], groups[2], groups[3]}) == 3


def test_campaign_groups_chains_similar_emails():
    base = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu"
    words = base.split()
    a = " ".join(words)
    b = " ".join(words[:-1] + ["nu"])  # one word changed from a
    c = " ".join(words[:-2] + ["xi", "nu"])  # one more word changed from b
    groups = train.campaign_groups([a, b, c], threshold=0.7)
    assert groups[0] == groups[1] == groups[2]


def test_fit_and_predict_all_three_approaches():
    phishing = [f"verify your password now account locked {i}" for i in range(20)]
    safe = [f"lunch on the patio with the team {i}" for i in range(20)]
    texts = phishing + safe
    labels = np.array([1] * 20 + [0] * 20)
    rule_rows = [[1.0, 0.0]] * 20 + [[0.0, 0.0]] * 20
    reasons = [[{"id": "x", "severity": "high", "message": ""}]] * 20 + [[]] * 20

    for approach in (RULES_ONLY, TEXT_ONLY, TEXT_AND_RULES):
        vectorizer, classifier = train.fit(approach, texts, rule_rows, labels)
        _, verdicts = train.predict_verdicts(
            approach, vectorizer, classifier, texts, rule_rows, reasons
        )
        result = train.summarise(labels, verdicts)
        assert result["f1"] == 1.0, approach


def test_summarise_counts_suspicious_as_flagged():
    result = train.summarise(np.array([1, 0]), ["suspicious", "safe"])
    assert result["confusion"].tolist() == [[1, 0], [0, 1]]
    assert result["precision"] == 1.0 and result["recall"] == 1.0
