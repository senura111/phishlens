import numpy as np
import pytest

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


def test_weight_table_computes_typical_push_for_words_and_rules():
    # Each email three times: the real vectorizer drops words in fewer than 3 emails.
    texts = ["verify your account now", "verify account", "lunch today", "lunch"] * 3
    labels = np.array([1, 1, 0, 0] * 3)
    rule_rows = [[1.0] + [0.0] * 8, [2 / 3] + [0.0] * 8, [0.0] * 9, [0.0] * 9] * 3
    vectorizer, classifier = train.fit(TEXT_AND_RULES, texts, rule_rows, labels)
    x = train.design_matrix(TEXT_AND_RULES, vectorizer, texts, rule_rows)

    table = train.weight_table(vectorizer, classifier, x).set_index("input")

    first_rule = f"rule: {train.features.REASON_IDS[0]}"
    assert len(table) == x.shape[1]
    assert table.loc[first_rule, "emails"] == 6
    assert table.loc[first_rule, "typical value"] == pytest.approx((1 + 2 / 3) / 2)
    assert table.loc[first_rule, "typical push"] == pytest.approx(
        table.loc[first_rule, "weight"] * (1 + 2 / 3) / 2
    )
    assert table.loc["rule: ip_link", "typical push"] == 0  # never fired
    assert table.loc["verify", "weight"] > 0 > table.loc["lunch", "weight"]
    assert table["rank"].min() == 1


def test_saved_approach_is_text_and_rules():
    assert train.SAVED_APPROACH == TEXT_AND_RULES


def test_vectorizer_ignores_the_brand_placeholder():
    # Words must be in 3+ emails (min_df) but not in over 90% of them (max_df).
    texts = ["verify your brandname account now"] * 4 + ["lunch on the patio"]
    vocabulary = train.make_vectorizer().fit(texts).vocabulary_
    assert "brandname" not in vocabulary
    assert "your account" in vocabulary  # word pairs form across the dropped word
