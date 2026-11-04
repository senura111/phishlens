"""A small model trained on the spot, so tests don't need the real model file (which
isn't in git). Used by the model's tests and the API's tests."""

import numpy as np

from model.src import features, predict, train


def build_tiny_model() -> dict:
    phishing = [
        f"Dear customer, verify your account password now or it will be suspended {i}"
        for i in range(15)
    ]
    safe = [
        f"Are we still on for lunch on the patio with the team {i}" for i in range(15)
    ]
    texts = phishing + safe
    labels = np.array([1] * 15 + [0] * 15)
    rule_rows = [[0.0] * len(features.REASON_IDS)] * 30
    vectorizer, classifier = train.fit(predict.TEXT_AND_RULES, texts, rule_rows, labels)
    return {
        "approach": predict.TEXT_AND_RULES,
        "vectorizer": vectorizer,
        "classifier": classifier,
        "rule_ids": features.REASON_IDS,
    }
