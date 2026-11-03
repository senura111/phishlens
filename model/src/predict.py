"""Public entry point for the model: analyze(email: dict) -> dict.

Input and output follow the API contract in CLAUDE.md: the email fields go in, and
{"verdict": ..., "score": ..., "reasons": [...]} comes out.

This module also holds the scoring pieces train.py uses, so training, evaluation and
the API all turn an email into features and a verdict in exactly the same way.
"""

from __future__ import annotations

import numpy as np
from scipy.sparse import csr_matrix, hstack

PHISHING, SUSPICIOUS, SAFE = "phishing", "suspicious", "safe"
# Starting thresholds from CLAUDE.md.
PHISHING_THRESHOLD = 0.8
SUSPICIOUS_THRESHOLD = 0.5

# Rules that make an email at least "suspicious" whatever its score. Only rules that
# (almost) never fire on legitimate mail qualify: on the test set a floor for every
# high-severity rule turned 3% of safe emails amber and caught no extra phishing.
# ip_link fires too rarely for the model to learn its weight (10 training emails).
FLOOR_RULES = {"ip_link", "homoglyphs"}

RULES_ONLY, TEXT_ONLY, TEXT_AND_RULES = "rules only", "text only", "text + rules"
APPROACHES = (RULES_ONLY, TEXT_ONLY, TEXT_AND_RULES)


def email_text(email: dict) -> str:
    """What the text model reads: subject and body only (see train.py)."""
    return f"{email.get('subject', '')} {email.get('body_text', '')}"


def design_matrix(approach, vectorizer, texts, rule_rows, without_rules=False):
    """The model input for each email.

    texts: one email_text() per email. rule_rows: one features.rule_vector() per email.
    without_rules=True zeroes the rule columns, which shows what the score would be
    from the text alone (used by decide_verdict).
    """
    rules = np.asarray(rule_rows, dtype=float)
    if without_rules:
        rules = np.zeros_like(rules)
    if approach == RULES_ONLY:
        return csr_matrix(rules)
    text = vectorizer.transform(texts)
    if approach == TEXT_ONLY:
        return text
    return hstack([text, csr_matrix(rules)], format="csr")


def decide_verdict(
    score: float, reasons: list[dict], score_without_rules: float
) -> str:
    """Turn a phishing probability into phishing / suspicious / safe.

    One medium-severity rule (e.g. urgency) on its own must not make an email
    "phishing": real companies write "action required" too. "phishing" needs a
    high-severity rule, two or more medium ones, or a text score that reaches the
    phishing threshold without help from the rules. Otherwise it stays "suspicious".

    A FLOOR_RULES reason lifts a low score to "suspicious", never to "phishing".
    """
    if score < SUSPICIOUS_THRESHOLD:
        floor = any(reason["id"] in FLOOR_RULES for reason in reasons)
        return SUSPICIOUS if floor else SAFE
    if score < PHISHING_THRESHOLD:
        return SUSPICIOUS
    severities = [reason["severity"] for reason in reasons]
    at_most_one_medium = "high" not in severities and severities.count("medium") <= 1
    if at_most_one_medium and score_without_rules < PHISHING_THRESHOLD:
        return SUSPICIOUS
    return PHISHING
