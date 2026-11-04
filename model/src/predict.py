"""Public entry point for the model: analyze(email: dict) -> dict.

Input and output follow the API contract in CLAUDE.md: the email fields go in, and
{"verdict": ..., "score": ..., "reasons": [...]} comes out.

This module also holds the scoring pieces train.py uses, so training, evaluation and
the API all turn an email into features and a verdict in exactly the same way.

Example (from the repo root, after `python -m model.src.train`):

    from model.src.predict import analyze
    analyze({"sender_name": "PayPal", "sender_email": "x@paypa1.com", ...})
"""

from __future__ import annotations

import re
from pathlib import Path

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack

from model.src import features, preprocess

ARTIFACT_PATH = Path(__file__).resolve().parents[1] / "artifacts" / "phishlens.joblib"

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


# Brand names in the text the model reads are replaced by one placeholder word. In the
# training data brands like PayPal, Dropbox or USAA appear almost only in phishing, so
# the model would learn "PayPal mentioned = phishing" and flag real PayPal email.
# The rules still see the real names (lookalike_domain uses features.BRANDS).
BRAND_TOKEN = "brandname"
_BRAND_NAMES = sorted(
    {*features.BRANDS, "bank of america", "wells fargo", "office 365", "pay pal"},
    key=len,
    reverse=True,  # longest first, so "bank of america" wins over shorter matches
)
_BRAND_RE = re.compile(
    r"\b(?:"
    + "|".join(r"\s+".join(map(re.escape, name.split())) for name in _BRAND_NAMES)
    + r")\b",
    re.IGNORECASE,
)


def mask_brands(text: str) -> str:
    return _BRAND_RE.sub(BRAND_TOKEN, text)


def email_text(email: dict, mask_brand_names: bool = False) -> str:
    """What the text model reads: subject and body only (see train.py)."""
    text = f"{email.get('subject', '')} {email.get('body_text', '')}"
    return mask_brands(text) if mask_brand_names else text


def design_matrix(approach, vectorizer, texts, rule_rows):
    """The model input for each email.

    texts: one email_text() per email. rule_rows: one features.rule_vector() per email.
    """
    rules = csr_matrix(np.asarray(rule_rows, dtype=float))
    if approach == RULES_ONLY:
        return rules
    text = vectorizer.transform(texts)
    if approach == TEXT_ONLY:
        return text
    return hstack([text, rules], format="csr")


def decide_verdict(score: float, reasons: list[dict]) -> str:
    """Turn a phishing probability into phishing / suspicious / safe.

    reasons: the rule results only (features.find_reasons), not phishing_language.

    Red ("phishing") needs a score of at least PHISHING_THRESHOLD *and* a strong
    rule-based reason: at least one high-severity rule, or two different
    medium-severity rules. Otherwise the most an email can get is "suspicious" (amber):
    - The text model alone can't make an email red. It has only seen phishing use
      words like "your order" and "invoice" (the training ham has no receipts), so on
      its own it can't tell a real receipt from a fake one.
    - One medium rule can't either, however confident the text model is: real
      password resets say "this link expires in 24 hours" too.

    A FLOOR_RULES reason lifts a low score to "suspicious", never to "phishing".
    """
    if score < SUSPICIOUS_THRESHOLD:
        floor = any(reason["id"] in FLOOR_RULES for reason in reasons)
        return SUSPICIOUS if floor else SAFE
    if score < PHISHING_THRESHOLD:
        return SUSPICIOUS
    high = any(reason["severity"] == "high" for reason in reasons)
    mediums = {reason["id"] for reason in reasons if reason["severity"] == "medium"}
    return PHISHING if high or len(mediums) >= 2 else SUSPICIOUS


# --- analyze() -----------------------------------------------------------------------

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
_loaded_model: dict | None = None

PHISHING_LANGUAGE = "phishing_language"
MAX_LANGUAGE_EXAMPLES = 3


def phishing_language_reason(model: dict, text: str) -> dict | None:
    """Explain a flag that comes from the wording: name the words or phrases in this
    email that pushed the text model's score toward phishing the most.

    Returns None when there's no text model, or when the wording overall points
    toward safe (then the flag came from the rules, and the reason would mislead).
    Low severity: wording alone is a weak sign.
    """
    vectorizer = model.get("vectorizer")
    if vectorizer is None:
        return None
    x = vectorizer.transform([text])
    weights = model["classifier"].coef_[0][: x.shape[1]]  # text columns come first
    names = vectorizer.get_feature_names_out()
    pushes = {names[j]: x[0, j] * weights[j] for j in x.indices}
    if sum(pushes.values()) <= 0:
        return None

    examples: list[str] = []
    for phrase, push in sorted(pushes.items(), key=lambda item: -item[1]):
        if push <= 0 or len(examples) == MAX_LANGUAGE_EXAMPLES:
            break
        words = set(phrase.split())
        if BRAND_TOKEN in words:
            continue  # the placeholder means nothing to a reader
        # Skip "your" when "your account" is already listed, and the other way round.
        if any(words <= set(e.split()) or set(e.split()) <= words for e in examples):
            continue
        examples.append(phrase)
    if not examples:
        return None
    quoted = ", ".join(f"'{e}'" for e in examples)
    return features.make_reason(
        PHISHING_LANGUAGE,
        features.LOW,
        f"The wording is similar to phishing emails (for example {quoted}). "
        "On its own this is a weak sign.",
    )


def load_model(path: Path = ARTIFACT_PATH) -> dict:
    """Load the model saved by train.py.

    joblib files are pickles, and loading a pickle can run code, so only ever load a
    model file you created yourself, never one downloaded from somewhere.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"No trained model at {path}. Train one first: python -m model.src.train"
        )
    model = joblib.load(path)
    if model["rule_ids"] != features.REASON_IDS:
        raise ValueError(
            "The saved model was trained with different rules; retrain it."
        )
    return model


def analyze(email: dict, model: dict | None = None) -> dict:
    """Analyse one email from Gmail and return the API response.

    email: the request body of POST /analyze (sender_name, sender_email, subject,
    body_text, links, and optionally attachments). Missing fields count as empty.
    model: a load_model() result; by default the saved model, loaded once.

    Returns {"verdict": "phishing" | "suspicious" | "safe", "score": 0.0-1.0,
    "reasons": [{"id", "severity", "message"}, ...]}, most severe reasons first.
    The score is the model's probability. The verdict usually follows the thresholds,
    except where decide_verdict() caps it (red needs a high rule or two medium
    ones) or lifts it (FLOOR_RULES). A flagged email also gets a
    "phishing_language" reason when its wording points toward phishing, so even an
    amber banner from the text alone says why.
    """
    global _loaded_model
    if model is None:
        if _loaded_model is None:
            _loaded_model = load_model()
        model = _loaded_model

    cleaned = preprocess.prepare_email(email)
    reasons = features.find_reasons(cleaned)
    # Mask brand names only if the model was trained that way.
    texts = [email_text(cleaned, model.get("mask_brands", False))]
    rule_rows = [features.rule_vector(reasons)]

    x = design_matrix(model["approach"], model["vectorizer"], texts, rule_rows)
    score = float(model["classifier"].predict_proba(x)[0, 1])
    verdict = decide_verdict(score, reasons)
    if verdict != SAFE and (language := phishing_language_reason(model, texts[0])):
        reasons = [*reasons, language]  # added after the verdict: it isn't a rule
    reasons = sorted(reasons, key=lambda r: _SEVERITY_ORDER[r["severity"]])
    return {
        "verdict": verdict,
        "score": round(score, 2),
        "reasons": [
            {"id": r["id"], "severity": r["severity"], "message": r["message"]}
            for r in reasons
        ],
    }
