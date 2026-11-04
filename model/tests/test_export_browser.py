import json
import math

import pytest

from model.src import export_browser, features, predict
from model.tests.tiny_model import build_tiny_model


@pytest.fixture(scope="module")
def tiny_model():
    return {**build_tiny_model(), "mask_brands": True}


def score_from_json(exported: dict, text: str, rule_row: list[float]) -> float:
    """Score an email from the exported numbers alone, the way predict.js does."""
    vectorizer = exported["vectorizer"]
    columns = {term: i for i, term in enumerate(vectorizer["vocabulary"])}
    words = [w for w in text.lower().split() if w.isalpha() and len(w) >= 2]
    terms = words + [f"{a} {b}" for a, b in zip(words, words[1:])]
    counts: dict[int, int] = {}
    for term in terms:
        if term in columns:
            counts[columns[term]] = counts.get(columns[term], 0) + 1
    values = {
        j: (math.log(c) + 1) * vectorizer["idf"][j] for j, c in sorted(counts.items())
    }
    length = math.sqrt(sum(v * v for v in values.values())) or 1.0
    classifier = exported["classifier"]
    log_odds = classifier["intercept"]
    log_odds += sum(
        v / length * classifier["text_weights"][j] for j, v in values.items()
    )
    rule_weights = [classifier["rule_weights"][rid] for rid in exported["rule_ids"]]
    log_odds += sum(v * w for v, w in zip(rule_row, rule_weights))
    return 1 / (1 + math.exp(-log_odds))


def test_exported_numbers_reproduce_the_python_score(tiny_model):
    exported = json.loads(json.dumps(export_browser.model_json(tiny_model)))
    text = "dear customer verify your account password now"
    rule_row = [1.0, 0, 0, 0, 0, 0, 2 / 3, 0, 0]
    x = predict.design_matrix(
        predict.TEXT_AND_RULES, tiny_model["vectorizer"], [text], [rule_row]
    )
    python_score = tiny_model["classifier"].predict_proba(x)[0, 1]
    assert score_from_json(exported, text, rule_row) == pytest.approx(
        python_score, abs=1e-12
    )


def test_export_has_one_rule_weight_per_rule(tiny_model):
    exported = export_browser.model_json(tiny_model)
    assert exported["rule_ids"] == features.REASON_IDS
    assert list(exported["classifier"]["rule_weights"]) == features.REASON_IDS
    assert (
        len(exported["vectorizer"]["vocabulary"])
        == len(exported["vectorizer"]["idf"])
        == len(exported["classifier"]["text_weights"])
    )


def test_export_refuses_settings_the_browser_does_not_implement(tiny_model):
    tiny_model["vectorizer"].set_params(ngram_range=(1, 3))
    try:
        with pytest.raises(ValueError, match="ngram_range"):
            export_browser.model_json(tiny_model)
    finally:
        tiny_model["vectorizer"].set_params(ngram_range=(1, 2))


def test_unicode_tables_name_the_lookalike_scripts():
    tables = export_browser.unicode_tables()
    cyrillic_a = 0x0430
    assert any(
        a <= cyrillic_a <= b for a, b in tables["script_name_ranges"]["CYRILLIC"]
    )
    superscript_two = 0xB2  # isdigit() but not a decimal digit
    assert any(a <= superscript_two <= b for a, b in tables["extra_digit_ranges"])


@pytest.mark.skipif(
    not predict.ARTIFACT_PATH.exists(), reason="no trained model to compare with"
)
def test_shipped_model_json_matches_the_trained_model():
    shipped = json.loads((export_browser.OUT_DIR / "model.json").read_text("ascii"))
    exported = json.loads(json.dumps(export_browser.model_json(predict.load_model())))
    assert shipped == exported, "run: python -m model.src.export_browser"
