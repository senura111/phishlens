"""Export what the browser-only extension needs from Python (Phase 5).

The extension analyses emails in JavaScript (extension/analyzer/), with the same rules
and the same trained model as predict.analyze(). This script writes the data it needs
into extension/analyzer/generated/:

- model.json: the trained model. TF-IDF vocabulary and IDF values, the Logistic
  Regression weights for every word column and every rule column, and the intercept.
- public-suffixes.js: the Public Suffix List exactly as the publicsuffixlist package
  parsed it, so registrable_domain() gives the same answers in both languages.
- unicode-tables.js: two Unicode facts JavaScript can't look up on its own (Unicode
  character names, and which characters str.isdigit() accepts).

Run from the repo root after training:  python -m model.src.export_browser
Then regenerate the golden fixtures and run the JS tests (see CLAUDE.md, Phase 5).

Numbers are written with Python's repr (the shortest text that reads back as exactly
the same float), so JavaScript's JSON.parse gets bit-for-bit the same weights.
Everything is written as ASCII: non-ASCII text (some vocabulary words, internationalised
domain names) becomes \\uXXXX escapes, so no invisible characters end up in the files.
"""

from __future__ import annotations

import itertools
import json

import sys
import unicodedata
from pathlib import Path

import publicsuffixlist
import sklearn

from model.src import features
from model.src.predict import BRAND_TOKEN, TEXT_AND_RULES, load_model
from model.src.train import LETTER_WORDS

OUT_DIR = Path(__file__).resolve().parents[2] / "extension" / "analyzer" / "generated"
FORMAT_VERSION = 1

# The TF-IDF settings extension/analyzer/predict.js implements. If training changes
# one of them, the export stops instead of writing a model the browser would misread.
EXPECTED_VECTORIZER = {
    "analyzer": "word",
    "binary": False,
    "lowercase": True,
    "max_features": None,
    "ngram_range": (1, 2),
    "norm": "l2",
    "preprocessor": None,
    "smooth_idf": True,
    "stop_words": [BRAND_TOKEN],
    "strip_accents": None,
    "sublinear_tf": True,
    "token_pattern": LETTER_WORDS,
    "tokenizer": None,
    "use_idf": True,
}


def check_model(model: dict) -> None:
    if model["approach"] != TEXT_AND_RULES:
        raise ValueError(f"Only '{TEXT_AND_RULES}' models can be exported.")
    params = model["vectorizer"].get_params()
    for name, expected in EXPECTED_VECTORIZER.items():
        if params[name] != expected:
            raise ValueError(
                f"The vectorizer's {name} is {params[name]!r}, but the browser "
                f"analyser implements {expected!r}. Update extension/analyzer/ first."
            )
    if list(model["classifier"].classes_) != [0, 1]:
        raise ValueError("Expected classes [0, 1] (safe, phishing).")


def model_json(model: dict) -> dict:
    """The model as plain lists and numbers, in column order."""
    check_model(model)
    vectorizer, classifier = model["vectorizer"], model["classifier"]
    vocabulary = [str(term) for term in vectorizer.get_feature_names_out()]
    weights = [float(w) for w in classifier.coef_[0]]
    text_weights, rule_weights = weights[: len(vocabulary)], weights[len(vocabulary) :]
    if len(rule_weights) != len(features.REASON_IDS):
        raise ValueError("Expected one rule column per features.REASON_IDS entry.")
    return {
        "format": "phishlens-browser-model",
        "format_version": FORMAT_VERSION,
        "sklearn_version": sklearn.__version__,
        "approach": model["approach"],
        "mask_brands": bool(model.get("mask_brands", False)),
        "test_metrics": model.get("test_metrics", {}),
        "rule_ids": list(features.REASON_IDS),
        "vectorizer": {
            "token_pattern": LETTER_WORDS,
            "ngram_range": [1, 2],
            "stop_words": [BRAND_TOKEN],
            "sublinear_tf": True,
            "norm": "l2",
            # Column i of the model is vocabulary[i], with IDF value idf[i].
            "vocabulary": vocabulary,
            "idf": [float(v) for v in vectorizer.idf_],
        },
        "classifier": {
            "intercept": float(classifier.intercept_[0]),
            "text_weights": text_weights,
            # By rule id; the rule columns come after the word columns.
            "rule_weights": dict(zip(features.REASON_IDS, rule_weights)),
        },
    }


def _ranges(code_points: list[int]) -> list[list[int]]:
    """[1, 2, 3, 7] -> [[1, 3], [7, 7]]"""
    groups = itertools.groupby(enumerate(code_points), lambda pair: pair[1] - pair[0])
    out = []
    for _, group in groups:
        group = list(group)
        out.append([group[0][1], group[-1][1]])
    return out


def unicode_tables() -> dict:
    """What features._script() and str.isdigit() need, as code point ranges.

    _script() reads the first word of a character's Unicode name ("CYRILLIC SMALL
    LETTER A"). JavaScript has no character names, and its Script property disagrees
    with the names for a few hundred letters, so the names are exported. Only the
    three scripts the homoglyph rule compares are needed.
    """
    scripts: dict[str, list[int]] = {"LATIN": [], "GREEK": [], "CYRILLIC": []}
    extra_digits = []
    for code_point in range(0x80, sys.maxunicode + 1):
        char = chr(code_point)
        first_word = unicodedata.name(char, "").split(" ")[0]
        if first_word in scripts:
            scripts[first_word].append(code_point)
        if char.isdigit() and unicodedata.category(char) != "Nd":
            extra_digits.append(code_point)
    return {
        "unicode_version": unicodedata.unidata_version,
        "script_name_ranges": {name: _ranges(cps) for name, cps in scripts.items()},
        "extra_digit_ranges": _ranges(extra_digits),
    }


def _ascii_json(value) -> str:
    return json.dumps(value, ensure_ascii=True)


def write_unicode_tables(path: Path) -> None:
    tables = unicode_tables()
    lines = [
        "// Generated by model/src/export_browser.py. Do not edit; rerun the script.",
        f"// From Python's unicodedata, Unicode {tables['unicode_version']}.",
        "",
        "// Code point ranges [first, last] of non-ASCII characters whose Unicode name",
        '// starts with LATIN, GREEK or CYRILLIC ("CYRILLIC SMALL LETTER A").',
        "export const SCRIPT_NAME_RANGES = {",
    ]
    for name, ranges in tables["script_name_ranges"].items():
        lines.append(f"  {name}: {_ascii_json(ranges)},")
    lines += [
        "};",
        "",
        "// Characters Python's str.isdigit() accepts that aren't decimal digits (\\p{Nd}):",
        "// superscripts, circled digits and similar.",
        f"export const EXTRA_DIGIT_RANGES = {_ascii_json(tables['extra_digit_ranges'])};",
        "",
    ]
    path.write_text("\n".join(lines), encoding="ascii", newline="\n")


def write_public_suffixes(path: Path) -> None:
    psl = features._PUBLIC_SUFFIXES  # the exact object registrable_domain() uses
    lines = [
        "// Generated by model/src/export_browser.py. Do not edit; rerun the script.",
        f"// The Public Suffix List as parsed by publicsuffixlist {publicsuffixlist.__version__}",
        "// (wildcard rules start with *., exceptions with !, and internationalised",
        "// names appear both in Unicode and in xn-- form).",
        "// The list's data is licensed under the Mozilla Public License 2.0:",
        "// https://mozilla.org/MPL/2.0/ (source: https://publicsuffix.org/).",
        "",
        '// The most labels any rule has ("a.b.c" has 3).',
        f"export const MAX_LABELS = {psl._maxlabel};",
        "",
        "export const PUBLIC_SUFFIXES = new Set([",
        *(f"  {_ascii_json(rule)}," for rule in sorted(psl._publicsuffix)),
        "]);",
        "",
    ]
    path.write_text("\n".join(lines), encoding="ascii", newline="\n")


def write_model(path: Path, model: dict) -> None:
    text = json.dumps(model_json(model), ensure_ascii=True, separators=(",", ":"))
    path.write_text(text + "\n", encoding="ascii", newline="\n")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_model(OUT_DIR / "model.json", load_model())
    write_public_suffixes(OUT_DIR / "public-suffixes.js")
    write_unicode_tables(OUT_DIR / "unicode-tables.js")
    for path in sorted(OUT_DIR.iterdir()):
        print(
            f"wrote {path.relative_to(OUT_DIR.parents[2])} ({path.stat().st_size / 1e3:.0f} KB)"
        )


if __name__ == "__main__":
    main()
