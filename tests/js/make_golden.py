"""Write the golden fixtures the JavaScript parity tests compare against.

Run from the repo root, after `python -m model.src.export_browser`:

    python -m tests.js.make_golden            # tests/js/fixtures/*.json (committed)
    python -m tests.js.make_golden --corpus   # model/data/corpus_golden.jsonl (never committed)

"Golden" files hold the answers of the reference implementation (Python) for fixed
inputs. The JS tests run the same inputs through extension/analyzer/ and must get
the same answers (CLAUDE.md, Phase 5).

- tests/js/fixtures/golden.json: our own example emails (tests/js/golden_emails.py)
  with Python's cleaned email, rule reasons, unrounded score, verdict and final
  result, plus single helpers (host_of, is_ip, ...) on tricky URLs.
- tests/js/fixtures/unicode-classes.json: which characters Python's \\w, \\d, \\s and
  IGNORECASE accept, so the JS tests can check pyRegex() against all of Unicode.
- --corpus: the same check on every email in the local datasets. Dataset text must
  never be committed, so this file goes to model/data/ (gitignored); parity.test.mjs
  uses it when it exists.

All files are written as ASCII JSON (non-ASCII becomes \\uXXXX escapes).
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

from model.src import export_browser, features, predict, preprocess
from tests.js.golden_emails import (
    GOLDEN_EMAILS,
    GOLDEN_QUOTES,
    GOLDEN_UNQUOTE,
    GOLDEN_URLS,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "js" / "fixtures"
MODEL_JSON = export_browser.OUT_DIR / "model.json"
CORPUS_GOLDEN = ROOT / "model" / "data" / "corpus_golden.jsonl"


def model_sha256() -> str:
    return hashlib.sha256(MODEL_JSON.read_bytes()).hexdigest()


def check_export_is_current(model: dict) -> None:
    """The JS side reads model.json; Python reads the joblib file. They must agree."""
    exported = json.loads(MODEL_JSON.read_text(encoding="ascii"))
    if exported != json.loads(json.dumps(export_browser.model_json(model))):
        sys.exit(
            "extension/analyzer/generated/model.json doesn't match the trained model. "
            "Run: python -m model.src.export_browser"
        )


def expected(fields: dict, model: dict) -> dict:
    """Python's answers for one email, step by step, as predict.analyze() works."""
    cleaned = preprocess.prepare_email(fields)
    reasons = features.find_reasons(cleaned)
    text = predict.email_text(cleaned, model.get("mask_brands", False))
    rule_rows = [features.rule_vector(reasons)]
    x = predict.design_matrix(model["approach"], model["vectorizer"], [text], rule_rows)
    score = float(model["classifier"].predict_proba(x)[0, 1])
    return {
        "cleaned": cleaned,
        "rule_reasons": reasons,
        "score": score,
        "verdict": predict.decide_verdict(score, reasons),
        "result": predict.analyze(fields, model),
    }


def url_case(url: str) -> dict:
    try:
        path, error = urlsplit(url).path, False
    except ValueError:
        path, error = "", True
    host = features.host_of(url)
    return {
        "url": url,
        "urlsplit_error": error,
        "path": path,
        "host": host,
        "is_ip": features.is_ip(host),
        "registrable_domain": features.registrable_domain(host),
    }


def golden(model: dict) -> dict:
    return {
        "generated_by": "python -m tests.js.make_golden",
        "python_version": platform.python_version(),
        "model_sha256": model_sha256(),
        "emails": [
            {"name": name, "input": fields, **expected(fields, model)}
            for name, fields in GOLDEN_EMAILS.items()
        ],
        "urls": [url_case(url) for url in GOLDEN_URLS],
        "unquote": [{"text": t, "result": unquote(t)} for t in GOLDEN_UNQUOTE],
        "quote": [{"text": t, "result": features.quote(t)} for t in GOLDEN_QUOTES],
    }


def _ranges(predicate) -> list[list[int]]:
    """Code point ranges [first, last] where predicate(char) is true."""
    ranges: list[list[int]] = []
    for code_point in range(sys.maxunicode + 1):
        if 0xD800 <= code_point <= 0xDFFF:  # surrogates aren't characters
            continue
        if predicate(chr(code_point)):
            if ranges and ranges[-1][1] == code_point - 1:
                ranges[-1][1] = code_point
            else:
                ranges.append([code_point, code_point])
    return ranges


def unicode_classes() -> dict:
    def matcher(pattern: str, flags: int = 0):
        regex = re.compile(pattern, flags)
        return lambda char: regex.fullmatch(char) is not None

    return {
        "unicode_version": unicodedata.unidata_version,
        # Characters this Python's Unicode version knows. Newer ones may differ.
        "assigned": _ranges(lambda c: unicodedata.category(c) != "Cn"),
        "word": _ranges(matcher(r"\w")),
        "digit": _ranges(matcher(r"\d")),
        "space": _ranges(matcher(r"\s")),
        "letter": _ranges(matcher(r"[^\W\d_]")),
        "isdigit": _ranges(str.isdigit),
        "ignorecase": {
            letter: _ranges(matcher(letter, re.IGNORECASE))
            for letter in "abcdefghijklmnopqrstuvwxyz"
        },
    }


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=True, indent=1)
    path.write_text(text + "\n", encoding="ascii", newline="\n")
    print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size / 1e3:.0f} KB)")


def write_corpus(model: dict) -> None:
    """Every dataset email, as Gmail would show it, with Python's answers."""
    count = 0
    with CORPUS_GOLDEN.open("w", encoding="ascii", newline="\n") as out:
        for source_iter in (
            preprocess._iter_nazario(preprocess.RAW_DIR),
            preprocess._iter_spamassassin(preprocess.RAW_DIR),
        ):
            for msg, _, source in source_iter:
                if preprocess._is_mbox_placeholder(msg):
                    continue
                fields = preprocess.extract_fields(msg)
                record = {"name": f"{source} #{count}", "input": fields}
                record.update(expected(fields, model))
                out.write(json.dumps(record, ensure_ascii=True) + "\n")
                count += 1
    print(f"wrote {CORPUS_GOLDEN.relative_to(ROOT)} ({count} emails; never commit it)")


def main() -> None:
    model = predict.load_model()
    check_export_is_current(model)
    if "--corpus" in sys.argv:
        write_corpus(model)
        return
    write_json(FIXTURES / "golden.json", golden(model))
    write_json(FIXTURES / "unicode-classes.json", unicode_classes())


if __name__ == "__main__":
    main()
