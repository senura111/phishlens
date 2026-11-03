"""Look for shortcuts: things that let a model tell the two datasets apart instead of
telling phishing from safe email.

Run it from the repo root after changing preprocess.py:

    python -m model.src.audit_shortcuts

It prints three checks. Prints come from the local datasets only, never from user email.

1. Lines that still repeat across many emails of one class but not the other.
   These are usually footers, signatures or templates that cleaning missed.
2. The words a quick TF-IDF + Logistic Regression model relies on most. Words about
   the dataset (list names, years, anonymised names) instead of about phishing are
   shortcuts. A near-perfect accuracy is a warning sign, not a success.
3. How many emails of each class still contain known artifact tokens.
"""

from __future__ import annotations

import re
from collections import Counter

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from model.src import preprocess as pp

REPEATED_MIN = 25
REPEATED_MAX_OTHER = 2
TOP_FEATURES = 60

# Tokens that were (or could be) shortcuts. Each should be rare, or similar in both classes.
LEFTOVER_TOKENS = {
    "anonymised names (zzzz/yyyy/qqqq)": r"zzzz|yyyy|qqqq",
    "Nazario recipient (jose/monkey)": r"\bjose\b|\bmonkey\b",
    "SpamAssassin owner (taint.org/jmason)": r"taint\.org|\bjmason\b|\bspamassassin\b",
    "years": r"\b(?:19|20)\d\d\b",
    "'url' / 'date' labels": r"\burl\b|\bdate\b",
    "'wrote:' reply lines": r"\bwrote:",
    "copyright sign": r"©",
}


def repeated_lines(
    bodies: list[str], labels: list[int], min_count: int = REPEATED_MIN
) -> dict[int, list[tuple[str, int, int]]]:
    """For each label, the lines found in >= min_count of its emails but at most
    REPEATED_MAX_OTHER emails of the other label: (line, count, other_count)."""
    counts = {pp.SAFE: Counter(), pp.PHISHING: Counter()}
    for body, label in zip(bodies, labels):
        lines = {pp.line_key(line) for line in body.splitlines()}
        counts[label].update(l for l in lines if len(l) >= pp.BOILERPLATE_MIN_CHARS)

    result = {}
    for label, other in ((pp.SAFE, pp.PHISHING), (pp.PHISHING, pp.SAFE)):
        result[label] = [
            (line, n, counts[other][line])
            for line, n in counts[label].most_common()
            if n >= min_count and counts[other][line] <= REPEATED_MAX_OTHER
        ]
    return result


def top_features(df: pd.DataFrame, n: int = TOP_FEATURES) -> tuple[float, dict]:
    """Train a quick text model and return (test accuracy, top words per label)."""
    text = df["subject"] + " " + df["body_text"]
    x_train, x_test, y_train, y_test = train_test_split(
        text, df["label"], test_size=0.25, random_state=0, stratify=df["label"]
    )
    vectorizer = TfidfVectorizer(min_df=3, sublinear_tf=True)
    model = LogisticRegression(max_iter=2000, C=10)
    model.fit(vectorizer.fit_transform(x_train), y_train)
    accuracy = model.score(vectorizer.transform(x_test), y_test)

    names = vectorizer.get_feature_names_out()
    order = model.coef_[0].argsort()  # negative = safe, positive = phishing
    return accuracy, {
        pp.SAFE: list(names[order[:n]]),
        pp.PHISHING: list(names[order[::-1][:n]]),
    }


def leftover_token_counts(df: pd.DataFrame) -> dict[str, tuple[int, int]]:
    """For each LEFTOVER_TOKENS pattern: (safe emails, phishing emails) containing it."""
    text = df["sender_name"] + " " + df["subject"] + " " + df["body_text"]
    result = {}
    for name, pattern in LEFTOVER_TOKENS.items():
        found = text.str.contains(re.compile(pattern, re.IGNORECASE))
        result[name] = (
            int((found & (df["label"] == pp.SAFE)).sum()),
            int((found & (df["label"] == pp.PHISHING)).sum()),
        )
    return result


def main() -> None:
    raw, stats = pp.load_raw_emails()
    df, stats = pp.build_table(raw, stats)
    label_names = {pp.SAFE: "safe", pp.PHISHING: "phishing"}
    print(f"Emails after cleaning: {len(df)}  {stats}\n")

    print(f"== 1. Lines repeated in >= {REPEATED_MIN} emails of only one class")
    lines = repeated_lines(
        [fields["body_text"] for fields, _, _ in raw], [label for _, label, _ in raw]
    )
    for label, found in lines.items():
        print(f"  {label_names[label]}: {len(found)} lines")
        for line, n, other in found[:40]:
            print(f"    {n:4} vs {other} | {line[:100]}")

    accuracy, features = top_features(df)
    print(f"\n== 2. Quick model accuracy: {accuracy:.4f}")
    for label, words in features.items():
        print(f"  top {label_names[label]} words: {', '.join(words)}")

    print("\n== 3. Emails still containing artifact tokens (safe / phishing)")
    for name, (safe, phishing) in leftover_token_counts(df).items():
        print(f"  {name:40} {safe:5} / {phishing}")


if __name__ == "__main__":
    main()
