"""Train the TF-IDF + Logistic Regression classifier, evaluate it, and save it.

Run from the repo root: `python -m model.src.train`

Evaluation uses a held-out test set (precision, recall, F1, confusion matrix).
The best approach is saved with joblib to model/artifacts/.

Train/test split (decided for v1): group near-duplicate campaigns so each campaign is
entirely in train or entirely in test (GroupShuffleSplit with one group id per
campaign). Exact duplicates are already removed in preprocess.py, but phishing
campaigns repeat with small changes (USAA, DocuSign, WeTransfer templates). A random
split would put copies on both sides and make the test scores look better than they are.

Text model input: subject + body_text only. sender_name is only normalised (not
date-stripped) so features.py can catch "service@paypal.com <x@evil.ru>", and a few
phishing display names contain years ("Mail Team (C) 2017"); it belongs to the rules.

Three approaches are compared on the same split:
- rules only: Logistic Regression on the rule results (features.rule_vector)
- text only: Logistic Regression on TF-IDF of subject + body
- text + rules: both inputs side by side in one Logistic Regression
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import connected_components
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import GroupShuffleSplit

from model.src import features, preprocess
from model.src.predict import (
    APPROACHES,
    PHISHING,
    RULES_ONLY,
    SAFE,
    SUSPICIOUS,
    TEXT_AND_RULES,
    TEXT_ONLY,
    decide_verdict,
    design_matrix,
    email_text,
)

ARTIFACT_PATH = Path(__file__).resolve().parents[1] / "artifacts" / "phishlens.joblib"
TEST_SIZE = 0.2
RANDOM_STATE = 42
# Emails this similar (cosine similarity of their TF-IDF vectors) are one campaign.
CAMPAIGN_SIMILARITY = 0.8
TOP_WORDS = 20
# Words of 2+ letters. Numbers (order ids, zip codes, version numbers) are left out:
# they identify individual emails or eras rather than phishing.
LETTER_WORDS = r"(?u)\b[^\W\d_]{2,}\b"


# --- Campaign groups -----------------------------------------------------------------


def campaign_groups(
    texts: list[str], threshold: float = CAMPAIGN_SIMILARITY, chunk: int = 1000
) -> np.ndarray:
    """Give every email a campaign id. Emails whose texts are at least `threshold`
    similar share an id, and so do chains of them (A~B and B~C puts A, B, C together).
    """
    vectorizer = TfidfVectorizer(token_pattern=LETTER_WORDS, sublinear_tf=True)
    x = vectorizer.fit_transform(texts)  # rows have length 1, so x @ x.T = cosine
    rows, cols = [], []
    for start in range(0, x.shape[0], chunk):  # in chunks to keep memory small
        similarity = (x[start : start + chunk] @ x.T).toarray()
        r, c = np.nonzero(similarity >= threshold)
        rows.append(r + start)
        cols.append(c)
    rows, cols = np.concatenate(rows), np.concatenate(cols)
    graph = csr_matrix((np.ones(len(rows)), (rows, cols)), shape=(x.shape[0],) * 2)
    _, labels = connected_components(graph, directed=False)
    return labels


# --- Training and evaluation ---------------------------------------------------------


def make_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(
        token_pattern=LETTER_WORDS,
        ngram_range=(1, 2),
        min_df=3,
        max_df=0.9,
        sublinear_tf=True,
    )


def make_classifier() -> LogisticRegression:
    # class_weight="balanced": phishing is the smaller class, so its mistakes count more.
    return LogisticRegression(class_weight="balanced", max_iter=5000)


def fit(approach: str, texts: list[str], rule_rows: list[list[float]], labels):
    vectorizer = None if approach == RULES_ONLY else make_vectorizer().fit(texts)
    x = design_matrix(approach, vectorizer, texts, rule_rows)
    return vectorizer, make_classifier().fit(x, labels)


def predict_verdicts(approach, vectorizer, classifier, texts, rule_rows, reasons):
    """Scores and verdicts, using the same verdict policy as the API."""
    x = design_matrix(approach, vectorizer, texts, rule_rows)
    x_text = design_matrix(approach, vectorizer, texts, rule_rows, without_rules=True)
    scores = classifier.predict_proba(x)[:, 1]
    text_scores = classifier.predict_proba(x_text)[:, 1]
    verdicts = [
        decide_verdict(score, r, text_score)
        for score, r, text_score in zip(scores, reasons, text_scores)
    ]
    return scores, verdicts


def summarise(labels, verdicts) -> dict:
    """Metrics where "flagged" (any warning banner, phishing or suspicious) = positive."""
    flagged = np.array([v != SAFE for v in verdicts], dtype=int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, flagged, average="binary", zero_division=0
    )
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion": confusion_matrix(labels, flagged, labels=[0, 1]),
        "verdict_table": pd.crosstab(
            pd.Series(labels, name="true").map({0: "safe", 1: "phishing"}),
            pd.Series(verdicts, name="verdict"),
        ).reindex(columns=[SAFE, SUSPICIOUS, PHISHING], fill_value=0),
    }


def top_words(vectorizer, classifier, n: int = TOP_WORDS) -> dict[str, list[str]]:
    names = vectorizer.get_feature_names_out()
    weights = classifier.coef_[0][: len(names)]  # text columns come first
    order = weights.argsort()
    return {"phishing": list(names[order[::-1][:n]]), "safe": list(names[order[:n]])}


def false_positives_by_source(test: pd.DataFrame, verdicts) -> pd.DataFrame:
    safe = test.assign(flagged=[v != SAFE for v in verdicts])[test["label"] == 0]
    table = safe.groupby("source")["flagged"].agg(["sum", "count"])
    table.columns = ["false positives", "safe emails"]
    table["rate"] = (table["false positives"] / table["safe emails"]).map(
        "{:.1%}".format
    )
    return table


def main() -> None:
    df, _ = preprocess.load_dataset()
    reasons = [features.find_reasons(email) for email in df.to_dict("records")]
    rule_rows = [features.rule_vector(r) for r in reasons]
    texts = [email_text(email) for email in df.to_dict("records")]
    labels = df["label"].to_numpy()

    groups = campaign_groups(texts)
    sizes = pd.Series(groups).value_counts()
    print(
        f"{len(df)} emails in {len(sizes)} campaigns; "
        f"{int((sizes > 1).sum())} campaigns have 2+ emails (largest: {sizes.iloc[0]})"
    )

    split = GroupShuffleSplit(
        n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE
    )
    train_idx, test_idx = next(split.split(texts, labels, groups))
    assert not set(groups[train_idx]) & set(
        groups[test_idx]
    )  # no campaign on both sides
    test = df.iloc[test_idx]
    print(
        f"train: {len(train_idx)} emails, test: {len(test_idx)} emails "
        f"({len(test_idx) / len(df):.0%}; {int(labels[test_idx].sum())} phishing)\n"
    )

    def pick(values, idx):
        return [values[i] for i in idx]

    results = {}
    for approach in APPROACHES:
        vectorizer, classifier = fit(
            approach,
            pick(texts, train_idx),
            pick(rule_rows, train_idx),
            labels[train_idx],
        )
        _, verdicts = predict_verdicts(
            approach,
            vectorizer,
            classifier,
            pick(texts, test_idx),
            pick(rule_rows, test_idx),
            pick(reasons, test_idx),
        )
        results[approach] = {
            "vectorizer": vectorizer,
            "classifier": classifier,
            "verdicts": verdicts,
            **summarise(labels[test_idx], verdicts),
        }

    for approach, r in results.items():
        (tn, fp), (fn, tp) = r["confusion"]
        print(f"=== {approach}")
        print(
            f"precision {r['precision']:.3f}  recall {r['recall']:.3f}  f1 {r['f1']:.3f}"
        )
        print(f"confusion matrix (flagged = phishing or suspicious):")
        print(f"                 flagged   not flagged")
        print(f"  phishing      {tp:8}   {fn:11}")
        print(f"  safe          {fp:8}   {tn:11}")
        print(r["verdict_table"].to_string(), "\n")
        print("false positives by source:")
        print(false_positives_by_source(test, r["verdicts"]).to_string(), "\n")

    text_model = results[TEXT_ONLY]
    words = top_words(text_model["vectorizer"], text_model["classifier"])
    print(f"=== top {TOP_WORDS} words of the text-only model")
    print("phishing:", ", ".join(words["phishing"]))
    print("safe:    ", ", ".join(words["safe"]))

    combined = results[TEXT_AND_RULES]["classifier"]
    rule_weights = combined.coef_[0][-len(features.REASON_IDS) :]
    print("\n=== rule weights in text + rules (log-odds per fired high-severity rule)")
    for rid, weight in sorted(
        zip(features.REASON_IDS, rule_weights), key=lambda x: -x[1]
    ):
        print(f"  {rid:22} {weight:+.2f}")

    best = max(results, key=lambda a: results[a]["f1"])
    artifact = {
        "approach": best,
        "vectorizer": results[best]["vectorizer"],
        "classifier": results[best]["classifier"],
        "rule_ids": features.REASON_IDS,
        "test_metrics": {
            k: float(results[best][k]) for k in ("precision", "recall", "f1")
        },
    }
    ARTIFACT_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(artifact, ARTIFACT_PATH, compress=3)
    size_mb = ARTIFACT_PATH.stat().st_size / 1e6
    print(f"\nbest approach by F1: {best}; saved to {ARTIFACT_PATH} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
