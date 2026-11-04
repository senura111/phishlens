"""Train the TF-IDF + Logistic Regression classifier, evaluate it, and save it.

Run from the repo root: `python -m model.src.train`

Evaluation uses a held-out test set (precision, recall, F1, confusion matrix).
SAVED_APPROACH is saved with joblib to model/artifacts/.

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
    ARTIFACT_PATH,
    BRAND_TOKEN,
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

# Chosen over "text only" although its F1 was a hair lower (0.981 vs 0.985): it made
# fewer false positives and leans less on the datasets' writing style, because part of
# its evidence comes from the rules, which look for phishing tactics, not style.
SAVED_APPROACH = TEXT_AND_RULES
# Replace brand names with one placeholder word before TF-IDF (see predict.mask_brands).
# The placeholder is also a stop word, so the text model ignores brand mentions:
# as a normal word it became a strong phishing sign ("a brand was mentioned").
# Spotting brand impersonation is the rules' job.
MASK_BRANDS = True
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
        stop_words=[BRAND_TOKEN],  # dropped before counting: never a model input
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
    scores = classifier.predict_proba(x)[:, 1]
    verdicts = [decide_verdict(score, r) for score, r in zip(scores, reasons)]
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


def weight_table(vectorizer, classifier, x) -> pd.DataFrame:
    """Every input column of a text + rules model with its learned weight.

    Raw weights can't be compared directly: a fired rule column is 1 (or 2/3), but a
    word's TF-IDF value in an email is usually small (rows are scaled to length 1).
    "typical push" = weight x the column's average value in the emails where it's
    present: the log-odds it typically adds to an email's score.
    """
    names = [*vectorizer.get_feature_names_out()]
    names += [f"rule: {rid}" for rid in features.REASON_IDS]
    columns = x.tocsc()
    present = np.diff(columns.indptr)  # how many emails have a non-zero value
    totals = np.asarray(columns.sum(axis=0)).ravel()
    typical = np.divide(
        totals, present, out=np.zeros_like(totals, dtype=float), where=present > 0
    )
    weights = classifier.coef_[0]
    table = pd.DataFrame(
        {
            "input": names,
            "weight": weights,
            "typical value": typical,
            "emails": present,
            "typical push": weights * typical,
        }
    )
    table["rank"] = table["typical push"].abs().rank(ascending=False).astype(int)
    return table


def print_weight_report(table: pd.DataFrame, n: int = 10) -> None:
    rules = table[table["input"].str.startswith("rule: ")]
    words = table[~table["input"].str.startswith("rule: ")]
    columns = ["input", "weight", "typical value", "typical push", "rank", "emails"]
    fmt = {
        "weight": "{:+.2f}".format,
        "typical value": "{:.2f}".format,
        "typical push": "{:+.2f}".format,
    }
    print(f"=== rule columns in {SAVED_APPROACH} (rank among {len(table)} inputs)")
    print(
        rules.sort_values("typical push", ascending=False)[columns].to_string(
            index=False, formatters=fmt
        )
    )
    for label, ascending in (("phishing", False), ("safe", True)):
        print(f"\n=== strongest {n} {label} words by typical push")
        top = words.sort_values("typical push", ascending=ascending).head(n)
        print(top[columns].to_string(index=False, formatters=fmt))


def false_positives_by_source(test: pd.DataFrame, verdicts) -> pd.DataFrame:
    safe = test.assign(flagged=[v != SAFE for v in verdicts])[test["label"] == 0]
    table = safe.groupby("source")["flagged"].agg(["sum", "count"])
    table.columns = ["false positives", "safe emails"]
    table["rate"] = (table["false positives"] / table["safe emails"]).map(
        "{:.1%}".format
    )
    return table


def _pick(values, idx):
    return [values[i] for i in idx]


def run_experiment(df: pd.DataFrame, mask_brand_names: bool = MASK_BRANDS) -> dict:
    """Group into campaigns, split, then fit and evaluate every approach.

    Campaigns are found on the unmasked text, so the split is the same whether or not
    brand names are masked, and the two settings can be compared fairly.
    """
    emails = df.to_dict("records")
    reasons = [features.find_reasons(email) for email in emails]
    rule_rows = [features.rule_vector(r) for r in reasons]
    texts = [email_text(email, mask_brand_names) for email in emails]
    labels = df["label"].to_numpy()

    groups = campaign_groups([email_text(email) for email in emails])
    split = GroupShuffleSplit(
        n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE
    )
    train_idx, test_idx = next(split.split(texts, labels, groups))
    assert not set(groups[train_idx]) & set(groups[test_idx])  # no shared campaign

    results = {}
    for approach in APPROACHES:
        vectorizer, classifier = fit(
            approach,
            _pick(texts, train_idx),
            _pick(rule_rows, train_idx),
            labels[train_idx],
        )
        scores, verdicts = predict_verdicts(
            approach,
            vectorizer,
            classifier,
            _pick(texts, test_idx),
            _pick(rule_rows, test_idx),
            _pick(reasons, test_idx),
        )
        results[approach] = {
            "vectorizer": vectorizer,
            "classifier": classifier,
            "scores": scores,
            "verdicts": verdicts,
            **summarise(labels[test_idx], verdicts),
        }
    return {
        "results": results,
        "groups": groups,
        "train_idx": train_idx,
        "test_idx": test_idx,
        "texts": texts,
        "rule_rows": rule_rows,
    }


def main() -> None:
    df, _ = preprocess.load_dataset()
    run = run_experiment(df)
    results, train_idx, test_idx = run["results"], run["train_idx"], run["test_idx"]
    texts, rule_rows, labels = run["texts"], run["rule_rows"], df["label"].to_numpy()
    test = df.iloc[test_idx]

    sizes = pd.Series(run["groups"]).value_counts()
    print(
        f"{len(df)} emails in {len(sizes)} campaigns; "
        f"{int((sizes > 1).sum())} campaigns have 2+ emails (largest: {sizes.iloc[0]})"
    )
    print(
        f"train: {len(train_idx)} emails, test: {len(test_idx)} emails "
        f"({len(test_idx) / len(df):.0%}; {int(labels[test_idx].sum())} phishing); "
        f"brand names masked: {MASK_BRANDS}\n"
    )

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

    saved = results[SAVED_APPROACH]
    x_train = design_matrix(
        SAVED_APPROACH,
        saved["vectorizer"],
        _pick(texts, train_idx),
        _pick(rule_rows, train_idx),
    )
    print()
    weights = weight_table(saved["vectorizer"], saved["classifier"], x_train)
    print_weight_report(weights)
    if MASK_BRANDS:
        ignored = BRAND_TOKEN not in saved["vectorizer"].vocabulary_
        print()
        print(f"brand placeholder '{BRAND_TOKEN}' ignored by the model: {ignored}")

    artifact = {
        "approach": SAVED_APPROACH,
        "vectorizer": saved["vectorizer"],
        "classifier": saved["classifier"],
        "rule_ids": features.REASON_IDS,
        "mask_brands": MASK_BRANDS,
        "test_metrics": {k: float(saved[k]) for k in ("precision", "recall", "f1")},
    }
    ARTIFACT_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(artifact, ARTIFACT_PATH, compress=3)
    size_mb = ARTIFACT_PATH.stat().st_size / 1e6
    print(f"\nsaved {SAVED_APPROACH} to {ARTIFACT_PATH} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
