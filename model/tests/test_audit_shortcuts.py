import pandas as pd

from model.src import audit_shortcuts as audit
from model.src import preprocess as pp


def make_df(rows):
    return pd.DataFrame(
        [
            {"sender_name": "", "subject": subject, "body_text": body, "label": label}
            for subject, body, label in rows
        ]
    )


def test_repeated_lines_finds_lines_unique_to_one_class():
    footer = "Visit our mailing list archive online"
    shared = "Please let me know what you think"
    bodies = [f"hi {i}\n{footer}\n{shared}" for i in range(3)] + [shared] * 3
    labels = [pp.SAFE] * 3 + [pp.PHISHING] * 3

    found = audit.repeated_lines(bodies, labels, min_count=3)

    assert found[pp.SAFE] == [(footer.lower(), 3, 0)]
    assert found[pp.PHISHING] == []


def test_top_features_surfaces_the_separating_words():
    rows = [("Hi", f"verify your password now {i}", pp.PHISHING) for i in range(20)]
    rows += [("Hi", f"lunch on the patio maybe {i}", pp.SAFE) for i in range(20)]

    accuracy, features = audit.top_features(make_df(rows), n=3)

    assert accuracy == 1.0
    assert set(features[pp.PHISHING]) <= {"verify", "your", "password", "now"}
    assert set(features[pp.SAFE]) <= {"lunch", "on", "the", "patio", "maybe"}


def test_leftover_token_counts_counts_emails_per_class():
    df = make_df(
        [
            ("Dear jose", "x", pp.PHISHING),
            ("Hello", "posted in 2002", pp.SAFE),
            ("Hello", "nothing here", pp.SAFE),
        ]
    )
    counts = audit.leftover_token_counts(df)
    assert counts["Nazario recipient (jose/monkey)"] == (0, 1)
    assert counts["years"] == (1, 0)
