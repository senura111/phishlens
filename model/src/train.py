"""Train the TF-IDF + Logistic Regression classifier, evaluate it, and save it.

Evaluation uses a held-out test set (precision, recall, F1, confusion matrix).
The trained model is saved with joblib to model/artifacts/.

Train/test split (decided for v1): group near-duplicate campaigns so each campaign is
entirely in train or entirely in test (e.g. sklearn's GroupShuffleSplit with one group
id per campaign). Exact duplicates are already removed in preprocess.py, but phishing
campaigns repeat with small changes (USAA, DocuSign, WeTransfer templates). A random
split would put copies on both sides and make the test scores look better than they are.

Text model input: subject + body_text only. sender_name is only normalised (not
date-stripped) so features.py can catch "service@paypal.com <x@evil.ru>", and a few
phishing display names contain years ("Mail Team (C) 2017"); it belongs to the rules.
"""
