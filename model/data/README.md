# Datasets

Raw data is **not** committed to git (see `.gitignore`). Download it yourself and put it in
this folder using the layout below.

## Sources

### Phishing: Nazario phishing corpus
<https://monkey.org/~jose/phishing/>

Real phishing emails collected by Jose Nazario. Download the yearly files (`phishing-2015`
through the latest year). They are in mbox format even though they have no `.mbox`
extension. The older `phishing0-3.mbox` and `20051114.mbox` files are optional extras.
Read `LICENSE.txt` on that page before using the data.

### Legitimate (ham): SpamAssassin public corpus
<https://spamassassin.apache.org/old/publiccorpus/>

Download these three:

- `20030228_easy_ham.tar.bz2`
- `20030228_easy_ham_2.tar.bz2`
- `20030228_hard_ham.tar.bz2`

`hard_ham` matters: it's legitimate mail that *looks* spammy (newsletters, promotions).
It helps keep false positives down. Skip the `20021010_*` files. They are older versions
of the same sets and would add duplicates.

### Optional: Enron email dataset
<https://www.cs.cmu.edu/~enron/>

A large set of real workplace email. Useful if the model needs more legitimate examples.

## Expected layout

```
model/data/
├── README.md
└── raw/
    ├── phishing/          # Nazario files, e.g. phishing-2024
    └── ham/
        ├── easy_ham/
        ├── easy_ham_2/
        └── hard_ham/
```

To extract the SpamAssassin archives (from `model/data/raw/ham/`):

```bash
tar -xjf 20030228_easy_ham.tar.bz2
```

## Known caveat

The SpamAssassin ham is from 2002–2003, but the Nazario phishing is mostly 2015 onward.
A model can "cheat" by learning that old-looking email is safe and modern-looking email
is phishing. Keep this in mind when reading evaluation results.
