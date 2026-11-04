// The analyser's entry point: analyze(email, model) -> { verdict, score, reasons }.
// The JavaScript twin of model/src/predict.py, using the model that
// model/src/export_browser.py exported to generated/model.json.
//
// How the score is computed (the same steps scikit-learn takes in Python):
// 1. TF-IDF: the subject and body are lowercased and split into words of 2+ letters.
//    Each word and each pair of neighbouring words ("your account") that is in the
//    model's vocabulary gets the value (1 + ln(count)) x IDF. IDF ("inverse document
//    frequency") is large for words that were rare in the training emails. The values
//    are then scaled so the email's list of values has length 1.
// 2. Logistic Regression: every value is multiplied by its learned weight, and so is
//    each rule's result (0, 1/3, 2/3 or 1). The sum plus the intercept is the
//    "log-odds"; the sigmoid 1 / (1 + e^-x) turns it into a probability from 0 to 1.
// 3. decideVerdict() turns the probability and the rule reasons into a verdict.

import { BRANDS, findReasons, LOW, makeReason, REASON_IDS, ruleVector } from "./features.js";
import { prepareEmail } from "./preprocess.js";
import { pyLen, pyRegex, pySplit } from "./python-compat.js";

export const PHISHING = "phishing";
export const SUSPICIOUS = "suspicious";
export const SAFE = "safe";
// Starting thresholds from CLAUDE.md.
const PHISHING_THRESHOLD = 0.8;
const SUSPICIOUS_THRESHOLD = 0.5;
// Rules that make an email at least "suspicious" whatever its score (see predict.py).
const FLOOR_RULES = new Set(["ip_link", "homoglyphs"]);

// --- Brand masking ------------------------------------------------------------------

// Brand names in the text the model reads become one placeholder word, which the
// model ignores (it's a stop word). Spotting brand impersonation is the rules' job.
const BRAND_TOKEN = "brandname";
const BRAND_NAMES = [
  ...new Set([...BRANDS.keys(), "bank of america", "wells fargo", "office 365", "pay pal"]),
].sort((a, b) => pyLen(b) - pyLen(a)); // longest first
const BRAND_RE = pyRegex(
  String.raw`\b(?:` + BRAND_NAMES.map((name) => pySplit(name).join(String.raw`\s+`)).join("|") + String.raw`)\b`,
  "ig"
);

function maskBrands(text) {
  return text.replace(BRAND_RE, BRAND_TOKEN);
}

// What the text model reads: subject and body only.
function emailText(email, maskBrandNames) {
  const text = `${email.subject} ${email.body_text}`;
  return maskBrandNames ? maskBrands(text) : text;
}

// --- Loading the exported model -----------------------------------------------------

const MODEL_FORMAT = "phishlens-browser-model";
const MODEL_FORMAT_VERSION = 1;
// scikit-learn's TF-IDF settings this file implements (train.make_vectorizer).
const TOKEN_PATTERN = String.raw`(?u)\b[^\W\d_]{2,}\b`;
const TOKEN_RE = pyRegex(TOKEN_PATTERN, "g");

// Checks the parsed model.json and prepares it for analyze(). Throws if the file
// isn't a model this code can use, so a mismatch fails loudly instead of scoring wrong.
export function loadModel(data) {
  if (data?.format !== MODEL_FORMAT || data.format_version !== MODEL_FORMAT_VERSION) {
    throw new Error(`Not a ${MODEL_FORMAT} file, version ${MODEL_FORMAT_VERSION}.`);
  }
  if (JSON.stringify(data.rule_ids) !== JSON.stringify(REASON_IDS)) {
    throw new Error("The model was trained with different rules; export it again.");
  }
  const vectorizer = data.vectorizer;
  const settingsMatch =
    vectorizer.token_pattern === TOKEN_PATTERN &&
    JSON.stringify(vectorizer.ngram_range) === "[1,2]" &&
    JSON.stringify(vectorizer.stop_words) === JSON.stringify([BRAND_TOKEN]) &&
    vectorizer.sublinear_tf === true &&
    vectorizer.norm === "l2";
  if (!settingsMatch) {
    throw new Error("The model uses TF-IDF settings predict.js doesn't implement.");
  }
  return {
    maskBrands: data.mask_brands,
    vocabulary: vectorizer.vocabulary,
    // Word or word pair -> its column number.
    columns: new Map(vectorizer.vocabulary.map((term, column) => [term, column])),
    idf: vectorizer.idf,
    textWeights: data.classifier.text_weights,
    ruleWeights: REASON_IDS.map((id) => data.classifier.rule_weights[id]),
    intercept: data.classifier.intercept,
    testMetrics: data.test_metrics,
  };
}

// --- Scoring ------------------------------------------------------------------------

// The email's TF-IDF values as [column, value] pairs, sorted by column (the order
// scikit-learn adds them up in). Columns not in the email are left out (they're 0).
function tfidf(text, model) {
  const words = Array.from(text.toLowerCase().matchAll(TOKEN_RE), (m) => m[0]).filter(
    (word) => word !== BRAND_TOKEN // stop words go before word pairs are made
  );
  const terms = [...words];
  for (let i = 0; i + 1 < words.length; i++) {
    terms.push(`${words[i]} ${words[i + 1]}`);
  }
  const counts = new Map();
  for (const term of terms) {
    const column = model.columns.get(term);
    if (column !== undefined) {
      counts.set(column, (counts.get(column) ?? 0) + 1);
    }
  }
  const values = [...counts]
    .sort((a, b) => a[0] - b[0])
    .map(([column, count]) => [column, (Math.log(count) + 1) * model.idf[column]]);
  let squares = 0;
  for (const [, value] of values) {
    squares += value * value;
  }
  if (squares === 0) {
    return values;
  }
  const length = Math.sqrt(squares);
  return values.map(([column, value]) => [column, value / length]);
}

// The model's phishing probability, from 0 to 1.
function probability(textValues, ruleRow, model) {
  let logOdds = 0;
  for (const [column, value] of textValues) {
    logOdds += value * model.textWeights[column];
  }
  ruleRow.forEach((value, i) => {
    if (value !== 0) {
      logOdds += value * model.ruleWeights[i];
    }
  });
  logOdds += model.intercept;
  return 1 / (1 + Math.exp(-logOdds));
}

// predict.decide_verdict(): red needs a score of at least PHISHING_THRESHOLD *and*
// a high-severity rule or two different medium-severity rules. A FLOOR_RULES reason
// lifts a low score to "suspicious", never to "phishing".
export function decideVerdict(score, reasons) {
  if (score < SUSPICIOUS_THRESHOLD) {
    const floor = reasons.some((reason) => FLOOR_RULES.has(reason.id));
    return floor ? SUSPICIOUS : SAFE;
  }
  if (score < PHISHING_THRESHOLD) {
    return SUSPICIOUS;
  }
  const high = reasons.some((reason) => reason.severity === "high");
  const mediums = new Set(
    reasons.filter((reason) => reason.severity === "medium").map((reason) => reason.id)
  );
  return high || mediums.size >= 2 ? PHISHING : SUSPICIOUS;
}

// --- The "phishing_language" reason -------------------------------------------------

const PHISHING_LANGUAGE = "phishing_language";
const MAX_LANGUAGE_EXAMPLES = 3;

// predict.phishing_language_reason(): name the words or phrases in this email that
// pushed the score toward phishing the most. null when the wording overall points
// toward safe (then the flag came from the rules).
function phishingLanguageReason(model, textValues) {
  const pushes = textValues.map(([column, value]) => [
    model.vocabulary[column],
    value * model.textWeights[column],
  ]);
  if (pySum(pushes.map(([, push]) => push)) <= 0) {
    return null;
  }
  // Biggest push first. sort() is stable, so equal pushes stay in column order,
  // as in Python.
  const sorted = [...pushes].sort((a, b) => b[1] - a[1]);
  const examples = [];
  for (const [phrase, push] of sorted) {
    if (push <= 0 || examples.length === MAX_LANGUAGE_EXAMPLES) {
      break;
    }
    const words = new Set(pySplit(phrase));
    if (words.has(BRAND_TOKEN)) {
      continue; // the placeholder means nothing to a reader
    }
    // Skip "your" when "your account" is already listed, and the other way round.
    const overlaps = examples.some((example) => {
      const exampleWords = new Set(pySplit(example));
      return isSubset(words, exampleWords) || isSubset(exampleWords, words);
    });
    if (!overlaps) {
      examples.push(phrase);
    }
  }
  if (examples.length === 0) {
    return null;
  }
  const quoted = examples.map((example) => `'${example}'`).join(", ");
  return makeReason(
    PHISHING_LANGUAGE,
    LOW,
    `The wording is similar to phishing emails (for example ${quoted}). ` +
      "On its own this is a weak sign."
  );
}

function isSubset(a, b) {
  return [...a].every((item) => b.has(item));
}

// Python's built-in sum() of floats. Since Python 3.12 it keeps a running correction
// for rounding errors (Neumaier summation), so a plain loop can differ in the last
// digits. That matters when the total is close to 0.
function pySum(numbers) {
  let total = 0;
  let correction = 0;
  for (const x of numbers) {
    const t = total + x;
    if (Math.abs(total) >= Math.abs(x)) {
      correction += total - t + x;
    } else {
      correction += x - t + total;
    }
    total = t;
  }
  return correction && Number.isFinite(correction) ? total + correction : total;
}

// --- analyze() ----------------------------------------------------------------------

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

// Python's round(score, 2). toFixed() rounds an exact half up, Python rounds it to
// the even digit. Between 0 and 1 the only floats exactly halfway at 2 decimals are
// these four.
const EXACT_HALVES = new Map([
  [0.125, 0.12],
  [0.375, 0.38],
  [0.625, 0.62],
  [0.875, 0.88],
]);

function roundScore(score) {
  return EXACT_HALVES.get(score) ?? Number(score.toFixed(2));
}

// Everything analyze() works out, for the parity tests: the cleaned email, the rule
// reasons, the unrounded score, the verdict and the final result.
export function analyzeInDetail(email, model) {
  const cleaned = prepareEmail(email);
  const ruleReasons = findReasons(cleaned);
  const textValues = tfidf(emailText(cleaned, model.maskBrands), model);
  const score = probability(textValues, ruleVector(ruleReasons), model);
  const verdict = decideVerdict(score, ruleReasons);
  let reasons = ruleReasons;
  if (verdict !== SAFE) {
    const language = phishingLanguageReason(model, textValues);
    if (language) {
      reasons = [...reasons, language]; // added after the verdict: it isn't a rule
    }
  }
  reasons = [...reasons].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const result = {
    verdict,
    score: roundScore(score),
    reasons: reasons.map(({ id, severity, message }) => ({ id, severity, message })),
  };
  return { cleaned, ruleReasons, score, verdict, result };
}

// Analyse one email read from Gmail: the fields of the API contract in CLAUDE.md
// (sender_name, sender_email, subject, body_text, links, optional attachments).
// model: a loadModel() result. Returns { verdict, score, reasons }, most severe
// reasons first, exactly like predict.analyze() in Python.
export function analyze(email, model) {
  return analyzeInDetail(email, model).result;
}
