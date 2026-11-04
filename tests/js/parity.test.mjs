// Parity tests: the JavaScript analyser (extension/analyzer/) must give the same
// answers as the Python reference (model/src/) for every test email: the same
// cleaned email, the same reasons, the same verdict, and a score within 1e-6.
//
// Run from the repo root:  node --test tests/js/
//
// The expected answers come from Python: tests/js/make_golden.py writes them to
// tests/js/fixtures/golden.json. If you change the Python model, rules or cleaning,
// export the model and regenerate the fixtures (CLAUDE.md, Phase 5), then make
// these tests pass again by changing the JavaScript to match.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import { _internal } from "../../extension/analyzer/features.js";
import { analyzeInDetail, loadModel } from "../../extension/analyzer/predict.js";
import {
  hostOf,
  isIp,
  registrableDomain,
  unquote,
  urlsplit,
} from "../../extension/analyzer/urls.js";

const ROOT = new URL("../../", import.meta.url);
const SCORE_TOLERANCE = 1e-6;

const modelBytes = readFileSync(new URL("extension/analyzer/generated/model.json", ROOT));
const model = loadModel(JSON.parse(modelBytes.toString("utf8")));
const golden = readJson("tests/js/fixtures/golden.json");

function readJson(path) {
  return JSON.parse(readFileSync(new URL(path, ROOT), "utf8"));
}

// Compares JS's answers for one email with Python's. Returns a list of what differs
// (empty if nothing does), so the corpus test can count mismatches.
function differences(expected) {
  const actual = analyzeInDetail(expected.input, model);
  const problems = [];
  const same = (a, b) => {
    try {
      assert.deepStrictEqual(a, b);
      return true;
    } catch {
      return false;
    }
  };
  if (!same(actual.cleaned, expected.cleaned)) {
    problems.push("cleaned email");
  }
  if (!same(actual.ruleReasons, expected.rule_reasons)) {
    problems.push("reasons");
  }
  if (!(Math.abs(actual.score - expected.score) <= SCORE_TOLERANCE)) {
    problems.push(`score (JS ${actual.score}, Python ${expected.score})`);
  }
  if (actual.verdict !== expected.verdict) {
    problems.push(`verdict (JS ${actual.verdict}, Python ${expected.verdict})`);
  }
  if (!same(actual.result, expected.result)) {
    problems.push("final result");
  }
  return problems;
}

test("golden.json was made with the model.json the extension ships", () => {
  const sha256 = createHash("sha256").update(modelBytes).digest("hex");
  assert.equal(
    sha256,
    golden.model_sha256,
    "Regenerate the fixtures: python -m tests.js.make_golden"
  );
});

for (const expected of golden.emails) {
  test(`same answers as Python: ${expected.name}`, () => {
    const actual = analyzeInDetail(expected.input, model);
    // Field by field first, so a failure shows exactly what differs.
    assert.deepStrictEqual(actual.cleaned, expected.cleaned);
    assert.deepStrictEqual(actual.ruleReasons, expected.rule_reasons);
    assert.ok(
      Math.abs(actual.score - expected.score) <= SCORE_TOLERANCE,
      `score: JS ${actual.score}, Python ${expected.score}`
    );
    assert.equal(actual.verdict, expected.verdict);
    assert.deepStrictEqual(actual.result, expected.result);
  });
}

test("the golden emails cover every rule and every verdict", () => {
  const ids = new Set(golden.emails.flatMap((e) => e.result.reasons.map((r) => r.id)));
  for (const id of [
    "link_text_mismatch",
    "ip_link",
    "url_shortener",
    "lookalike_domain",
    "homoglyphs",
    "sender_name_mismatch",
    "urgency",
    "sensitive_request",
    "risky_attachment",
    "phishing_language",
  ]) {
    assert.ok(ids.has(id), `no golden email makes ${id} fire`);
  }
  const verdicts = new Set(golden.emails.map((e) => e.verdict));
  assert.deepEqual([...verdicts].sort(), ["phishing", "safe", "suspicious"]);
});

test("URL helpers match Python", () => {
  for (const expected of golden.urls) {
    let path = "";
    let error = false;
    try {
      path = urlsplit(expected.url).path;
    } catch {
      error = true;
    }
    const where = JSON.stringify(expected.url);
    assert.equal(error, expected.urlsplit_error, `urlsplit error for ${where}`);
    assert.equal(path, expected.path, `urlsplit path for ${where}`);
    const host = hostOf(expected.url);
    assert.equal(host, expected.host, `host_of ${where}`);
    assert.equal(isIp(host), expected.is_ip, `is_ip ${where}`);
    assert.equal(registrableDomain(host), expected.registrable_domain, `registrable ${where}`);
  }
});

test("unquote matches Python", () => {
  for (const { text, result } of golden.unquote) {
    assert.equal(unquote(text), result, JSON.stringify(text));
  }
});

test("quote matches Python", () => {
  for (const { text, result } of golden.quote) {
    assert.equal(_internal.quote(text), result, JSON.stringify(text));
  }
});

// The local datasets, if you have them: python -m tests.js.make_golden --corpus.
// Dataset text is never committed, so this only runs on a machine that has it.
const CORPUS = new URL("model/data/corpus_golden.jsonl", ROOT);

test(
  "same answers as Python on every dataset email",
  { skip: !existsSync(CORPUS) && "no model/data/corpus_golden.jsonl" },
  () => {
    const lines = readFileSync(CORPUS, "utf8").split("\n").filter((line) => line);
    const mismatches = [];
    for (const line of lines) {
      const expected = JSON.parse(line);
      const problems = differences(expected);
      if (problems.length > 0) {
        mismatches.push(`${expected.name}: ${problems.join(", ")}`);
      }
    }
    assert.equal(
      mismatches.length,
      0,
      `${mismatches.length} of ${lines.length} emails differ, e.g.\n` +
        mismatches.slice(0, 10).join("\n")
    );
  }
);
