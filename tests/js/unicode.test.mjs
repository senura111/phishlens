// Checks python-compat.js against Python for every character Unicode has: the
// character classes pyRegex() uses for \w, \d, \s and [^\W\d_], str.isdigit(), and
// how IGNORECASE matches each ASCII letter.
//
// Run from the repo root:  node --test tests/js/
//
// The expected sets come from tests/js/fixtures/unicode-classes.json, written by
// python -m tests.js.make_golden. Characters that Python's Unicode version doesn't
// know yet are skipped: a newer browser may already know them, and there's no
// Python answer to compare with.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  DIGIT,
  isDigit,
  LETTER,
  pyRegex,
  SPACE,
  WORD,
} from "../../extension/analyzer/python-compat.js";

const expected = JSON.parse(
  readFileSync(new URL("fixtures/unicode-classes.json", import.meta.url), "utf8")
);

function inRanges(codePoint, ranges) {
  return ranges.some(([first, last]) => codePoint >= first && codePoint <= last);
}

// Every character this Python version knows, as [code point, character] pairs.
const assigned = [];
for (const [first, last] of expected.assigned) {
  for (let codePoint = first; codePoint <= last; codePoint++) {
    assigned.push([codePoint, String.fromCodePoint(codePoint)]);
  }
}

// Returns the characters where the JS test and Python disagree (as hex), at most 10.
function disagreements(jsTest, pythonRanges) {
  const differ = [];
  for (const [codePoint, char] of assigned) {
    if (jsTest(char) !== inRanges(codePoint, pythonRanges)) {
      differ.push(codePoint.toString(16));
      if (differ.length === 10) {
        break;
      }
    }
  }
  return differ;
}

function classTest(chars) {
  const regex = new RegExp(`^[${chars}]$`, "u");
  return (char) => regex.test(char);
}

test("WORD is Python's \\w", () => {
  assert.deepEqual(disagreements(classTest(WORD), expected.word), []);
});

test("DIGIT is Python's \\d", () => {
  assert.deepEqual(disagreements(classTest(DIGIT), expected.digit), []);
});

test("SPACE is Python's \\s", () => {
  assert.deepEqual(disagreements(classTest(SPACE), expected.space), []);
});

test("LETTER is Python's [^\\W\\d_]", () => {
  assert.deepEqual(disagreements(classTest(LETTER), expected.letter), []);
});

test("isDigit is Python's str.isdigit", () => {
  assert.deepEqual(disagreements(isDigit, expected.isdigit), []);
});

test("pyRegex matches ASCII letters with IGNORECASE like Python", () => {
  for (const [letter, ranges] of Object.entries(expected.ignorecase)) {
    const regex = new RegExp(`^(?:${pyRegex(letter, "i").source})$`, "iu");
    const differ = disagreements((char) => regex.test(char), ranges);
    assert.deepEqual(differ, [], `letter ${letter}`);
  }
});
