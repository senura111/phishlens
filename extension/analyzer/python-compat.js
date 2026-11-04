// Helpers that make JavaScript strings and regular expressions behave like Python's.
//
// The analyser must give exactly the same answers as the Python reference in
// model/src (CLAUDE.md, Phase 5). The two languages differ in small ways that matter:
//
// - Python's \w, \d, \s and \b know every alphabet. JavaScript's only know ASCII,
//   so "e with an acute accent" is a word character in Python but not in JS.
// - Python counts a string's length in characters (code points); JS counts UTF-16
//   units, so most emoji have length 1 in Python and 2 in JS.
// - Python's str.split(), strip() and splitlines() use slightly different sets of
//   space and line-break characters than JS's split(), trim() and "\n".
// - With IGNORECASE, Python lets "i" also match U+0130 and U+0131 (the Turkish
//   dotted capital I and dotless small i). JavaScript doesn't.
//
// pyRegex() takes a pattern written the Python way and builds the equivalent
// JavaScript RegExp, so the patterns in preprocess.js and features.js can be copied
// from the Python files character for character.
//
// Code points above 0xFF are written as \\u{...} inside strings in this folder, never
// as escapes JavaScript would turn into the invisible character itself when reading
// the source. tests/js/unicode.test.mjs checks every class below against Python.

import { EXTRA_DIGIT_RANGES, SCRIPT_NAME_RANGES } from "./generated/unicode-tables.js";

// --- Character classes (the inside of [...]) ---------------------------------------

// Python's \w: letters and numbers in any script, plus "_".
export const WORD = "\\p{L}\\p{N}_";
// Python's \d: decimal digits in any script.
export const DIGIT = "\\p{Nd}";
// Python's \s, and the characters str.isspace() accepts. (JavaScript's \s also has
// U+FEFF, and lacks \x1c-\x1f and \x85.)
const SPACE_EXCEPT_NEWLINE =
  "\\t\\x0b\\x0c\\r\\x1c-\\x20\\x85\\xa0\\u{1680}\\u{2000}-\\u{200a}" +
  "\\u{2028}\\u{2029}\\u{202f}\\u{205f}\\u{3000}";
export const SPACE = "\\n" + SPACE_EXCEPT_NEWLINE;
// Python's [^\W\d_]: \w without decimal digits and "_", so letters plus numbers
// such as Roman numerals and superscripts.
export const LETTER = "\\p{L}\\p{Nl}\\p{No}";

// Python's \b: between a \w character and a non-\w character (or the text's edge).
const BOUNDARY = `(?:(?<=[${WORD}])(?![${WORD}])|(?<![${WORD}])(?=[${WORD}]))`;
const TURKISH_I = "\\u{130}\\u{131}";

// --- pyRegex ------------------------------------------------------------------------

// Builds a JavaScript RegExp that matches exactly what Python's re module would match
// with the same pattern. flags: "i" for re.IGNORECASE, "g" to find every match.
//
// Only the parts of Python's syntax this project uses are supported; anything else
// throws, so a pattern copied from Python never silently means something different.
export function pyRegex(source, flags = "") {
  const ignoreCase = flags.includes("i");
  // [^\W\d_] can't be translated piece by piece (JavaScript can't put "not \w"
  // inside a negated class), so it's replaced as a whole.
  source = source.replaceAll("[^\\W\\d_]", `[${LETTER}]`);
  // (?u) is Python's "Unicode" flag, which is always on for text.
  let i = source.startsWith("(?u)") ? 4 : 0;
  let out = "";
  while (i < source.length) {
    const char = source[i];
    if (char === "[") {
      const end = classEnd(source, i);
      out += translateClass(source.slice(i + 1, end), ignoreCase);
      i = end + 1;
    } else if (char === "\\") {
      const [translated, length] = translateEscape(source, i, false);
      out += translated;
      i += length;
    } else if (char === ".") {
      // Python's "." is anything but \n; JavaScript's also skips \r, U+2028, U+2029.
      out += "[^\\n]";
      i += 1;
    } else if (char === "$") {
      // Python's $ also matches before a final \n. Not needed, so not supported.
      throw new Error("pyRegex: $ is not supported");
    } else if (ignoreCase && (char === "i" || char === "I")) {
      out += `[iI${TURKISH_I}]`;
      i += 1;
    } else {
      out += char;
      i += 1;
    }
  }
  return new RegExp(out, "u" + (ignoreCase ? "i" : "") + (flags.includes("g") ? "g" : ""));
}

// The index of the "]" that closes the class starting at source[start] ("[").
function classEnd(source, start) {
  let i = start + 1;
  if (source[i] === "^") {
    i += 1;
  }
  if (source[i] === "]") {
    i += 1; // a "]" first in a class is a literal "]" in Python
  }
  while (i < source.length) {
    if (source[i] === "\\") {
      i += translateEscape(source, i, true)[1];
    } else if (source[i] === "]") {
      return i;
    } else {
      i += 1;
    }
  }
  throw new Error(`pyRegex: unclosed [ in ${source}`);
}

function translateClass(body, ignoreCase) {
  const negated = body.startsWith("^");
  const content = negated ? body.slice(1) : body;
  let out = "";
  let i = 0;
  while (i < content.length) {
    if (content[i] === "\\") {
      const [translated, length] = translateEscape(content, i, true);
      out += translated;
      i += length;
    } else {
      // "[" and "]" are literal here in Python; JavaScript wants them escaped.
      out += content[i] === "[" || content[i] === "]" ? "\\" + content[i] : content[i];
      i += 1;
    }
  }
  if (ignoreCase && new RegExp(`[${out}]`, "ui").test("i")) {
    // Add the Turkish i's as a separate class: appended to this one, a class
    // ending in "-" would turn into a range ("_-" + U+0130 = everything between).
    return negated ? `(?![${TURKISH_I}])[^${out}]` : `(?:[${out}]|[${TURKISH_I}])`;
  }
  return `[${negated ? "^" : ""}${out}]`;
}

const CLASS_ESCAPES = { w: WORD, d: DIGIT, s: SPACE };

// Translates the escape at source[start] ("\"). Returns [JavaScript text, length].
function translateEscape(source, start, inClass) {
  const next = source[start + 1];
  // \p{L}, \P{L} and \u{2028} are already JavaScript syntax (from the classes above).
  if (next === "p" || next === "P" || (next === "u" && source[start + 2] === "{")) {
    const close = source.indexOf("}", start);
    return [source.slice(start, close + 1), close + 1 - start];
  }
  if (next === "x") {
    return [source.slice(start, start + 4), 4];
  }
  if (next in CLASS_ESCAPES) {
    const chars = CLASS_ESCAPES[next];
    return [inClass ? chars : `[${chars}]`, 2];
  }
  const lower = next.toLowerCase();
  if (lower in CLASS_ESCAPES && !inClass) {
    return [`[^${CLASS_ESCAPES[lower]}]`, 2]; // \W, \D, \S
  }
  if (next === "b" && !inClass) {
    return [BOUNDARY, 2];
  }
  if (/[A-Za-z0-9]/.test(next) && !"ntr".includes(next)) {
    throw new Error(`pyRegex: \\${next} is not supported here`);
  }
  if ("ntr".includes(next) || "^$\\.*+?()[]{}|/".includes(next)) {
    return ["\\" + next, 2]; // \n, \. \( \[ ...: the same in both
  }
  if (next === "-") {
    return [inClass ? "\\-" : "-", 2];
  }
  // Python allows escaping any punctuation (\" or \@); JavaScript's "u" flag only
  // allows it for characters that are special, so write the character itself.
  return [next, 2];
}

// --- Strings ------------------------------------------------------------------------

const SPACE_RUN = new RegExp(`[${SPACE}]+`, "u");
const EDGE_SPACES = new RegExp(`^[${SPACE}]+|[${SPACE}]+$`, "gu");
export const LINE_SPACES = new RegExp(`[${SPACE_EXCEPT_NEWLINE}]+`, "gu");
// What str.splitlines() splits on.
const LINE_BREAK = new RegExp(
  "\\r\\n|[\\n\\r\\x0b\\x0c\\x1c\\x1d\\x1e\\x85\\u{2028}\\u{2029}]",
  "u"
);

// str.strip()
export function pyStrip(text) {
  return text.replace(EDGE_SPACES, "");
}

// str.split() with no arguments: split on runs of spaces, no empty pieces.
export function pySplit(text) {
  const stripped = pyStrip(text);
  return stripped === "" ? [] : stripped.split(SPACE_RUN);
}

// str.splitlines(): a final line break doesn't start another (empty) line.
export function pySplitlines(text) {
  const lines = text.split(LINE_BREAK);
  if (lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines;
}

// len(text): the number of characters (code points), not UTF-16 units.
export function pyLen(text) {
  let length = 0;
  for (const _ of text) {
    length += 1;
  }
  return length;
}

// text[:n] for n >= 0, counted in characters.
export function pyHead(text, n) {
  return Array.from(text).slice(0, n).join("");
}

// str.isascii()
export function isAscii(text) {
  return /^[\x00-\x7f]*$/.test(text);
}

// str.isdigit(): at least one character, all of them digits of some kind.
export function isDigit(text) {
  if (text === "") {
    return false;
  }
  for (const char of text) {
    if (!/\p{Nd}/u.test(char) && !inRanges(char.codePointAt(0), EXTRA_DIGIT_RANGES)) {
      return false;
    }
  }
  return true;
}

// The first word of a character's Unicode name if it's LATIN, GREEK or CYRILLIC
// ("CYRILLIC SMALL LETTER A" -> "CYRILLIC"), else "OTHER". ASCII counts as LATIN.
// This is features._script() for the scripts the homoglyph rule compares.
export function scriptOf(char) {
  const codePoint = char.codePointAt(0);
  if (codePoint < 0x80) {
    return "LATIN";
  }
  for (const [name, ranges] of Object.entries(SCRIPT_NAME_RANGES)) {
    if (inRanges(codePoint, ranges)) {
      return name;
    }
  }
  return "OTHER";
}

// True if codePoint is in one of the sorted [first, last] ranges (binary search).
function inRanges(codePoint, ranges) {
  let low = 0;
  let high = ranges.length - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const [first, last] = ranges[middle];
    if (codePoint < first) {
      high = middle - 1;
    } else if (codePoint > last) {
      low = middle + 1;
    } else {
      return true;
    }
  }
  return false;
}

// text.rpartition(separator)[2]: everything after the last separator, or all of it.
export function afterLast(text, separator) {
  return text.slice(text.lastIndexOf(separator) + 1);
}

// text.rsplit(separator, maxSplit)
export function pyRsplit(text, separator, maxSplit) {
  const parts = text.split(separator);
  if (parts.length <= maxSplit + 1) {
    return parts;
  }
  const keep = parts.length - maxSplit;
  return [parts.slice(0, keep).join(separator), ...parts.slice(keep)];
}

// list(dict.fromkeys(items)): repeats removed, first-seen order kept.
export function unique(items) {
  return [...new Set(items)];
}
