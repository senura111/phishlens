// Tests for extension/content/payload.js. Run from the repo root:
//
//     node --test tests/js/
//
// Invisible and non-ASCII characters are built with String.fromCodePoint, so this
// file stays plain ASCII and every test input is visible when reading it.

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  LIMITS,
  MIN_BODY_CHARS,
  stripInvisible,
  cutText,
  requestBytes,
  fitEmail,
} = require("../../extension/content/payload.js");

const ZERO_WIDTH_SPACE = String.fromCodePoint(0x200b);
const SOFT_HYPHEN = String.fromCodePoint(0xad);
const RIGHT_TO_LEFT_OVERRIDE = String.fromCodePoint(0x202e);
const E_ACUTE = String.fromCodePoint(0xe9); // 2 bytes in UTF-8
const EMOJI = String.fromCodePoint(0x1f600); // 2 JS characters, 4 bytes in UTF-8

function makeEmail(overrides = {}) {
  return {
    sender_name: "PayPal Support",
    sender_email: "support@paypa1-secure.com",
    subject: "Your account will be suspended",
    body_text: "Please confirm your password within 24 hours.",
    links: [{ text: "paypal.com/login", href: "http://185.22.10.4/login" }],
    attachments: ["Invoice_2291.pdf.exe"],
    ...overrides,
  };
}

function manyLinks(count, hrefLength = 30) {
  return Array.from({ length: count }, (_, i) => ({
    text: `link ${i}`,
    href: `https://example.com/${i}/`.padEnd(hrefLength, "x"),
  }));
}

// --- Emails that already fit ---

test("an email that fits is sent unchanged", () => {
  const email = makeEmail();
  const { request, truncated } = fitEmail(email);
  assert.deepEqual(request, email);
  assert.equal(truncated, false);
});

test("empty fields stay empty, and missing attachments become []", () => {
  const email = makeEmail({ sender_name: "", subject: "", body_text: "", links: [] });
  delete email.attachments;
  const { request, truncated } = fitEmail(email);
  assert.equal(request.sender_name, "");
  assert.equal(request.subject, "");
  assert.equal(request.body_text, "");
  assert.deepEqual(request.links, []);
  assert.deepEqual(request.attachments, []);
  assert.equal(truncated, false);
});

// --- Invisible characters ---

test("zero-width characters are removed from free text", () => {
  const hidden = `pass${ZERO_WIDTH_SPACE}word`;
  const { request, truncated } = fitEmail(
    makeEmail({
      sender_name: `Pay${ZERO_WIDTH_SPACE}Pal`,
      subject: `Reset your ${hidden}`,
      body_text: `Enter your ${hidden} and pass${SOFT_HYPHEN}code`,
      links: [{ text: `pay${ZERO_WIDTH_SPACE}pal.com`, href: "https://evil.example/" }],
      attachments: [`report${ZERO_WIDTH_SPACE}.pdf`],
    })
  );
  assert.equal(request.sender_name, "PayPal");
  assert.equal(request.subject, "Reset your password");
  assert.equal(request.body_text, "Enter your password and passcode");
  assert.equal(request.links[0].text, "paypal.com");
  assert.deepEqual(request.attachments, ["report.pdf"]);
  // Cleaning isn't cutting: the email was analysed in full.
  assert.equal(truncated, false);
});

test("a right-to-left override can't disguise an attachment's extension", () => {
  // Displayed as "Invoice_exe.pdf", because the characters after the override are
  // shown backwards. The real name ends in ".exe", and that's what the API must see.
  const name = `Invoice_${RIGHT_TO_LEFT_OVERRIDE}fdp.exe`;
  const { request } = fitEmail(makeEmail({ attachments: [name] }));
  assert.deepEqual(request.attachments, ["Invoice_fdp.exe"]);
});

test("the sender address and hrefs are kept exactly, invisible characters included", () => {
  const address = `support@pay${ZERO_WIDTH_SPACE}pal.com`;
  const href = `https://pay${ZERO_WIDTH_SPACE}pal.com/login`;
  const { request } = fitEmail(
    makeEmail({ sender_email: address, links: [{ text: "paypal.com", href }] })
  );
  assert.equal(request.sender_email, address);
  assert.equal(request.links[0].href, href);
});

test("stripInvisible leaves ordinary text, accents and emoji alone", () => {
  const text = `Caf${E_ACUTE} ${EMOJI} line one\nline two\ttab`;
  assert.equal(stripInvisible(text), text);
});

// --- Length caps ---

test("each field is cut to its cap, and the email is marked as truncated", () => {
  const { request, truncated } = fitEmail(
    makeEmail({
      sender_name: "n".repeat(300),
      sender_email: "a".repeat(300) + "@example.com",
      subject: "s".repeat(1_500),
      links: [{ text: "t".repeat(3_000), href: "https://example.com/" }],
      attachments: ["f".repeat(400) + ".exe"],
    })
  );
  assert.equal(request.sender_name.length, LIMITS.senderName);
  assert.equal(request.sender_email.length, LIMITS.senderEmail);
  assert.equal(request.subject.length, LIMITS.subject);
  assert.equal(request.links[0].text.length, LIMITS.linkText);
  assert.equal(request.attachments[0].length, LIMITS.attachmentName);
  assert.equal(truncated, true);
});

test("a long href is cut from the end, so its domain is kept", () => {
  const href = "https://evil.example/" + "a".repeat(5_000);
  const { request, truncated } = fitEmail(makeEmail({ links: [{ text: "x", href }] }));
  assert.equal(request.links[0].href.length, LIMITS.linkHref);
  assert.ok(request.links[0].href.startsWith("https://evil.example/"));
  assert.equal(truncated, true);
});

test("a single field over its cap is enough to mark the email as truncated", () => {
  const { truncated } = fitEmail(makeEmail({ subject: "s".repeat(LIMITS.subject + 1) }));
  assert.equal(truncated, true);
});

test("a field exactly at its cap is not truncated", () => {
  const { request, truncated } = fitEmail(makeEmail({ subject: "s".repeat(LIMITS.subject) }));
  assert.equal(request.subject.length, LIMITS.subject);
  assert.equal(truncated, false);
});

test("cutText never leaves half of a two-part character", () => {
  // 255 letters + an emoji (2 JS characters) = 257; a plain cut at 256 would split it.
  const text = "a".repeat(255) + EMOJI;
  const short = cutText(text, 256);
  assert.equal(short, "a".repeat(255));
  // A string with half a character can't be encoded faithfully as UTF-8.
  assert.equal(short.isWellFormed(), true);
});

test("cutText keeps a whole two-part character that fits", () => {
  assert.equal(cutText("ab" + EMOJI + "cd", 4), "ab" + EMOJI);
});

test("more than 100 attachments are cut to 100", () => {
  const names = Array.from({ length: 150 }, (_, i) => `file${i}.pdf`);
  const { request, truncated } = fitEmail(makeEmail({ attachments: names }));
  assert.equal(request.attachments.length, LIMITS.attachments);
  assert.equal(request.attachments[0], "file0.pdf");
  assert.equal(truncated, true);
});

// --- Duplicate links and the link cap ---

test("exact duplicate links are removed before the cap, so nothing is lost", () => {
  const repeated = { text: "Read more", href: "https://example.com/post" };
  const links = [...Array(1_500).fill(repeated), { text: "Other", href: "https://other.example/" }];
  const { request, truncated } = fitEmail(makeEmail({ links }));
  assert.deepEqual(request.links, [repeated, { text: "Other", href: "https://other.example/" }]);
  assert.equal(truncated, false);
});

test("links with the same href but different text are all kept", () => {
  // The second link's text pretends to be PayPal: dropping it as a "duplicate"
  // of the first would hide exactly what the rules look for.
  const href = "https://evil.example/login";
  const links = [
    { text: "", href },
    { text: "paypal.com", href },
  ];
  const { request } = fitEmail(makeEmail({ links }));
  assert.deepEqual(request.links, links);
});

test("more than 1,000 different links are cut to the first 1,000", () => {
  const { request, truncated } = fitEmail(makeEmail({ links: manyLinks(1_200) }));
  assert.equal(request.links.length, LIMITS.links);
  assert.equal(request.links[0].text, "link 0");
  assert.equal(truncated, true);
});

// --- The 100 KB request limit ---

test("a long body is cut so the request fits, keeping the start", () => {
  const body = "Start of the email. " + "a".repeat(150_000);
  const { request, truncated } = fitEmail(makeEmail({ body_text: body }));
  assert.ok(requestBytes(request) <= LIMITS.requestBytes);
  assert.ok(request.body_text.startsWith("Start of the email. "));
  assert.equal(truncated, true);
});

test("a body that fits in characters but not in bytes is cut too", () => {
  // 80,000 characters, but 160,000 bytes in UTF-8.
  const { request, truncated } = fitEmail(makeEmail({ body_text: E_ACUTE.repeat(80_000) }));
  assert.ok(requestBytes(request) <= LIMITS.requestBytes);
  assert.equal(truncated, true);
});

test("characters JSON escapes are counted at their escaped size", () => {
  // A quote is sent as \" (2 bytes), a control character as \u0001 (6 bytes).
  const quotes = fitEmail(makeEmail({ body_text: '"'.repeat(60_000) }));
  assert.ok(requestBytes(quotes.request) <= LIMITS.requestBytes);
  const controls = fitEmail(makeEmail({ body_text: String.fromCodePoint(1).repeat(20_000) }));
  assert.ok(requestBytes(controls.request) <= LIMITS.requestBytes);
});

test("a body of emoji is cut without leaving half a character", () => {
  const { request } = fitEmail(makeEmail({ body_text: EMOJI.repeat(40_000) }));
  assert.ok(requestBytes(request) <= LIMITS.requestBytes);
  assert.equal(request.body_text.isWellFormed(), true);
});

test("when links fill the request, the body keeps its start and links are dropped from the end", () => {
  // 1,000 links of about 2,000 characters: about 2 MB on their own.
  const body = "b".repeat(50_000);
  const { request, truncated } = fitEmail(
    makeEmail({ body_text: body, links: manyLinks(1_000, 2_000) })
  );
  assert.ok(requestBytes(request) <= LIMITS.requestBytes);
  assert.equal(request.body_text.length, MIN_BODY_CHARS);
  assert.ok(request.links.length > 0);
  assert.equal(request.links[0].text, "link 0");
  assert.equal(truncated, true);
});

test("a request just under the byte limit is left alone", () => {
  const email = makeEmail({ body_text: "" });
  const spare = LIMITS.requestBytes - requestBytes(email);
  const { request, truncated } = fitEmail({ ...email, body_text: "a".repeat(spare) });
  assert.equal(requestBytes(request), LIMITS.requestBytes);
  assert.equal(truncated, false);
});

test("fitEmail doesn't change the email it was given", () => {
  const email = makeEmail({ body_text: "a".repeat(150_000), links: manyLinks(1_200) });
  const copy = structuredClone(email);
  fitEmail(email);
  assert.deepEqual(email, copy);
});
