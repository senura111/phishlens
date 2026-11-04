// Fits an email read from Gmail to PhishLens's analysis limits (the API contract in
// CLAUDE.md). The limits keep every analysis small and fast, and they're the same
// for the in-browser analyser and the Python API. Pure functions, no DOM.
//
// Everything cut off here is a blind spot an attacker could hide in, so fitEmail()
// reports whether anything was cut, and the banner then says the email was only
// partly analysed.
//
// This file runs in two places with no build step:
// - In Chrome, as a content script. Its top-level functions become globals that
//   gmail.js (loaded after it, see manifest.json) can call.
// - Under `node --test`. Node has `module`, Chrome doesn't, so only Node runs the
//   module.exports at the bottom.

// Keep in step with api/schemas.py (the Python API checks the same limits).
// Lengths are in characters.
const LIMITS = {
  senderEmail: 254,
  senderName: 256,
  subject: 1_000,
  linkText: 2_048,
  linkHref: 2_048,
  attachmentName: 255,
  links: 1_000,
  attachments: 100,
  // The Python API rejects requests over 100 KB (102,400 bytes). Stay a little under.
  requestBytes: 100_000,
};

// If the request is over requestBytes, the body is shortened first, but its first
// MIN_BODY_CHARS are kept before any links are dropped: both matter, and a body
// cut to nothing would leave the text model blind.
const MIN_BODY_CHARS = 20_000;

// Invisible "format" characters (Unicode category Cf): zero-width spaces and
// joiners, soft hyphens, text-direction controls and more. Phishers put them inside
// words ("pass" + zero-width space + "word") so that rules looking for "password"
// miss them, or use a right-to-left mark to show "Invoice.exe" as "Invoice.jpg".
// This also removes the zero-width joiners Sinhala and emoji use; that's harmless
// here, because the cleaned text is only analysed, never shown.
const INVISIBLE_CHARACTERS = /\p{Cf}/gu;

function stripInvisible(text) {
  return text.replace(INVISIBLE_CHARACTERS, "");
}

// Cuts text to at most maxLength characters, keeping the start.
//
// JS counts some characters (most emoji) as two, while Python counts
// them as one. So text that fits here also fits there. Cutting between the two
// halves of such a character would leave half a character, so cut just before it.
function cutText(text, maxLength) {
  if (text.length <= maxLength) {
    return text;
  }
  let end = maxLength;
  const lastKept = text.charCodeAt(end - 1);
  if (lastKept >= 0xd800 && lastKept <= 0xdbff) {
    end -= 1; // the first half of a two-part character
  }
  return text.slice(0, end);
}

// The request's size in bytes as the service worker will send it: JSON, in UTF-8.
// An accented letter takes 2 bytes, an emoji 4, and JSON escapes some characters (a quote becomes
// \" and a control character \u0001, 6 bytes), so length in characters isn't enough.
const encoder = new TextEncoder();

function requestBytes(request) {
  return encoder.encode(JSON.stringify(request)).length;
}

// Returns { request, truncated }: the request to send to POST /analyze, and whether
// anything had to be left out or cut.
//
// Free text (name, subject, body, link text, attachment names) is cleaned of
// invisible characters. The sender address and link hrefs are kept exactly as
// Gmail shows them: they say where mail comes from and where a link goes, and
// cleaning them could turn a fake domain into a real-looking one.
function fitEmail(email) {
  let truncated = false;

  function fit(text, maxLength) {
    const short = cutText(text, maxLength);
    if (short.length < text.length) {
      truncated = true;
    }
    return short;
  }

  // Remove exact duplicates (same text and same href) before the link cap. Links
  // with the same href but different text are all kept: one of them could be the
  // one whose text pretends to go somewhere else.
  const links = [];
  const seenLinks = new Set();
  for (const link of email.links) {
    const fitted = {
      text: fit(stripInvisible(link.text), LIMITS.linkText),
      // Cut from the end, so the scheme and domain at the start are kept.
      href: fit(link.href, LIMITS.linkHref),
    };
    const key = JSON.stringify([fitted.text, fitted.href]);
    if (!seenLinks.has(key)) {
      seenLinks.add(key);
      links.push(fitted);
    }
  }
  if (links.length > LIMITS.links) {
    links.length = LIMITS.links;
    truncated = true;
  }

  const attachments = (email.attachments ?? []).map((name) =>
    fit(stripInvisible(name), LIMITS.attachmentName)
  );
  if (attachments.length > LIMITS.attachments) {
    attachments.length = LIMITS.attachments;
    truncated = true;
  }

  const request = {
    sender_name: fit(stripInvisible(email.sender_name), LIMITS.senderName),
    sender_email: fit(email.sender_email, LIMITS.senderEmail),
    subject: fit(stripInvisible(email.subject), LIMITS.subject),
    body_text: stripInvisible(email.body_text),
    links,
    attachments,
  };

  if (fitToRequestBytes(request)) {
    truncated = true;
  }
  return { request, truncated };
}

// Shortens the request until it's at most LIMITS.requestBytes. Changes `request`
// in place and returns true if anything was removed.
//
// Removing N characters always removes at least N bytes (every character takes at
// least one byte), so cutting by the excess in characters is always enough.
function fitToRequestBytes(request) {
  let excess = requestBytes(request) - LIMITS.requestBytes;
  if (excess <= 0) {
    return false;
  }

  // 1. Shorten the body, down to MIN_BODY_CHARS at most.
  const bodyLength = Math.max(MIN_BODY_CHARS, request.body_text.length - excess);
  request.body_text = cutText(request.body_text, bodyLength);
  excess = requestBytes(request) - LIMITS.requestBytes;

  // 2. Drop links from the end (footers, social links, "unsubscribe"). Each one
  //    frees its own JSON plus the comma before it.
  while (excess > 0 && request.links.length > 0) {
    const removed = request.links.pop();
    excess -= encoder.encode(JSON.stringify(removed)).length + 1;
  }
  excess = requestBytes(request) - LIMITS.requestBytes;

  // 3. Still too big (very long subject, name and attachment names together with
  //    the remaining body): shorten the body further, to nothing if need be. Only
  //    made-up inputs are still too big after that; they're analysed anyway, and
  //    the banner says the email was only partly analysed.
  if (excess > 0) {
    const shorter = Math.max(0, request.body_text.length - excess);
    request.body_text = cutText(request.body_text, shorter);
  }
  return true;
}

if (typeof module !== "undefined") {
  module.exports = { LIMITS, MIN_BODY_CHARS, stripInvisible, cutText, requestBytes, fitEmail };
}
