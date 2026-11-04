// Finds the emails the user opens in Gmail and reads what PhishLens analyses: sender
// name and address, subject, body text, links and attachment file names.
//
// Gmail is a single-page app: opening an email doesn't load a new page, Gmail just
// changes the page's DOM. A MutationObserver tells us whenever the DOM changes, and we
// then look for expanded messages we haven't read yet.
//
// Step 2 of Phase 3: messages are only read and summarised in the console. Sending
// them to the API comes next.

// How long to wait after the first DOM change before looking for messages. Gmail
// changes the DOM many times while it shows an email; waiting lets it finish.
const SCAN_DELAY_MS = 300;

// Messages already read, by their data-message-id. Without this, every DOM change
// (and Gmail makes many) would read the same message again. It lives only in this
// tab's memory and holds no email content.
const seenMessages = new Set();

let scanTimer = null;

// Called on every DOM change. Starts a timer unless one is already running, so a
// burst of changes leads to one scan. (Restarting the timer on each change instead
// could postpone the scan forever while Gmail keeps changing something.)
function scheduleScan() {
  if (scanTimer !== null) {
    return;
  }
  scanTimer = setTimeout(() => {
    scanTimer = null;
    scanForMessages();
  }, SCAN_DELAY_MS);
}

// Reads every expanded, visible message that hasn't been read yet. A thread can
// have several expanded messages; each one is read on its own, because a phishing
// message can be a reply inside a real conversation.
function scanForMessages() {
  for (const message of document.querySelectorAll(SELECTORS.message)) {
    const id = message.getAttribute(ATTRIBUTES.messageId);
    const body = message.querySelector(SELECTORS.body);
    // No body: the message is collapsed. Read it once the user expands it.
    if (!id || !body || seenMessages.has(id)) {
      continue;
    }
    // Gmail can keep earlier views in the page, hidden. Skip them: on a hidden
    // element innerText also returns hidden text. A message that becomes visible
    // later is picked up by the scan that follows.
    if (!body.checkVisibility()) {
      continue;
    }
    seenMessages.add(id);
    const email = readMessage(message, body);
    logSummary(id, email);
  }
}

// Returns the email in the shape of the API request (see the API contract in
// CLAUDE.md), not yet fitted to the API's length caps.
function readMessage(message, body) {
  const sender = message.querySelector(SELECTORS.sender);
  return {
    sender_name: sender?.getAttribute(ATTRIBUTES.senderName)?.trim() ?? "",
    sender_email: sender?.getAttribute(ATTRIBUTES.senderEmail)?.trim() ?? "",
    subject: readSubject(message),
    // innerText, not textContent: it leaves out text hidden with CSS, which
    // phishers use to pad an email with harmless words.
    body_text: body.innerText,
    links: readLinks(body),
    attachments: readAttachments(message),
  };
}

// The subject belongs to the thread, not to one message. Search outwards from the
// message, so a hidden earlier thread's subject elsewhere in the page isn't used.
function readSubject(message) {
  for (let element = message.parentElement; element; element = element.parentElement) {
    const subject = element.querySelector(SELECTORS.subject);
    if (subject) {
      return subject.innerText.trim();
    }
  }
  return "";
}

function readLinks(body) {
  return [...body.querySelectorAll(SELECTORS.link)].map((link) => ({
    text: link.innerText.trim(),
    // getAttribute gives the URL exactly as the sender wrote it. Never unwrap a
    // google.com/url?q= link here: if one is in href, the sender put it there,
    // and hiding a link behind Google's redirect is a known phishing trick.
    href: link.getAttribute("href"),
  }));
}

// File names only; attachments are never downloaded or opened.
function readAttachments(message) {
  const chips = message.querySelectorAll(SELECTORS.attachment);
  if (chips.length > 0) {
    return [...chips].map((chip) =>
      fileNameFromDownloadUrl(chip.getAttribute(ATTRIBUTES.downloadUrl))
    );
  }
  // Fallback: the file name shown on the chip.
  return [...message.querySelectorAll(SELECTORS.attachmentName)].map((name) =>
    name.innerText.trim()
  );
}

// download_url is "mime type:file name:url", with the name URL-encoded. Because it's
// encoded, a ":" inside the name appears as "%3A", so splitting on ":" is safe.
function fileNameFromDownloadUrl(downloadUrl) {
  const encoded = downloadUrl.split(":")[1] ?? "";
  try {
    return decodeURIComponent(encoded);
  } catch {
    // A malformed escape like "%E0%A4%A" makes decodeURIComponent throw.
    return encoded;
  }
}

// Logs sizes and counts only, never the content itself (CLAUDE.md security rules).
function logSummary(id, email) {
  console.log(
    `PhishLens read ${id}: sender ${email.sender_email ? "found" : "MISSING"}, ` +
      `subject ${email.subject.length} chars, body ${email.body_text.length} chars, ` +
      `${email.links.length} links, ${email.attachments.length} attachments`
  );
}

const observer = new MutationObserver(scheduleScan);
observer.observe(document.body, {
  // Elements added or removed: an email opened, or a message expanded.
  childList: true,
  subtree: true,
  // Gmail shows a hidden view by changing these attributes, without adding elements.
  // Without them, a message skipped while hidden would not be read once it's shown.
  attributes: true,
  attributeFilter: ["style", "class", "hidden"],
});
// An email may already be open when this script starts, e.g. after reloading a
// thread's URL.
scheduleScan();
