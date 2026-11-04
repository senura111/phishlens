// Finds the emails the user opens in Gmail and reads what PhishLens analyses: sender
// name and address, subject, body text, links and attachment file names.
//
// Gmail is a single-page app: opening an email doesn't load a new page, Gmail just
// changes the page's DOM. A MutationObserver tells us whenever the DOM changes, and we
// then look for expanded messages we haven't read yet.
//
// Each message is fitted to the API's limits (payload.js) and sent to the service
// worker, which calls the local API. The outcome is shown in a banner above the
// message's body (banner.js) and logged to the console.

// How long to wait after the first DOM change before looking for messages. Gmail
// changes the DOM many times while it shows an email; waiting lets it finish.
const SCAN_DELAY_MS = 300;

// Outcomes by data-message-id: null while the API is working on a message, then
// { state, result, truncated } (see analyseMessage). Without this, every DOM change
// (and Gmail makes many) would send the same message again. It lives only in this
// tab's memory; the reasons can quote a domain from the email, so it's never saved.
const messageOutcomes = new Map();

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
    if (!id || !body) {
      continue;
    }
    if (messageOutcomes.has(id)) {
      showBanner(id, message, body);
      continue;
    }
    // Gmail can keep earlier views in the page, hidden. Skip them: on a hidden
    // element innerText also returns hidden text. A message that becomes visible
    // later is picked up by the scan that follows.
    if (!body.checkVisibility()) {
      continue;
    }
    messageOutcomes.set(id, null);
    analyseMessage(id, readMessage(message, body));
  }
}

// Sends one message to the service worker and stores the outcome:
//   state      "verdict", "offline", "unreadable" or "failed" (service-worker.js)
//   result     the API's verdict, score and reasons (only when state is "verdict")
//   truncated  true if payload.js had to cut something: only partly analysed
async function analyseMessage(id, email) {
  const { request, truncated } = fitEmail(email);
  let answer;
  try {
    answer = await chrome.runtime.sendMessage({ type: "analyze", request });
  } catch {
    // After the extension is reloaded, a content script that was already in the
    // page can't reach it any more ("Extension context invalidated"). Reloading
    // the Gmail tab fixes that.
    console.warn("PhishLens: can't reach the extension. Reload this tab.");
  }
  const outcome = { state: "failed", ...answer, truncated };
  messageOutcomes.set(id, outcome);
  logOutcome(id, outcome);
  // The next scan shows the banner.
  scheduleScan();
}

// Puts a message's banner above its body, unless it's already there, the API is
// still working on the message, or the user dismissed it. Gmail sometimes rebuilds
// a message's DOM (e.g. when you come back to a thread), which removes our banner;
// the next scan puts it back from the stored outcome, without asking the API again.
function showBanner(id, message, body) {
  const outcome = messageOutcomes.get(id);
  if (!outcome || outcome.dismissed || message.querySelector(`.${BANNER_CLASS}`)) {
    return;
  }
  const banner = createBanner(outcome, {
    // Stays dismissed until this tab is reloaded.
    onDismiss: () => {
      outcome.dismissed = true;
    },
    // Forget the outcome, so the next scan analyses the message again.
    onRetry: () => {
      banner.remove();
      messageOutcomes.delete(id);
      scheduleScan();
    },
  });
  body.before(banner);
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

// Logs the verdict, score and reason ids, never the reasons' messages: they can
// quote a domain or phrase from the email (CLAUDE.md security rules).
function logOutcome(id, outcome) {
  let summary = outcome.state;
  if (outcome.state === "verdict") {
    const { verdict, score, reasons } = outcome.result;
    const ids = reasons.map((reason) => reason.id).join(", ") || "no reasons";
    summary = `${verdict} (score ${score.toFixed(2)}; ${ids})`;
  }
  const partly = outcome.truncated ? ", only partly analysed" : "";
  console.log(`PhishLens ${id}: ${summary}${partly}`);
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
