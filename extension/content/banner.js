// Builds the PhishLens banner shown above an email's body.
//
// Everything here is built with createElement and textContent, never innerHTML:
// reason messages can quote the email (a domain, a phrase from the subject), and
// email content is written by the attacker. textContent always shows text as text,
// so "<img src=x onerror=...>" in a reason appears as those characters and never
// becomes an element. docs/banner-preview.html shows every state, hostile text
// included.
//
// This file only builds the banner; gmail.js decides where it goes.

// Our own class names start with "phishlens-", so Gmail's CSS doesn't style them and
// ours doesn't style Gmail. gmail.js uses BANNER_CLASS to find banners it inserted.
const BANNER_CLASS = "phishlens-banner";

const SEVERITY_LABELS = { high: "High", medium: "Medium", low: "Low" };

// Builds a banner for one message's outcome (see analyseMessage in gmail.js):
//   outcome.state      "verdict", "offline", "unreadable" or "failed"
//   outcome.result     { verdict, score, reasons } when state is "verdict"
//   outcome.truncated  true if the email was only partly analysed
// onDismiss is called when the user closes the banner; onRetry when they click
// "Try again" on a banner that has no verdict.
function createBanner(outcome, { onDismiss, onRetry }) {
  const content = bannerContent(outcome);

  const banner = element("div", `${BANNER_CLASS} phishlens-${content.tone}`);
  banner.setAttribute("role", "region");
  banner.setAttribute("aria-label", "PhishLens");

  const header = element("div", "phishlens-header");
  const text = element("div", "phishlens-text");
  text.append(element("span", "phishlens-brand", "PhishLens"));
  text.append(element("strong", "phishlens-title", content.title));
  for (const line of content.lines) {
    text.append(element("p", "phishlens-line", line));
  }
  header.append(text);

  const buttons = element("div", "phishlens-buttons");
  if (outcome.state !== "verdict") {
    buttons.append(button("Try again", onRetry));
  }
  const dismiss = button("Dismiss", () => {
    banner.remove();
    onDismiss();
  });
  dismiss.setAttribute("aria-label", "Dismiss the PhishLens banner");
  buttons.append(dismiss);
  header.append(buttons);
  banner.append(header);

  if (outcome.state === "verdict" && outcome.result.reasons.length > 0) {
    banner.append(reasonsSection(outcome.result, content.tone));
  }
  return banner;
}

// The banner's colour ("tone"), title and extra lines for an outcome.
function bannerContent(outcome) {
  const partly = "This email is too long to check in full, so part of it wasn't checked.";
  if (outcome.state === "offline") {
    return {
      tone: "neutral",
      title: "PhishLens can't check this email: its local server isn't running.",
      lines: ["Start the server (the PhishLens popup shows how), then click Try again."],
    };
  }
  if (outcome.state === "unreadable") {
    return {
      tone: "neutral",
      title: "PhishLens couldn't read this email, so it wasn't checked.",
      lines: ["Gmail may still have been loading it. Click Try again."],
    };
  }
  if (outcome.state !== "verdict") {
    return {
      tone: "neutral",
      title: "PhishLens couldn't check this email: the analysis failed.",
      lines: ["Click Try again. If it keeps failing, check the server's window for errors."],
    };
  }

  const verdict = outcome.result.verdict;
  if (verdict === "phishing") {
    return {
      tone: "phishing",
      title: "This email is likely phishing.",
      lines: [
        "Don't click its links, open its attachments or reply with any personal details.",
        ...(outcome.truncated ? [partly] : []),
      ],
    };
  }
  if (verdict === "suspicious") {
    return {
      tone: "suspicious",
      title: "This email shows signs of phishing.",
      lines: [
        "Check carefully before clicking links or replying.",
        ...(outcome.truncated ? [partly] : []),
      ],
    };
  }
  // Safe. If part of the email wasn't checked, it can't honestly be called safe:
  // grey instead of green, and say so.
  if (outcome.truncated) {
    return {
      tone: "neutral",
      title: "No signs of phishing in the part PhishLens could check.",
      lines: [partly],
    };
  }
  return { tone: "safe", title: "No signs of phishing found.", lines: [] };
}

// The expandable list of reasons. On a safe email they're "minor notes": grey,
// collapsed, no severity labels. A lone rule hit on a safe email is usually harmless,
// and warning styling there would teach users to ignore the banner.
function reasonsSection(result, tone) {
  const count = result.reasons.length;
  const isWarning = result.verdict !== "safe";
  const showLabel = isWarning
    ? `Why? (${count} ${count === 1 ? "reason" : "reasons"})`
    : `Minor notes (${count})`;
  const hideLabel = isWarning ? "Hide reasons" : "Hide notes";

  const section = element("div", "phishlens-reasons");
  const list = element("ul", "phishlens-reason-list");
  for (const reason of result.reasons) {
    const item = element("li", "phishlens-reason");
    if (isWarning) {
      item.append(
        element("span", `phishlens-severity phishlens-severity-${reason.severity}`,
          SEVERITY_LABELS[reason.severity])
      );
    }
    const message = element("span", "phishlens-message");
    appendWithQuotes(message, reason.message);
    item.append(message);
    list.append(item);
  }
  list.append(
    element("li", "phishlens-score",
      `Model score ${result.score.toFixed(2)} (0 = looks safe, 1 = looks like phishing).`)
  );

  // Warnings start open, minor notes start closed.
  let open = isWarning;
  const toggle = button("", () => {
    open = !open;
    update();
  });
  toggle.classList.add("phishlens-toggle");
  function update() {
    toggle.textContent = open ? hideLabel : showLabel;
    // Tells screen readers whether the list is showing.
    toggle.setAttribute("aria-expanded", String(open));
    list.hidden = !open;
  }
  update();

  section.append(toggle, list);
  return section;
}

// Reason messages put the values they quote in single quotes: "A link shows
// 'paypal.com' but goes to 'evil.example'". Show those values highlighted, so
// both domains stand out and the user can judge them. A quote only counts when it
// starts after a space or "(" and ends before a space or punctuation, so the
// apostrophe in "doesn't" is left alone. The quotes themselves stay, so the banner
// shows the message exactly as the API sent it.
const QUOTED_VALUE = /(^|[\s(])'([^']+)'(?=$|[\s,.;:)])/g;

function appendWithQuotes(parent, text) {
  let last = 0;
  for (const match of text.matchAll(QUOTED_VALUE)) {
    // Where the value starts: after the space or "(" and the opening quote.
    const valueStart = match.index + match[1].length + 1;
    // append() with a string adds plain text, never HTML.
    parent.append(text.slice(last, valueStart));
    parent.append(element("span", "phishlens-quoted", match[2]));
    last = valueStart + match[2].length; // the closing quote goes with the next text
  }
  parent.append(text.slice(last));
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  node.className = className;
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

function button(label, onClick) {
  const node = element("button", "phishlens-button", label);
  // type="button": not a form submit button, whatever surrounds it in Gmail.
  node.type = "button";
  node.addEventListener("click", onClick);
  return node;
}
