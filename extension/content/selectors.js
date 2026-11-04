// Every Gmail DOM selector PhishLens uses lives in this file. Gmail changes its markup
// from time to time, so when PhishLens stops finding emails, this is the one file to
// fix. Stable attributes (data-message-id, email, download_url) are preferred over
// Gmail's obfuscated class names (a3s, aV3), which can change without notice.
//
// Never match visible text ("to me", "Message clipped"): Gmail's interface can be in
// any language. Use attributes and page structure only.
//
// Checked against live Gmail (2026-11-04) on two single-message emails, one with
// attachments: all selectors below matched. Threads with several messages are not
// checked yet.
//
// Content scripts share one global scope (listed in order in manifest.json), so the
// scripts loaded after this one can use SELECTORS and ATTRIBUTES directly.

const SELECTORS = {
  // One message in a thread, collapsed or expanded. Its id looks like
  // "#msg-f:1879669327088501622".
  message: "div[data-message-id]",
  // The body of an expanded message; collapsed messages don't have one.
  // The weakest selector here (a class name), so check it first if things break.
  body: ".a3s",
  // The sender. Recipients ("to me") also have span[email], but only the sender is
  // inside the message header's h3.
  sender: "h3 span[email]",
  // The thread's subject: one per thread, outside the messages.
  subject: "h2[data-thread-perm-id]",
  // Links inside a message body. Their href is the URL the sender wrote; Gmail puts
  // its own redirect in data-saferedirecturl, which we ignore.
  link: "a[href]",
  // An attachment chip. Its download_url attribute is "mime type:file name:url", with
  // the file name URL-encoded ("Session%201%20(MAS).jpg").
  attachment: "[download_url]",
  // Fallback for attachments: the visible file name on the chip, not encoded.
  attachmentName: ".aV3",
};

// Attribute names read from the elements above. They are Gmail markup too.
const ATTRIBUTES = {
  // On SELECTORS.message: a unique id per message, used to avoid analysing a
  // message twice.
  messageId: "data-message-id",
  // On SELECTORS.sender.
  senderEmail: "email",
  senderName: "name",
  // On SELECTORS.attachment.
  downloadUrl: "download_url",
};
