// Tests for extension/background/service-worker.js, run under Node with a small
// stand-in for the browser's `chrome` API and `fetch`. They check that the worker
// loads the model shipped in extension/, answers each message type, and never
// needs a server.
//
// Run from the repo root:  node --test tests/js/

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const EXTENSION = new URL("../../extension/", import.meta.url);

let listener = null;
const fetched = [];
globalThis.chrome = {
  runtime: {
    getURL: (path) => `chrome-extension://phishlens/${path}`,
    onMessage: { addListener: (fn) => (listener = fn) },
  },
};
// The worker may only fetch files from inside the extension.
globalThis.fetch = async (url) => {
  fetched.push(url);
  const path = url.replace("chrome-extension://phishlens/", "");
  const text = readFileSync(new URL(path, EXTENSION), "utf8");
  return { json: async () => JSON.parse(text) };
};

await import("../../extension/background/service-worker.js");

// Sends a message the way Chrome does and waits for the reply.
function send(message) {
  return new Promise((resolve) => {
    const async = listener(message, {}, resolve);
    if (!async) {
      resolve(undefined);
    }
  });
}

const PHISHING = {
  sender_name: "PayPal Service",
  sender_email: "service@paypal-account-review.com",
  subject: "Action required: your account has been limited",
  body_text: "Please confirm your account details within 24 hours.",
  links: [{ text: "https://www.paypal.com/signin", href: "http://185.22.10.4/login" }],
  attachments: [],
};

test("status: the model loads", async () => {
  const response = await send({ type: "status" });
  assert.equal(response.state, "ready");
  assert.equal(typeof response.testMetrics.f1, "number");
});

test("analyze: returns a verdict with reasons", async () => {
  const response = await send({ type: "analyze", request: PHISHING });
  assert.equal(response.state, "verdict");
  assert.equal(response.result.verdict, "phishing");
  assert.ok(response.result.reasons.some((reason) => reason.id === "ip_link"));
});

test("analyze: no sender address means the email couldn't be read", async () => {
  const response = await send({ type: "analyze", request: { ...PHISHING, sender_email: "" } });
  assert.deepEqual(response, { state: "unreadable" });
});

test("analyze: a request in the wrong shape fails cleanly", async () => {
  const response = await send({ type: "analyze", request: { ...PHISHING, links: null } });
  assert.deepEqual(response, { state: "failed" });
});

test("unknown messages get no answer", async () => {
  assert.equal(await send({ type: "health" }), undefined);
});

test("the only file fetched is the model inside the extension, once", () => {
  assert.deepEqual(fetched, ["chrome-extension://phishlens/analyzer/generated/model.json"]);
});
