// PhishLens service worker: analyses emails inside the browser.
//
// gmail.js (a content script) reads an opened email and sends it here; this worker
// runs the analyser (../analyzer/, a JavaScript copy of the Python model) and sends
// the verdict back. Nothing leaves the browser: there is no server, and this file
// makes no network requests except reading the model file that ships inside the
// extension.
//
// It's an ES module ("type": "module" in manifest.json), so it can import the
// analyser. Chrome starts it when a message arrives and stops it after about 30
// seconds of idle time; the model is loaded again the next time it starts.

import { analyze, loadModel } from "../analyzer/predict.js";

const MODEL_URL = chrome.runtime.getURL("analyzer/generated/model.json");

// The loaded model, shared by every message while this worker is running. A promise,
// so messages that arrive while it's loading all wait for the same load.
let modelPromise = null;

function getModel() {
  if (modelPromise === null) {
    modelPromise = fetch(MODEL_URL)
      .then((response) => response.json())
      .then(loadModel)
      .catch((error) => {
        modelPromise = null; // try again next time
        throw error;
      });
  }
  return modelPromise;
}

// Analyses one email (already fitted to the analyser's limits by payload.js).
// Returns one of:
//   { state: "verdict", result }  verdict, score and reasons
//   { state: "unreadable" }       no sender address was found in the page
//   { state: "failed" }           the model couldn't load or the analysis failed
async function analyzeEmail(request) {
  if (!isValidRequest(request)) {
    console.warn("PhishLens: the email wasn't read in the expected shape");
    return { state: "failed" };
  }
  // Every email has a sender address, so an empty one means gmail.js couldn't
  // read it (Gmail may still have been loading the message).
  if (request.sender_email === "") {
    return { state: "unreadable" };
  }
  let model;
  try {
    model = await getModel();
  } catch (error) {
    console.warn(`PhishLens: the model couldn't be loaded: ${error.message}`);
    return { state: "failed" };
  }
  try {
    return { state: "verdict", result: analyze(request, model) };
  } catch (error) {
    // Only the error's type is logged: its message could quote the email.
    console.warn(`PhishLens: the analysis failed (${error.name})`);
    return { state: "failed" };
  }
}

// The request must have the shape of the API contract in CLAUDE.md: four strings,
// links as { text, href } strings, and attachment names as strings.
function isValidRequest(request) {
  const isString = (value) => typeof value === "string";
  return (
    ["sender_name", "sender_email", "subject", "body_text"].every((key) =>
      isString(request?.[key])
    ) &&
    Array.isArray(request.links) &&
    request.links.every((link) => isString(link?.text) && isString(link?.href)) &&
    Array.isArray(request.attachments) &&
    request.attachments.every(isString)
  );
}

// For the popup: does the model load? Also returns its test scores.
async function checkStatus() {
  try {
    const model = await getModel();
    return { state: "ready", testMetrics: model.testMetrics };
  } catch (error) {
    console.warn(`PhishLens: the model couldn't be loaded: ${error.message}`);
    return { state: "error" };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only this extension's own popup and content scripts can send messages here
  // (manifest.json has no "externally_connectable"). Still, answer only the message
  // types we know.
  if (message?.type === "status") {
    checkStatus().then(sendResponse);
    // true means "I'll call sendResponse later". Without it Chrome closes the reply
    // channel as soon as this function returns.
    return true;
  }
  if (message?.type === "analyze") {
    analyzeEmail(message.request).then(sendResponse);
    return true;
  }
  return false;
});
