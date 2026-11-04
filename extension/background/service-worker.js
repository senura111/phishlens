// PhishLens service worker: the only part of the extension that talks to the local API.
//
// Chrome starts this script when a message arrives and stops it after about 30
// seconds of idle time, so nothing here may rely on variables surviving between
// messages.
//
// The API sends no CORS headers, so ordinary websites can't read its answers. This
// worker can, because manifest.json's host_permissions include http://127.0.0.1:8000/*.

const API_URL = "http://127.0.0.1:8000";
// The server answers /health instantly when it's running, so don't wait long.
const HEALTH_TIMEOUT_MS = 2000;
// An analysis takes well under a second (the slowest test input takes about 0.3 s).
const ANALYZE_TIMEOUT_MS = 10000;

const VERDICTS = ["phishing", "suspicious", "safe"];
const SEVERITIES = ["high", "medium", "low"];

// Asks GET /health whether the server is running.
// Returns { state: "running" } or { state: "offline" }.
async function checkHealth() {
  try {
    const response = await fetch(`${API_URL}/health`, {
      signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS),
    });
    const data = await response.json();
    // Something other than PhishLens could be answering on port 8000. Only our
    // server says {"status": "ok"}.
    const running = response.ok && data.status === "ok";
    return { state: running ? "running" : "offline" };
  } catch {
    // fetch throws when nothing is listening on the port or the timeout passes;
    // response.json() throws when the answer isn't JSON.
    return { state: "offline" };
  }
}

// Sends one email (already fitted to the API's limits by payload.js) to
// POST /analyze. Returns one of:
//   { state: "verdict", result }  the API's answer: verdict, score, reasons
//   { state: "offline" }          nothing is listening on 127.0.0.1:8000
//   { state: "unreadable" }       422: the email couldn't be read, e.g. no sender
//   { state: "failed" }           500, a timeout, or an answer we don't understand
async function analyzeEmail(request) {
  let response;
  try {
    response = await fetch(`${API_URL}/analyze`, {
      method: "POST",
      // The API only accepts JSON. fetch adds Content-Length itself.
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(ANALYZE_TIMEOUT_MS),
    });
  } catch (error) {
    // A timeout means the server is running but stuck; anything else means
    // nothing answered at all.
    return { state: error.name === "TimeoutError" ? "failed" : "offline" };
  }

  if (response.status === 422) {
    // The 422 lists which fields were wrong (never their values), which is what
    // we need to fix the extension.
    const locations = await errorLocations(response);
    console.warn(`PhishLens: /analyze answered 422 at ${locations}`);
    return { state: "unreadable" };
  }
  if (response.status !== 200) {
    // 500: the analysis failed. 400, 411, 413 or 415 would mean a bug in the
    // extension, since payload.js and this function build the request.
    console.warn(`PhishLens: /analyze answered ${response.status}`);
    return { state: "failed" };
  }

  try {
    const result = cleanResult(await response.json());
    if (result) {
      return { state: "verdict", result };
    }
  } catch {
    // Not JSON: something other than PhishLens is answering on port 8000.
  }
  console.warn("PhishLens: /analyze answered 200 with an unexpected body");
  return { state: "failed" };
}

// "body.sender_email, body.links.3.href" from a 422 answer's detail list.
async function errorLocations(response) {
  try {
    const { detail } = await response.json();
    return detail.map((error) => error.loc.join(".")).join(", ");
  } catch {
    return "(unknown fields)";
  }
}

// Returns the answer with only the fields of the API contract, or null if it
// doesn't match the contract. The banner can then rely on every field's type.
function cleanResult(data) {
  const reasonsOk =
    Array.isArray(data?.reasons) &&
    data.reasons.every(
      (reason) =>
        typeof reason?.id === "string" &&
        SEVERITIES.includes(reason.severity) &&
        typeof reason.message === "string"
    );
  if (!VERDICTS.includes(data?.verdict) || typeof data.score !== "number" || !reasonsOk) {
    return null;
  }
  return {
    verdict: data.verdict,
    score: data.score,
    reasons: data.reasons.map(({ id, severity, message }) => ({ id, severity, message })),
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only this extension's own popup and content scripts can send messages here
  // (manifest.json has no "externally_connectable"). Still, answer only the message
  // types we know.
  if (message?.type === "health") {
    checkHealth().then(sendResponse);
    // true means "I'll call sendResponse later". Without it Chrome closes the reply
    // channel as soon as this function returns, before fetch has finished.
    return true;
  }
  if (message?.type === "analyze") {
    analyzeEmail(message.request).then(sendResponse);
    return true;
  }
  return false;
});
