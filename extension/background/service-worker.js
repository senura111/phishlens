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
  return false;
});
