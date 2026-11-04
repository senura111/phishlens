// Popup: shows whether the analyser is ready, i.e. the service worker could load the
// model that ships inside the extension.

const statusElement = document.getElementById("status");

function showStatus(response) {
  if (response?.state === "ready") {
    statusElement.textContent = "Ready: emails are checked inside your browser.";
    statusElement.className = "status status-ready";
  } else {
    statusElement.textContent =
      "The analyser couldn't start, so emails can't be checked. Try reloading the extension.";
    statusElement.className = "status status-error";
  }
}

chrome.runtime
  .sendMessage({ type: "status" })
  .then(showStatus)
  // sendMessage fails if the service worker couldn't start or didn't answer.
  .catch(() => showStatus(null));
