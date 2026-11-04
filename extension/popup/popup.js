// Popup: shows whether the local API is running. It asks the service worker instead
// of calling the API itself, so every API call lives in one file.

const statusElement = document.getElementById("status");
const helpElement = document.getElementById("help");

function showStatus(state) {
  if (state === "running") {
    statusElement.textContent = "The local server is running.";
    statusElement.className = "status status-running";
    helpElement.hidden = true;
  } else {
    statusElement.textContent = "The local server is not running, so emails can't be checked.";
    statusElement.className = "status status-offline";
    helpElement.hidden = false;
  }
}

chrome.runtime
  .sendMessage({ type: "health" })
  .then((response) => showStatus(response?.state))
  // sendMessage fails if the service worker couldn't start or didn't answer.
  .catch(() => showStatus("offline"));
