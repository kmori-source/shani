/**
 * Shani Chrome Extension — Content Script
 *
 * A bridge that allows AI agents on the page to request browser operations
 * through Shani governance.
 *
 * Path A — when page JS dispatches a CustomEvent directly:
 *
 *   window.dispatchEvent(new CustomEvent("shani:request", {
 *     detail: {
 *       requestId: "my-req-001",
 *       action: "navigate",
 *       target: "https://example.com",
 *       description: "Page navigation per user instruction",
 *       confidence: 0.9,
 *     }
 *   }));
 *
 *   window.addEventListener("shani:response", (e) => { ... });
 *
 * Path B — when auto-intercepting browser API calls from Claude in Chrome
 *           via page-bridge.js (MAIN world):
 *           page-bridge.js notifies via window.postMessage.
 *
 * Bug 3 fix:
 *   To handle MV3 Service Worker stops, HITL pending state is resolved via
 *   shani_collect polling rather than sendResponse callbacks.
 */

const _POLL_INTERVAL_MS = 2000;

// ── HITL result polling ───────────────────────────────────────────────────────

/**
 * Polls shani_collect until request_id is resolved,
 * then calls replyFn(result).
 * Even if the Service Worker restarts, each poll is an independent message
 * so state is not lost.
 */
function _pollForResult(requestId, replyFn) {
  const timer = setInterval(() => {
    chrome.runtime.sendMessage(
      { type: "shani_collect", request_id: requestId },
      (result) => {
        if (chrome.runtime.lastError || !result) return; // Transient error, retry next time
        if (result.status === "pending") return;         // Still waiting
        clearInterval(timer);
        replyFn(result);
      }
    );
  }, _POLL_INTERVAL_MS);
}

// ── Common: send request to background and return result ──────────────────────

function forwardToBackground(detail, replyFn) {
  chrome.runtime.sendMessage(
    {
      type: "shani_request",
      action: detail.action,
      target: detail.target,
      args: detail.args || {},
      description: detail.description || "",
      confidence: detail.confidence || 0.8,
      evidence: detail.evidence || [],
    },
    (result) => {
      if (chrome.runtime.lastError) {
        replyFn({ approved: false, reason: "Background communication error" });
        return;
      }
      if (result && result.status === "pending" && result.request_id) {
        // Switch to polling so we can continue even if the Service Worker stops
        _pollForResult(result.request_id, replyFn);
      } else {
        replyFn(result);
      }
    }
  );
}

// ── Path A: CustomEvent ("shani:request") ────────────────────────────────────

window.addEventListener("shani:request", (event) => {
  const detail = event.detail || {};
  const clientRequestId = detail.requestId;

  forwardToBackground(detail, (result) => {
    window.dispatchEvent(
      new CustomEvent("shani:response", {
        detail: { requestId: clientRequestId, result },
      })
    );
  });
});

// ── Path B: postMessage from page-bridge.js (MAIN world) ─────────────────────

window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  if (!event.data || event.data.type !== "shani:request") return;

  const data = event.data;
  const requestId = data.requestId;

  forwardToBackground(data, (result) => {
    window.postMessage(
      { type: "shani:response", requestId, result },
      "*"
    );
  });
});
