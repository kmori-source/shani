/**
 * Shani Chrome Extension — Background Service Worker
 *
 * The central hub of the Chrome extension. Receives messages from content.js / popup.js
 * and communicates with the local Shani sidecar (http://127.0.0.1:7891).
 *
 * Message types:
 *   shani_request  — from content.js: approval request for a browser action
 *   shani_collect  — from content.js: polling for HITL results
 *   shani_execute  — from content.js: execute action with an approved token
 *
 * Bug 3 fix:
 *   MV3 Service Workers stop when idle. When stopped, sendResponse
 *   callbacks are lost, so if shani_request returns "pending" we
 *   immediately return { status: "pending", request_id }.
 *   content.js periodically polls shani_collect to retrieve the result.
 */

const SIDECAR = "http://127.0.0.1:7891";
const BADGE_POLL_MS = 3000;

// ── Sidecar communication utilities ──────────────────────────────────────────

async function sidecarPost(path, body) {
  const res = await fetch(`${SIDECAR}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function sidecarGet(path) {
  const res = await fetch(`${SIDECAR}${path}`);
  return res.json();
}

// ── Badge update (show pending count) ────────────────────────────────────────

async function refreshBadge() {
  try {
    const data = await sidecarGet("/pending");
    const count = (data.pending || []).length;
    const text = count > 0 ? String(count) : "";
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color: count > 0 ? "#e53e3e" : "#718096" });
  } catch {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#718096" });
  }
}

setInterval(refreshBadge, BADGE_POLL_MS);
refreshBadge();

// ── webNavigation-based tab URL tracking (foundation for Bug 1 fix) ──────────
// Infrastructure for future detection and interception of navigations that bypass
// page-bridge.js (e.g. CDP operations or ISOLATED world).
// Currently only tracks the previous URL per tabId.

const _tabLastUrls = new Map(); // tabId → previous URL

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) _tabLastUrls.set(tabId, changeInfo.url);
});
chrome.tabs.onRemoved.addListener((tabId) => _tabLastUrls.delete(tabId));

// ── Message listener ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  if (message.type === "shani_request") {
    // Browser action approval request from content.js
    const body = {
      action: message.action,
      target: message.target,
      tab_url: sender.tab?.url || "",
      args: message.args || {},
      description: message.description || "",
      confidence: message.confidence || 0.8,
      evidence: message.evidence || [],
    };

    sidecarPost("/approve", body)
      .then((result) => {
        if (result.approved === null || result.status === "pending") {
          // Waiting for HITL: return request_id and let content.js poll.
          // Even if the Service Worker stops, content.js polling continues
          // so state is not lost (Bug 3 fix).
          sendResponse({ status: "pending", request_id: result.request_id });
        } else {
          // Immediate approval or denial
          sendResponse(result);
        }
        refreshBadge();
      })
      .catch((err) => {
        sendResponse({ approved: false, reason: `Sidecar error: ${err.message}` });
      });

    return true; // Keep async sendResponse alive

  } else if (message.type === "shani_execute") {
    // Execute action with an approved token
    sidecarPost("/execute", {
      token: message.token,
      operation: message.operation || "http_get",
      target: message.target,
      payload: message.payload,
    })
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ success: false, error: err.message }));

    return true;

  } else if (message.type === "shani_collect") {
    // HITL result polling from content.js (queries sidecar directly)
    sidecarPost("/collect", { request_id: message.request_id })
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ status: "pending", error: err.message }));

    return true;
  }
});
