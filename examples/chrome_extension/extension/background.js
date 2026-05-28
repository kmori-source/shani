/**
 * Shani Chrome Extension — Background Service Worker
 *
 * Chrome拡張の中枢。content.js / popup.js からのメッセージを受信し、
 * ローカル Shani サイドカー (http://127.0.0.1:7891) と通信する。
 *
 * メッセージ種別:
 *   shani_request  — content.js から: ブラウザアクションの承認申請
 *   shani_collect  — content.js から: HITL 結果のポーリング
 *   shani_execute  — content.js から: 承認済みトークンでアクション実行
 *
 * Bug 3 対応:
 *   MV3 Service Worker はアイドル時に停止する。停止すると sendResponse
 *   コールバックが失われるため、shani_request が "pending" の場合は
 *   即座に { status: "pending", request_id } を返す。
 *   content.js が shani_collect を定期ポーリングして結果を取得する。
 */

const SIDECAR = "http://127.0.0.1:7891";
const BADGE_POLL_MS = 3000;

// ── サイドカー通信ユーティリティ ──────────────────────────────────────────

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

// ── バッジ更新（未決件数を表示）──────────────────────────────────────────

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

// ── webNavigation ベースのタブ URL トラッキング (Bug 1 対策の基盤) ─────────
// page-bridge.js をバイパスしたナビゲーション（CDP 操作や ISOLATED world）を
// 将来的に検知・インターセプトするためのインフラ。
// 現時点では前 URL を tabId ごとに追跡するのみ。

const _tabLastUrls = new Map(); // tabId → 直前の URL

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) _tabLastUrls.set(tabId, changeInfo.url);
});
chrome.tabs.onRemoved.addListener((tabId) => _tabLastUrls.delete(tabId));

// ── メッセージリスナー ────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  if (message.type === "shani_request") {
    // content.js からのブラウザアクション承認申請
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
          // HITL 待機中: request_id を返し、content.js 側でポーリングさせる。
          // Service Worker が停止しても content.js のポーリングは継続するため
          // 状態が失われない（Bug 3 修正）。
          sendResponse({ status: "pending", request_id: result.request_id });
        } else {
          // 即時承認 or 拒否
          sendResponse(result);
        }
        refreshBadge();
      })
      .catch((err) => {
        sendResponse({ approved: false, reason: `Sidecar error: ${err.message}` });
      });

    return true; // 非同期 sendResponse を維持

  } else if (message.type === "shani_execute") {
    // 承認済みトークンでアクション実行
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
    // content.js からの HITL 結果ポーリング（サイドカーに直接問い合わせ）
    sidecarPost("/collect", { request_id: message.request_id })
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ status: "pending", error: err.message }));

    return true;
  }
});
