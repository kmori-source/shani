/**
 * Shani Chrome Extension — Content Script
 *
 * ページ内の AI エージェントが Shani ガバナンスを通じてブラウザ操作を
 * 要求できるようにするブリッジ。
 *
 * Path A — ページ JS が直接 CustomEvent を dispatch する場合:
 *
 *   window.dispatchEvent(new CustomEvent("shani:request", {
 *     detail: {
 *       requestId: "my-req-001",
 *       action: "navigate",
 *       target: "https://example.com",
 *       description: "ユーザーの指示でページ遷移",
 *       confidence: 0.9,
 *     }
 *   }));
 *
 *   window.addEventListener("shani:response", (e) => { ... });
 *
 * Path B — page-bridge.js (MAIN world) 経由で Claude in Chrome の
 *           ブラウザ API 呼び出しを自動インターセプトする場合:
 *           page-bridge.js が window.postMessage を使って通知してくる。
 *
 * Bug 3 対応:
 *   MV3 Service Worker の停止に備え、HITL pending 状態は sendResponse
 *   コールバックではなく shani_collect ポーリングで解決する。
 */

const _POLL_INTERVAL_MS = 2000;

// ── HITL 結果ポーリング ───────────────────────────────────────────────────

/**
 * request_id が解決するまで shani_collect をポーリングし、
 * 解決したら replyFn(result) を呼ぶ。
 * Service Worker が再起動しても各ポーリングが独立したメッセージなので
 * 状態が失われない。
 */
function _pollForResult(requestId, replyFn) {
  const timer = setInterval(() => {
    chrome.runtime.sendMessage(
      { type: "shani_collect", request_id: requestId },
      (result) => {
        if (chrome.runtime.lastError || !result) return; // 一時エラー、次回リトライ
        if (result.status === "pending") return;         // まだ待機中
        clearInterval(timer);
        replyFn(result);
      }
    );
  }, _POLL_INTERVAL_MS);
}

// ── 共通: background へリクエストを送り、結果を返す ────────────────────────

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
        // Service Worker が停止しても継続できるよう、ポーリングに切り替える
        _pollForResult(result.request_id, replyFn);
      } else {
        replyFn(result);
      }
    }
  );
}

// ── Path A: CustomEvent ("shani:request") ────────────────────────────────

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

// ── Path B: postMessage from page-bridge.js (MAIN world) ─────────────────

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
