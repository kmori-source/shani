/**
 * Shani Chrome Extension — Popup UI
 *
 * サイドカーの GET /pending をポーリングし、
 * 承認待ちリクエストを一覧表示する。
 * [承認] / [拒否] ボタンで POST /decision を呼ぶ。
 */

const SIDECAR = "http://127.0.0.1:7891";
const POLL_INTERVAL_MS = 3000;

const $cards = document.getElementById("cards");
const $empty = document.getElementById("empty");
const $dot = document.getElementById("status-dot");

// ── 残り時間フォーマット ────────────────────────────────────────────────────

function formatRemaining(isoString) {
  const diff = new Date(isoString) - Date.now();
  if (diff <= 0) return "タイムアウト";
  const min = Math.floor(diff / 60000);
  const sec = Math.floor((diff % 60000) / 1000);
  return min > 0 ? `残 ${min}分${sec}秒` : `残 ${sec}秒`;
}

// ── カード描画 ──────────────────────────────────────────────────────────────

function renderCard(req) {
  const card = document.createElement("div");
  card.className = "card";
  card.dataset.requestId = req.request_id;

  const evidenceHtml = req.evidence && req.evidence.length
    ? `<ul class="evidence-list">${req.evidence.map((e) => `<li>${e}</li>`).join("")}</ul>`
    : "";

  card.innerHTML = `
    <div class="card-header">
      <span class="card-action">${req.action || req.decision_type}</span>
      <span class="dsal-badge">D-SAL ${req.dsal}</span>
    </div>
    <div class="card-row"><span class="label">対象</span><span class="value">${req.target}</span></div>
    <div class="card-row"><span class="label">エージェント</span><span class="value">${req.proposed_by}</span></div>
    <div class="card-row"><span class="label">権限</span><span class="value">${req.required_authority}</span></div>
    <div class="card-row"><span class="label">Blast Radius</span><span class="value">${req.blast_radius}</span></div>
    ${evidenceHtml}
    <div class="timeout-row" data-timeout="${req.timeout_at}">${formatRemaining(req.timeout_at)}</div>
    <div class="card-actions">
      <button class="btn btn-approve" data-id="${req.request_id}">✓ 承認</button>
      <button class="btn btn-deny" data-id="${req.request_id}">✗ 拒否</button>
    </div>
  `;

  // ボタンイベント
  card.querySelector(".btn-approve").addEventListener("click", () => decide(req.request_id, "approve", card));
  card.querySelector(".btn-deny").addEventListener("click", () => decide(req.request_id, "deny", card));

  return card;
}

// ── 承認/拒否送信 ───────────────────────────────────────────────────────────

async function decide(requestId, action, card) {
  const btns = card.querySelectorAll(".btn");
  btns.forEach((b) => (b.disabled = true));

  try {
    const res = await fetch(`${SIDECAR}/decision`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        request_id: requestId,
        action,
        authority: "popup-user",
        note: action === "approve" ? "Approved via Shani popup" : "Denied via Shani popup",
      }),
    });
    const data = await res.json();
    if (data.ok) {
      card.style.opacity = "0.5";
      setTimeout(() => card.remove(), 600);
      poll(); // 即時更新
    } else {
      btns.forEach((b) => (b.disabled = false));
      alert(`エラー: ${data.error || "Unknown"}`);
    }
  } catch (err) {
    btns.forEach((b) => (b.disabled = false));
    alert(`サイドカー通信エラー: ${err.message}`);
  }
}

// ── タイムアウト表示の更新 ─────────────────────────────────────────────────

function updateTimeouts() {
  document.querySelectorAll(".timeout-row[data-timeout]").forEach((el) => {
    el.textContent = formatRemaining(el.dataset.timeout);
  });
}

setInterval(updateTimeouts, 1000);

// ── ポーリング ───────────────────────────────────────────────────────────────

async function poll() {
  try {
    const res = await fetch(`${SIDECAR}/pending`);
    const data = await res.json();
    const pending = data.pending || [];

    $dot.className = "ok";

    // 既存カードの ID セット
    const existingIds = new Set(
      [...$cards.querySelectorAll(".card")].map((c) => c.dataset.requestId)
    );
    const incomingIds = new Set(pending.map((r) => r.request_id));

    // 解消されたカードを削除
    for (const el of $cards.querySelectorAll(".card")) {
      if (!incomingIds.has(el.dataset.requestId)) el.remove();
    }

    // 新着カードを追加
    for (const req of pending) {
      if (!existingIds.has(req.request_id)) {
        $cards.appendChild(renderCard(req));
      }
    }

    $empty.style.display = pending.length ? "none" : "block";

    // バッジ更新
    const count = pending.length;
    chrome.action.setBadgeText({ text: count > 0 ? String(count) : "" });
    chrome.action.setBadgeBackgroundColor({ color: count > 0 ? "#e53e3e" : "#718096" });

  } catch {
    $dot.className = "error";
    $empty.style.display = "block";
    $empty.textContent = "サイドカーに接続できません (http://127.0.0.1:7891)";
  }
}

poll();
setInterval(poll, POLL_INTERVAL_MS);
