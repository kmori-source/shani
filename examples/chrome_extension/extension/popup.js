/**
 * Shani Chrome Extension — Popup UI
 *
 * Polls GET /pending on the sidecar and displays a list of
 * pending approval requests.
 * Calls POST /decision via the [Approve] / [Deny] buttons.
 */

const SIDECAR = "http://127.0.0.1:7891";
const POLL_INTERVAL_MS = 3000;

const $cards = document.getElementById("cards");
const $empty = document.getElementById("empty");
const $dot = document.getElementById("status-dot");

// ── Remaining time formatter ───────────────────────────────────────────────────

function formatRemaining(isoString) {
  const diff = new Date(isoString) - Date.now();
  if (diff <= 0) return "Timeout";
  const min = Math.floor(diff / 60000);
  const sec = Math.floor((diff % 60000) / 1000);
  return min > 0 ? `${min}m ${sec}s remaining` : `${sec}s remaining`;
}

// ── Card rendering ─────────────────────────────────────────────────────────────

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
    <div class="card-row"><span class="label">Target</span><span class="value">${req.target}</span></div>
    <div class="card-row"><span class="label">Agent</span><span class="value">${req.proposed_by}</span></div>
    <div class="card-row"><span class="label">Authority</span><span class="value">${req.required_authority}</span></div>
    <div class="card-row"><span class="label">Blast Radius</span><span class="value">${req.blast_radius}</span></div>
    ${evidenceHtml}
    <div class="timeout-row" data-timeout="${req.timeout_at}">${formatRemaining(req.timeout_at)}</div>
    <div class="card-actions">
      <button class="btn btn-approve" data-id="${req.request_id}">✓ Approve</button>
      <button class="btn btn-deny" data-id="${req.request_id}">✗ Deny</button>
    </div>
  `;

  // Button events
  card.querySelector(".btn-approve").addEventListener("click", () => decide(req.request_id, "approve", card));
  card.querySelector(".btn-deny").addEventListener("click", () => decide(req.request_id, "deny", card));

  return card;
}

// ── Approve/deny submission ────────────────────────────────────────────────────

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
      poll(); // Immediate update
    } else {
      btns.forEach((b) => (b.disabled = false));
      alert(`Error: ${data.error || "Unknown"}`);
    }
  } catch (err) {
    btns.forEach((b) => (b.disabled = false));
    alert(`Sidecar communication error: ${err.message}`);
  }
}

// ── Timeout display update ─────────────────────────────────────────────────────

function updateTimeouts() {
  document.querySelectorAll(".timeout-row[data-timeout]").forEach((el) => {
    el.textContent = formatRemaining(el.dataset.timeout);
  });
}

setInterval(updateTimeouts, 1000);

// ── Polling ────────────────────────────────────────────────────────────────────

async function poll() {
  try {
    const res = await fetch(`${SIDECAR}/pending`);
    const data = await res.json();
    const pending = data.pending || [];

    $dot.className = "ok";

    // Existing card ID set
    const existingIds = new Set(
      [...$cards.querySelectorAll(".card")].map((c) => c.dataset.requestId)
    );
    const incomingIds = new Set(pending.map((r) => r.request_id));

    // Remove resolved cards
    for (const el of $cards.querySelectorAll(".card")) {
      if (!incomingIds.has(el.dataset.requestId)) el.remove();
    }

    // Add new cards
    for (const req of pending) {
      if (!existingIds.has(req.request_id)) {
        $cards.appendChild(renderCard(req));
      }
    }

    $empty.style.display = pending.length ? "none" : "block";

    // Badge update
    const count = pending.length;
    chrome.action.setBadgeText({ text: count > 0 ? String(count) : "" });
    chrome.action.setBadgeBackgroundColor({ color: count > 0 ? "#e53e3e" : "#718096" });

  } catch {
    $dot.className = "error";
    $empty.style.display = "block";
    $empty.textContent = "Cannot connect to sidecar (http://127.0.0.1:7891)";
  }
}

poll();
setInterval(poll, POLL_INTERVAL_MS);
