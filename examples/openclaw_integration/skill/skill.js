/**
 * OpenClaw Skill: shani-governed-api
 *
 * Routes all external API operations through the Shani sidecar for approval.
 *
 * Location:
 *   .agents/skills/shani-governed-api/skill.js
 *
 * SKILL.md describes this skill to the OpenClaw Brain so it knows when to invoke it.
 *
 * Usage (speak to OpenClaw):
 *   "Check the status of api.example.com"
 *   → D-SAL 1 (GET) → auto-approved → return result
 *
 *   "Send the report to api.example.com/reports"
 *   → D-SAL 2 (POST) → HITL required → execute after approval
 */

const SIDECAR_URL = process.env.SHANI_SIDECAR_URL || "http://127.0.0.1:8765";

/**
 * Request a capability token from the Shani sidecar.
 *
 * D-SAL 1 (low risk): returns a token immediately.
 * D-SAL 2+ (HITL):    returns a request_id; poll /collect until approved.
 *
 * The caller does NOT declare a D-SAL level.
 * Shani computes it from decision_type + context (blast_radius, target, evidence).
 */
async function requestCapability({
  decisionType,    // "data_access" | "configuration_change" | "remediation" | "network_action"
  target,          // target URL or resource path
  description,     // what the operation does
  evidence = [],   // [{ source, content, confidence }]
  blastRadius = "limited",
}) {
  const res = await fetch(`${SIDECAR_URL}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      decision_type: decisionType,
      target,
      description,
      evidence,
      blast_radius: blastRadius,
      confidence: 0.85,
      reversibility: true,
      // Note: D-SAL is NOT declared here. Shani computes it from context.
    }),
  });

  const data = await res.json();

  if (data.approved === true) {
    // Auto-approved (low risk)
    console.log(`[Shani] Auto-approved | token=${data.token.slice(0, 8)}... ops=${data.allowed_ops}`);
    return { token: data.token, pending: false };
  }

  if (data.status === "pending") {
    // HITL: return request_id for polling
    console.log(`[Shani] HITL pending | request_id=${data.request_id.slice(0, 8)}...`);
    return { requestId: data.request_id, pending: true };
  }

  throw new Error(`Shani denied: ${data.reason}`);
}

/**
 * Poll /collect until the HITL decision is made.
 * Returns the token on approval, or throws on denial.
 */
async function collectToken(requestId, maxAttempts = 60, intervalMs = 2000) {
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, intervalMs));
    const res = await fetch(`${SIDECAR_URL}/collect`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ request_id: requestId }),
    });
    const data = await res.json();
    if (data.status === "pending") continue;
    if (data.approved) return data.token;
    throw new Error(`Shani denied: ${data.reason}`);
  }
  throw new Error("HITL approval timed out");
}

/**
 * Execute an operation using a capability token.
 * The token is single-use: any second call is rejected.
 */
async function executeWithToken({ token, operation, target, payload = {}, content = "" }) {
  const res = await fetch(`${SIDECAR_URL}/execute`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, operation, target, payload, content }),
  });

  const data = await res.json();
  if (!data.success) {
    throw new Error(`Execution failed: ${data.error} (${data.type})`);
  }
  return data.result;
}

/**
 * Governed HTTP GET — D-SAL 1 (typically auto-approved).
 *
 * Before (ungoverned):
 *   const result = await fetch(url).then(r => r.json());
 *
 * After (governed):
 *   const result = await governedGet(url);
 */
export async function governedGet(url, { evidence = [] } = {}) {
  const cap = await requestCapability({
    decisionType: "data_access",
    target: url,
    description: `GET ${url}`,
    blastRadius: "isolated",
    evidence,
  });

  const token = cap.pending ? await collectToken(cap.requestId) : cap.token;
  return executeWithToken({ token, operation: "http_get", target: url });
}

/**
 * Governed HTTP POST — D-SAL 2 (HITL required).
 *
 * Before (ungoverned):
 *   const result = await fetch(url, { method: "POST", body: JSON.stringify(payload) });
 *
 * After (governed):
 *   const result = await governedPost(url, payload, { evidence: [...] });
 */
export async function governedPost(url, payload, { evidence = [] } = {}) {
  const cap = await requestCapability({
    decisionType: "configuration_change",
    target: url,
    description: `POST ${url}`,
    blastRadius: "limited",
    evidence,
  });

  const token = cap.pending ? await collectToken(cap.requestId) : cap.token;
  return executeWithToken({ token, operation: "http_post", target: url, payload });
}

/**
 * Governed shell command — D-SAL 2 (HITL required).
 */
export async function governedCommand(cmd, { evidence = [] } = {}) {
  const cap = await requestCapability({
    decisionType: "remediation",
    target: cmd,
    description: `run: ${cmd}`,
    blastRadius: "significant",
    evidence,
  });

  const token = cap.pending ? await collectToken(cap.requestId) : cap.token;
  return executeWithToken({ token, operation: "run_command", target: cmd });
}

// ─────────────────────────────────────────────────────────────────────────────
// OpenClaw Skill handler — called by the Brain's ReAct loop
// ─────────────────────────────────────────────────────────────────────────────

/**
 * OpenClaw calls this function when it decides to use this skill.
 *
 * @param {Object} params
 * @param {string} params.action   - "get" | "post" | "command"
 * @param {string} params.target   - URL or command string
 * @param {Object} [params.payload] - POST body
 * @param {string} [params.context] - Brain context (used as evidence)
 */
export async function handler({ action, target, payload, context }) {
  const evidence = context
    ? [{ source: "openclaw-brain", content: context, confidence: 0.8 }]
    : [];

  try {
    switch (action) {
      case "get":     return await governedGet(target, { evidence });
      case "post":    return await governedPost(target, payload || {}, { evidence });
      case "command": return await governedCommand(target, { evidence });
      default:        return { error: `Unknown action: ${action}` };
    }
  } catch (err) {
    // If Shani denies, report the reason to OpenClaw Brain
    return {
      denied: true,
      reason: err.message,
      suggestion: "This operation was blocked by Shani. Check with an authorized approver.",
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HITL decision webhook (called by Slack bot or Web UI)
// ─────────────────────────────────────────────────────────────────────────────

/** List pending HITL approvals. Called by /shani-pending Slack command. */
export async function listPending() {
  const res = await fetch(`${SIDECAR_URL}/pending`);
  return res.json();
}

/**
 * Approve or deny a pending HITL request.
 * Called when an operator clicks a button in Slack or the Web UI.
 *
 * @param {string} requestId
 * @param {"approve"|"deny"} action
 * @param {string} authority  - approver identifier (e.g. "alice@example.com")
 * @param {string} [note]
 */
export async function decide(requestId, action, authority, note = "") {
  const res = await fetch(`${SIDECAR_URL}/decision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request_id: requestId, action, authority, note }),
  });
  return res.json();
}
