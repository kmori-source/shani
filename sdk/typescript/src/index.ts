/**
 * @shani/sdk — Shani Decision Governance Layer TypeScript SDK
 *
 * @example
 * ```typescript
 * import { ShaniEvaluator, createProposal, ExecutionBoundary } from "@shani/sdk";
 *
 * const evaluator = new ShaniEvaluator({ maxAuthorizedDsal: 2 });
 *
 * const proposal = createProposal({
 *   decision_type: "remediation",
 *   proposed_by: "agent-1",
 *   intent: "restart service svc-api",
 *   reversibility: "reversible",
 *   blast_radius: "limited",
 * });
 *
 * const result = evaluator.evaluate(proposal);
 * if (result.authorized) {
 *   const boundary = new ExecutionBoundary(evaluator);
 *   const cap = boundary.issueCapability(result.ado);
 *   cap.execute((ado) => {
 *     console.log("executing with authority:", ado.authority);
 *   });
 * }
 * ```
 */

export * from "./types.js";
export { DisStateMachine } from "./dis.js";
export { ShaniEvaluator, createProposal } from "./evaluator.js";
export { ExecutionBoundary, Capability } from "./boundary.js";
export { sha256Hex, hmacSign, hmacVerify, canonicalPayload } from "./crypto.js";
