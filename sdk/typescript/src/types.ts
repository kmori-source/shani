/**
 * Shani Decision Governance Layer — Core Types (SPEC §4.1, §4.2, §4.3, §4.4)
 *
 * These types mirror the Python reference implementation in shani/schemas/.
 * All field names use snake_case to match the canonical JSON schema.
 */

/** Action types an agent may propose (SPEC §4.1) */
export type DecisionType =
  | "remediation"
  | "configuration_change"
  | "data_access"
  | "network_action"
  | "delegation"
  | "policy_update"
  | "browser_action"
  | "agent_task"
  | "tool_call";

/** Impact scope of a proposed action (SPEC §4.1) */
export type BlastRadius = "isolated" | "limited" | "significant" | "critical";

/** Decision System Autonomy Level 0–4 (SPEC §4.3) */
export type DSAL = 0 | 1 | 2 | 3 | 4;

/** Decision Integrity State (SPEC §4.4) */
export type DIS = "VALID" | "DEGRADED" | "VIOLATED";

/** Bounds on child delegation chains (SPEC §4.2) */
export interface DelegationRules {
  /** Whitelist of DecisionType values children may propose. Empty = no delegation. */
  allowed_sub_decisions: DecisionType[];
  /** Maximum D-SAL level a child ADO may authorize. */
  max_child_dsal: DSAL;
  /** Maximum delegation chain depth. */
  max_depth: number;
  /** Maximum number of direct child ADOs (fan-out prevention). */
  max_children: number;
}

/** Execution context included in the signed ADO payload (SPEC §4.2) */
export interface ExecContext {
  decision_type: DecisionType;
  intent_binding: string;
  parent_decision_id?: string;
  constraints: Record<string, unknown>;
  rollback_policy: string;
}

/**
 * A structured request from an agent to Shani (SPEC §4.1).
 *
 * MUST NOT be treated as authorization. It is a request only.
 */
export interface DecisionProposal {
  decision_id: string;
  decision_type: DecisionType;
  proposed_by: string;
  intent: string;
  reversibility: "reversible" | "irreversible";
  blast_radius: BlastRadius;
  evidence?: unknown[];
  context?: Record<string, unknown>;
  created_at: string; // ISO 8601
}

/**
 * Authorized Decision Object v5 — the exclusive authorization artifact (SPEC §4.2).
 *
 * An Execution Agent MUST NOT execute any action without a valid ADO.
 */
export interface AuthorizedDecisionObject {
  decision_id: string;
  proposal_hash: string;
  signature: string;
  authority: string;
  authorized_dsal: DSAL;
  delegation_rules: DelegationRules;
  nonce: string;
  issued_at: string; // ISO 8601
  expires_at: string; // ISO 8601
  exec_context: ExecContext;
  signature_chain?: string[];
  propagated_constraints?: Record<string, unknown>;
  origin_org?: string;
}

/** Returned when Shani denies a proposal */
export interface DeniedDecision {
  decision_id: string;
  reason: string;
  denied_at: string; // ISO 8601
}

/** Result of evaluating a proposal */
export type EvaluationResult =
  | { authorized: true; ado: AuthorizedDecisionObject }
  | { authorized: false; denial: DeniedDecision };

/** DIS state transition record (SPEC §4.4) */
export interface DisTransition {
  from_state: DIS;
  to_state: DIS;
  reason: string;
  timestamp: string; // ISO 8601
  triggered_by: string;
}

/** Posture evaluation outcome (SPEC §8.4) */
export type PostureOutcome = "PASS" | "REJECT" | "AMBIGUOUS";

/** Constraints declared in a UserPosture (SPEC §8.2) */
export interface PostureConstraints {
  target_scope: string;
  max_blast_radius: BlastRadius;
  reversibility_required: boolean;
  minimum_evidence: number;
}

/** A principal's expressed governance posture (SPEC §8.2) */
export interface UserPosture {
  version: string;
  principal_id: string;
  signed_at: string; // ISO 8601
  intent_statement: string;
  simulation_ref: string;
  constraints: PostureConstraints;
  posture_signature?: string;
}
