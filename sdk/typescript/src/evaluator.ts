/**
 * Core Shani Evaluator (SPEC §5)
 */

import { randomUUID } from "node:crypto";
import type {
  AuthorizedDecisionObject,
  DecisionProposal,
  DelegationRules,
  DeniedDecision,
  DSAL,
  EvaluationResult,
  ExecContext,
} from "./types.js";
import { DisStateMachine } from "./dis.js";
import { canonicalPayload, hmacSign, hmacVerify, sha256Hex } from "./crypto.js";

export interface AuthorityConfig {
  maxAuthorizedDsal: DSAL;
  authorityName: string;
  signingKey: string;
  adoTtlSeconds: number;
}

const DEFAULT_CONFIG: AuthorityConfig = {
  maxAuthorizedDsal: 2,
  authorityName: "shani-authority",
  signingKey: "shani-dev-key-replace-in-production",
  adoTtlSeconds: 300,
};

/** D-SAL mapping from decision type (simplified — use policy YAML in production) */
const DSAL_MAP: Record<string, DSAL> = {
  remediation: 1,
  configuration_change: 2,
  data_access: 1,
  network_action: 3,
  delegation: 2,
  policy_update: 4,
  browser_action: 1,
  agent_task: 1,
  tool_call: 1,
};

/**
 * The core Shani evaluator (SPEC §5).
 *
 * Evaluates DecisionProposals and issues ADOs or DeniedDecisions.
 */
export class ShaniEvaluator {
  private readonly config: AuthorityConfig;
  private readonly dis: DisStateMachine;
  private readonly consumedNonces = new Set<string>();

  constructor(config: Partial<AuthorityConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.dis = new DisStateMachine();
  }

  get disStateMachine(): DisStateMachine {
    return this.dis;
  }

  /** Evaluate a proposal and return an ADO or denial (SPEC §5) */
  evaluate(proposal: DecisionProposal): EvaluationResult {
    // SPEC §4.4: DIS VALID required
    if (this.dis.getState() !== "VALID") {
      return {
        authorized: false,
        denial: {
          decision_id: proposal.decision_id,
          reason: `DIS is ${this.dis.getState()} — all proposals suspended`,
          denied_at: new Date().toISOString(),
        },
      };
    }

    const effectiveDsal = this.computeDsal(proposal);

    // SPEC §4.3: D-SAL ceiling enforcement
    if (effectiveDsal > this.config.maxAuthorizedDsal) {
      return {
        authorized: false,
        denial: {
          decision_id: proposal.decision_id,
          reason: `D-SAL ${effectiveDsal} exceeds ceiling ${this.config.maxAuthorizedDsal}`,
          denied_at: new Date().toISOString(),
        },
      };
    }

    try {
      const ado = this.issueAdo(proposal, effectiveDsal as DSAL);
      return { authorized: true, ado };
    } catch (err) {
      return {
        authorized: false,
        denial: {
          decision_id: proposal.decision_id,
          reason: String(err),
          denied_at: new Date().toISOString(),
        },
      };
    }
  }

  /** Verify an ADO before execution (SPEC §4.2) */
  verifyAdo(ado: AuthorizedDecisionObject): void {
    if (new Date(ado.expires_at) <= new Date()) {
      throw new Error(`ADO expired at ${ado.expires_at}`);
    }

    const payload = canonicalPayload(
      ado.decision_id,
      ado.authorized_dsal,
      ado.authority,
      ado.expires_at,
      ado.proposal_hash,
      ado.nonce,
      ado.delegation_rules,
    );

    if (!hmacVerify(this.config.signingKey, payload, ado.signature)) {
      throw new Error("ADO signature verification failed");
    }
  }

  /** Consume the nonce to prevent replay (SPEC §4.2) */
  registerExecuted(ado: AuthorizedDecisionObject): void {
    if (this.consumedNonces.has(ado.nonce)) {
      throw new Error("nonce already consumed — replay attack detected");
    }
    this.consumedNonces.add(ado.nonce);
  }

  private computeDsal(proposal: DecisionProposal): number {
    return DSAL_MAP[proposal.decision_type] ?? 1;
  }

  private issueAdo(proposal: DecisionProposal, effectiveDsal: DSAL): AuthorizedDecisionObject {
    const nonce = randomUUID();
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + this.config.adoTtlSeconds * 1000);
    const proposalHash = sha256Hex(JSON.stringify(proposal));

    const maxChildDsal = Math.max(0, effectiveDsal - 1) as DSAL;
    const delegationRules: DelegationRules = {
      allowed_sub_decisions: [],
      max_child_dsal: maxChildDsal,
      max_depth: 1,
      max_children: 0,
    };

    const payload = canonicalPayload(
      proposal.decision_id,
      effectiveDsal,
      this.config.authorityName,
      expiresAt.toISOString(),
      proposalHash,
      nonce,
      delegationRules,
    );
    const signature = hmacSign(this.config.signingKey, payload);

    const execContext: ExecContext = {
      decision_type: proposal.decision_type,
      intent_binding: proposal.intent,
      constraints: {},
      rollback_policy: "best_effort",
    };

    return {
      decision_id: proposal.decision_id,
      proposal_hash: proposalHash,
      signature,
      authority: this.config.authorityName,
      authorized_dsal: effectiveDsal,
      delegation_rules: delegationRules,
      nonce,
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
      exec_context: execContext,
    };
  }
}

/** Helper: create a proposal with a generated decision_id */
export function createProposal(
  opts: Omit<DecisionProposal, "decision_id" | "created_at">,
): DecisionProposal {
  return {
    decision_id: randomUUID(),
    created_at: new Date().toISOString(),
    ...opts,
  };
}
