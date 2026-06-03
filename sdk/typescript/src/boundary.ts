/**
 * Execution Boundary — enforces that no action runs without a valid ADO (SPEC §7)
 */

import type { AuthorizedDecisionObject } from "./types.js";
import type { ShaniEvaluator } from "./evaluator.js";

/**
 * A Capability grants the right to execute exactly one action (SPEC §7.2).
 *
 * Single-use. Agents MUST NOT cache or reuse Capabilities.
 */
export class Capability {
  private used = false;

  constructor(private readonly ado: AuthorizedDecisionObject) {}

  getAdo(): AuthorizedDecisionObject {
    return this.ado;
  }

  /**
   * Execute an action gated by this capability (single-use).
   */
  execute<T>(action: (ado: AuthorizedDecisionObject) => T): T {
    if (this.used) {
      throw new Error("capability already used — capabilities are single-use");
    }
    this.used = true;
    return action(this.ado);
  }
}

/**
 * Enforces that execution only happens through a valid, verified ADO.
 */
export class ExecutionBoundary {
  constructor(private readonly evaluator: ShaniEvaluator) {}

  /**
   * Verify an ADO and issue a Capability.
   *
   * Verifies signature and expiry, then consumes the nonce.
   */
  issueCapability(ado: AuthorizedDecisionObject): Capability {
    this.evaluator.verifyAdo(ado);
    this.evaluator.registerExecuted(ado);
    return new Capability(ado);
  }
}
