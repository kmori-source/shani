/**
 * DIS State Machine (SPEC §4.4)
 */

import type { DIS, DisTransition } from "./types.js";

/** Legal DIS transitions */
const ALLOWED_TRANSITIONS = new Set<string>([
  "VALID->DEGRADED",
  "VALID->VIOLATED",
  "DEGRADED->VALID",
  "DEGRADED->VIOLATED",
]);

/**
 * The DIS State Machine governs Shani's integrity posture.
 *
 * Transitions are explicit and logged. VIOLATED → VALID requires
 * explicit reset with documented justification (SPEC §4.4).
 */
export class DisStateMachine {
  private state: DIS = "VALID";
  private history: DisTransition[] = [];

  getState(): DIS {
    return this.state;
  }

  getHistory(): readonly DisTransition[] {
    return this.history;
  }

  /**
   * Attempt a state transition. VIOLATED → VALID must use resetToValid().
   */
  transition(to: DIS, reason: string, triggeredBy: string): DisTransition {
    if (this.state === "VIOLATED" && to === "VALID") {
      throw new Error(
        "Use resetToValid() with justification to recover from VIOLATED state",
      );
    }

    const key = `${this.state}->${to}`;
    if (!ALLOWED_TRANSITIONS.has(key) && this.state !== to) {
      throw new Error(`Illegal DIS transition: ${this.state} → ${to}`);
    }

    const record: DisTransition = {
      from_state: this.state,
      to_state: to,
      reason,
      timestamp: new Date().toISOString(),
      triggered_by: triggeredBy,
    };
    this.history.push(record);
    this.state = to;
    this.logTransition(record);
    return record;
  }

  /**
   * Reset DIS from VIOLATED to VALID (SPEC §4.4).
   *
   * Requires non-empty justification and named human authority.
   */
  resetToValid(justification: string, authorizedBy: string): DisTransition {
    if (this.state !== "VIOLATED") {
      throw new Error(
        `resetToValid() may only be called from VIOLATED state. Current: ${this.state}`,
      );
    }
    if (!justification.trim()) {
      throw new Error("justification must not be empty");
    }
    if (!authorizedBy.trim()) {
      throw new Error("authorizedBy must name a human authority");
    }

    const record: DisTransition = {
      from_state: "VIOLATED",
      to_state: "VALID",
      reason: `MANUAL RESET — ${justification}`,
      timestamp: new Date().toISOString(),
      triggered_by: authorizedBy,
    };
    this.history.push(record);
    this.state = "VALID";
    this.logTransition(record);
    return record;
  }

  private logTransition(record: DisTransition): void {
    console.info("[shani.dis.audit] DIS transition:", JSON.stringify(record));
  }
}
