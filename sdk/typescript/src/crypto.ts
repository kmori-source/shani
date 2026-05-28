/**
 * Cryptographic signing for ADO binding (SPEC §4.6)
 *
 * Uses the Node.js built-in `crypto` module (no external dependencies).
 * Ed25519 support requires Node.js >= 15 with SubtleCrypto.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { DelegationRules } from "./types.js";

/**
 * SHA-256 hash of canonical JSON (SPEC §4.6).
 */
export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Builds the canonical signing payload for an ADO (SPEC §4.6).
 *
 * Covers: decision_id, authorized_dsal, authority, expires_at, proposal_hash,
 * nonce, delegation_rules.
 */
export function canonicalPayload(
  decisionId: string,
  authorizedDsal: number,
  authority: string,
  expiresAt: string,
  proposalHash: string,
  nonce: string,
  delegationRules: DelegationRules,
): string {
  return JSON.stringify({
    decision_id: decisionId,
    authorized_dsal: authorizedDsal,
    authority,
    expires_at: expiresAt,
    proposal_hash: proposalHash,
    nonce,
    delegation_rules: delegationRules,
  });
}

/**
 * HMAC-SHA256 signature over canonical payload (SPEC §4.6 minimum requirement).
 */
export function hmacSign(key: string, payload: string): string {
  return createHmac("sha256", key).update(payload, "utf8").digest("hex");
}

/**
 * Verify an HMAC-SHA256 signature using timing-safe comparison.
 */
export function hmacVerify(key: string, payload: string, expected: string): boolean {
  const computed = hmacSign(key, payload);
  const a = Buffer.from(computed, "hex");
  const b = Buffer.from(expected, "hex");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
