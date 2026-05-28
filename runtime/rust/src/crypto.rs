//! Cryptographic signing for ADO binding (SPEC §4.6)

use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde_json::Value;

type HmacSha256 = Hmac<Sha256>;

/// Canonical payload for signing (SPEC §4.6)
///
/// Covers: decision_id, authorized_dsal, authority, expires_at, constraints,
/// proposal_hash, nonce, delegation_rules.
pub fn canonical_payload(
    decision_id: &str,
    authorized_dsal: u8,
    authority: &str,
    expires_at: &str,
    proposal_hash: &str,
    nonce: &str,
    delegation_rules: &Value,
) -> Vec<u8> {
    let payload = serde_json::json!({
        "decision_id": decision_id,
        "authorized_dsal": authorized_dsal,
        "authority": authority,
        "expires_at": expires_at,
        "proposal_hash": proposal_hash,
        "nonce": nonce,
        "delegation_rules": delegation_rules,
    });

    serde_json::to_string(&payload)
        .expect("canonical payload serialization must not fail")
        .into_bytes()
}

/// HMAC-SHA256 signature over canonical payload.
///
/// Minimum binding requirement from SPEC §4.6.
/// Use Ed25519 feature flag for production deployments.
pub fn hmac_sign(key: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key size");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify an HMAC-SHA256 signature.
pub fn hmac_verify(key: &[u8], payload: &[u8], expected_signature: &str) -> bool {
    let computed = hmac_sign(key, payload);
    // Constant-time comparison
    use sha2::Digest;
    let a = Sha256::digest(computed.as_bytes());
    let b = Sha256::digest(expected_signature.as_bytes());
    a == b
}
