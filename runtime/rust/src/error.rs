use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShaniError {
    #[error("proposal denied: {reason}")]
    Denied { reason: String },

    #[error("DIS is {0:?} — all proposals suspended")]
    DisViolated(String),

    #[error("ADO verification failed: {0}")]
    VerificationFailed(String),

    #[error("ADO expired at {expires_at}")]
    Expired { expires_at: String },

    #[error("nonce already consumed — replay attack detected")]
    ReplayAttack,

    #[error("delegation constraint violated: {0}")]
    DelegationViolation(String),

    #[error("D-SAL ceiling exceeded: requested {requested}, ceiling {ceiling}")]
    DsalCeilingExceeded { requested: u8, ceiling: u8 },

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
