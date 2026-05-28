//! Posture Layer schemas (SPEC §8.2)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Result of PostureEngine evaluation (SPEC §8.4)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PostureOutcome {
    Pass,
    Reject,
    Ambiguous,
}

/// Constraints declared in a UserPosture (SPEC §8.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureConstraints {
    /// Regex or glob pattern for allowed targets, e.g. "host:dev-*"
    pub target_scope: String,
    /// Maximum blast radius: isolated | limited | significant | critical
    pub max_blast_radius: String,
    /// If true, irreversible proposals are REJECTED
    pub reversibility_required: bool,
    /// Minimum number of evidence items required
    pub minimum_evidence: u32,
}

/// A principal's expressed governance posture (SPEC §8.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPosture {
    pub version: String,
    pub principal_id: String,
    pub signed_at: DateTime<Utc>,
    pub intent_statement: String,
    pub simulation_ref: String,
    pub constraints: PostureConstraints,
    pub posture_signature: Option<String>,
}

/// Issued when PostureEngine returns AMBIGUOUS — requires human refinement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureRefinementRequest {
    pub decision_id: String,
    pub proposal_intent: String,
    pub ambiguity_reason: String,
    pub suggested_constraints: Option<PostureConstraints>,
}
