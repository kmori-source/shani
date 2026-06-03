//! Decision Proposal and ADO v5 schemas (SPEC §4.1, §4.2)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schemas::state::Dsal;

/// Action types an agent may propose (SPEC §4.1)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionType {
    Remediation,
    ConfigurationChange,
    DataAccess,
    NetworkAction,
    Delegation,
    PolicyUpdate,
    BrowserAction,
    AgentTask,
    ToolCall,
}

/// Blast radius of a proposed action (SPEC §4.1)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadius {
    Isolated,
    Limited,
    Significant,
    Critical,
}

/// Bounds on child delegation chains (SPEC §4.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRules {
    /// Whitelist of DecisionType values children may propose. Empty = no delegation.
    pub allowed_sub_decisions: Vec<String>,
    /// Maximum D-SAL level a child ADO may authorize.
    pub max_child_dsal: u8,
    /// Maximum depth of the delegation chain.
    pub max_depth: u8,
    /// Maximum number of direct child ADOs (fan-out prevention).
    pub max_children: u8,
}

impl Default for DelegationRules {
    fn default() -> Self {
        Self {
            allowed_sub_decisions: vec![],
            max_child_dsal: 0,
            max_depth: 1,
            max_children: 0,
        }
    }
}

/// Execution context included in the signed ADO payload (SPEC §4.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecContext {
    pub decision_type: DecisionType,
    pub intent_binding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_decision_id: Option<String>,
    pub constraints: serde_json::Value,
    pub rollback_policy: String,
}

/// A structured request from an agent to Shani (SPEC §4.1)
///
/// MUST NOT be treated as authorization. It is a request only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionProposal {
    pub decision_id: String,
    pub decision_type: DecisionType,
    pub proposed_by: String,
    pub intent: String,
    pub reversibility: String,
    pub blast_radius: BlastRadius,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

impl DecisionProposal {
    pub fn builder() -> DecisionProposalBuilder {
        DecisionProposalBuilder::default()
    }

    /// SHA-256 of canonical JSON (SPEC §4.6)
    pub fn canonical_hash(&self) -> String {
        let canonical = serde_json::to_string(self)
            .expect("proposal serialization must not fail");
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(canonical.as_bytes());
        hex::encode(hash)
    }
}

#[derive(Default)]
pub struct DecisionProposalBuilder {
    decision_type: Option<DecisionType>,
    proposed_by: Option<String>,
    intent: Option<String>,
    reversibility: Option<String>,
    blast_radius: Option<BlastRadius>,
}

impl DecisionProposalBuilder {
    pub fn decision_type(mut self, dt: DecisionType) -> Self {
        self.decision_type = Some(dt);
        self
    }

    pub fn proposed_by(mut self, v: impl Into<String>) -> Self {
        self.proposed_by = Some(v.into());
        self
    }

    pub fn intent(mut self, v: impl Into<String>) -> Self {
        self.intent = Some(v.into());
        self
    }

    pub fn blast_radius(mut self, br: BlastRadius) -> Self {
        self.blast_radius = Some(br);
        self
    }

    pub fn reversible(mut self, v: bool) -> Self {
        self.reversibility = Some(if v { "reversible" } else { "irreversible" }.to_string());
        self
    }

    pub fn build(self) -> DecisionProposal {
        DecisionProposal {
            decision_id: Uuid::new_v4().to_string(),
            decision_type: self.decision_type.expect("decision_type is required"),
            proposed_by: self.proposed_by.expect("proposed_by is required"),
            intent: self.intent.unwrap_or_default(),
            reversibility: self.reversibility.unwrap_or_else(|| "reversible".to_string()),
            blast_radius: self.blast_radius.expect("blast_radius is required"),
            evidence: None,
            context: None,
            created_at: Utc::now(),
        }
    }
}

/// Authorized Decision Object v5 — the exclusive authorization artifact (SPEC §4.2)
///
/// An Execution Agent MUST NOT execute any action without a valid ADO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedDecisionObject {
    pub decision_id: String,
    pub proposal_hash: String,
    pub signature: String,
    pub authority: String,
    pub authorized_dsal: u8,
    pub delegation_rules: DelegationRules,
    pub nonce: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub exec_context: ExecContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_chain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub propagated_constraints: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_org: Option<String>,
}

impl AuthorizedDecisionObject {
    /// Returns true if this ADO is expired (SPEC §4.2)
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}
