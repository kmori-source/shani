//! Core Shani Evaluator (SPEC §5)

use std::collections::HashSet;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::crypto;
use crate::dis::DisStateMachine;
use crate::error::ShaniError;
use crate::schemas::decision::{
    AuthorizedDecisionObject, DecisionProposal, DelegationRules, ExecContext,
};
use crate::schemas::state::{Dis, Dsal};

/// Outcome of evaluating a proposal
pub enum EvaluationResult {
    Authorized(AuthorizedDecisionObject),
    Denied(DeniedDecision),
}

/// Returned when Shani denies a proposal
pub struct DeniedDecision {
    pub decision_id: String,
    pub reason: String,
    pub denied_at: chrono::DateTime<Utc>,
}

/// Authority configuration for the evaluator
pub struct AuthorityConfig {
    pub max_authorized_dsal: u8,
    pub authority_name: String,
    pub signing_key: Vec<u8>,
    pub ado_ttl_seconds: i64,
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            max_authorized_dsal: 2,
            authority_name: "shani-authority".to_string(),
            signing_key: b"shani-dev-key-replace-in-production".to_vec(),
            ado_ttl_seconds: 300,
        }
    }
}

/// The core Shani evaluator (SPEC §5)
///
/// Evaluates a DecisionProposal and issues an ADO or DeniedDecision.
///
/// Invariants enforced:
/// - DIS must be VALID to authorize any proposal (SPEC §4.4)
/// - D-SAL ceiling must not be exceeded (SPEC §4.3)
/// - Delegation rules anti-escalation invariant (SPEC §4.2)
/// - Nonce consumed on execution to prevent replay (SPEC §4.2)
pub struct ShaniEvaluator {
    config: AuthorityConfig,
    dis: DisStateMachine,
    consumed_nonces: HashSet<String>,
}

impl ShaniEvaluator {
    pub fn builder() -> ShaniEvaluatorBuilder {
        ShaniEvaluatorBuilder::default()
    }

    pub fn new(config: AuthorityConfig) -> Self {
        Self {
            config,
            dis: DisStateMachine::new(),
            consumed_nonces: HashSet::new(),
        }
    }

    /// Current DIS state
    pub fn dis_state(&self) -> Dis {
        self.dis.state()
    }

    /// Evaluate a proposal and return an ADO or denial (SPEC §5)
    pub fn evaluate(&mut self, proposal: &DecisionProposal) -> EvaluationResult {
        // SPEC §4.4: DIS VALID required
        if !self.dis.state().allows_execution() {
            return EvaluationResult::Denied(DeniedDecision {
                decision_id: proposal.decision_id.clone(),
                reason: format!("DIS is {:?} — all proposals suspended", self.dis.state()),
                denied_at: Utc::now(),
            });
        }

        // Compute effective D-SAL from decision type
        let effective_dsal = self.compute_dsal(proposal);

        // SPEC §4.3: D-SAL ceiling enforcement
        if effective_dsal > self.config.max_authorized_dsal {
            return EvaluationResult::Denied(DeniedDecision {
                decision_id: proposal.decision_id.clone(),
                reason: format!(
                    "D-SAL {effective_dsal} exceeds ceiling {}",
                    self.config.max_authorized_dsal
                ),
                denied_at: Utc::now(),
            });
        }

        // Issue ADO
        match self.issue_ado(proposal, effective_dsal) {
            Ok(ado) => EvaluationResult::Authorized(ado),
            Err(e) => EvaluationResult::Denied(DeniedDecision {
                decision_id: proposal.decision_id.clone(),
                reason: e.to_string(),
                denied_at: Utc::now(),
            }),
        }
    }

    /// Verify an ADO before execution
    pub fn verify_ado(&self, ado: &AuthorizedDecisionObject) -> Result<(), ShaniError> {
        // SPEC §4.2: ADO must not be used after expires_at
        if ado.is_expired() {
            return Err(ShaniError::Expired {
                expires_at: ado.expires_at.to_rfc3339(),
            });
        }

        // Verify signature
        let payload = crypto::canonical_payload(
            &ado.decision_id,
            ado.authorized_dsal,
            &ado.authority,
            &ado.expires_at.to_rfc3339(),
            &ado.proposal_hash,
            &ado.nonce,
            &serde_json::to_value(&ado.delegation_rules).unwrap_or_default(),
        );
        if !crypto::hmac_verify(&self.config.signing_key, &payload, &ado.signature) {
            return Err(ShaniError::VerificationFailed("signature mismatch".into()));
        }

        Ok(())
    }

    /// Register that an ADO has been executed (consumes nonce to prevent replay)
    pub fn register_executed(&mut self, ado: &AuthorizedDecisionObject) -> Result<(), ShaniError> {
        if self.consumed_nonces.contains(&ado.nonce) {
            return Err(ShaniError::ReplayAttack);
        }
        self.consumed_nonces.insert(ado.nonce.clone());
        Ok(())
    }

    fn compute_dsal(&self, proposal: &DecisionProposal) -> u8 {
        use crate::schemas::decision::DecisionType;
        // Simplified D-SAL mapping — production implementations should use policy YAML
        match &proposal.decision_type {
            DecisionType::Remediation => 1,
            DecisionType::ConfigurationChange => 2,
            DecisionType::DataAccess => 1,
            DecisionType::NetworkAction => 3,
            DecisionType::Delegation => 2,
            DecisionType::PolicyUpdate => 4,
            DecisionType::BrowserAction => 1,
            DecisionType::AgentTask => 1,
            DecisionType::ToolCall => 1,
        }
    }

    fn issue_ado(
        &self,
        proposal: &DecisionProposal,
        effective_dsal: u8,
    ) -> Result<AuthorizedDecisionObject, ShaniError> {
        let nonce = Uuid::new_v4().to_string();
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::seconds(self.config.ado_ttl_seconds);
        let proposal_hash = proposal.canonical_hash();

        let delegation_rules = DelegationRules {
            allowed_sub_decisions: vec![],
            max_child_dsal: if effective_dsal > 0 { effective_dsal - 1 } else { 0 },
            max_depth: 1,
            max_children: 0,
        };

        let payload = crypto::canonical_payload(
            &proposal.decision_id,
            effective_dsal,
            &self.config.authority_name,
            &expires_at.to_rfc3339(),
            &proposal_hash,
            &nonce,
            &serde_json::to_value(&delegation_rules).unwrap_or_default(),
        );
        let signature = crypto::hmac_sign(&self.config.signing_key, &payload);

        Ok(AuthorizedDecisionObject {
            decision_id: proposal.decision_id.clone(),
            proposal_hash,
            signature,
            authority: self.config.authority_name.clone(),
            authorized_dsal: effective_dsal,
            delegation_rules,
            nonce,
            issued_at,
            expires_at,
            exec_context: ExecContext {
                decision_type: proposal.decision_type.clone(),
                intent_binding: proposal.intent.clone(),
                parent_decision_id: None,
                constraints: serde_json::Value::Object(Default::default()),
                rollback_policy: "best_effort".to_string(),
            },
            signature_chain: None,
            propagated_constraints: None,
            origin_org: None,
        })
    }
}

pub struct ShaniEvaluatorBuilder {
    max_authorized_dsal: u8,
}

impl Default for ShaniEvaluatorBuilder {
    fn default() -> Self {
        Self { max_authorized_dsal: 2 }
    }
}

impl ShaniEvaluatorBuilder {
    pub fn max_authorized_dsal(mut self, v: u8) -> Self {
        self.max_authorized_dsal = v;
        self
    }

    pub fn build(self) -> ShaniEvaluator {
        ShaniEvaluator::new(AuthorityConfig {
            max_authorized_dsal: self.max_authorized_dsal,
            ..Default::default()
        })
    }
}
