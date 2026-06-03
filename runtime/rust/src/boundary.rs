//! Execution Boundary — enforces that no action runs without a valid ADO (SPEC §7)

use crate::error::ShaniError;
use crate::evaluator::ShaniEvaluator;
use crate::schemas::decision::AuthorizedDecisionObject;

/// A Capability grants the right to execute exactly one action.
///
/// Capabilities are non-clonable and consumed on use.
/// Agents MUST NOT cache or reuse Capabilities (SPEC §7.2).
pub struct Capability {
    ado: AuthorizedDecisionObject,
}

impl Capability {
    /// Execute an action gated by this capability.
    ///
    /// The closure receives the ADO for context. Returns the action result.
    pub fn execute<F, T>(self, action: F) -> T
    where
        F: FnOnce(&AuthorizedDecisionObject) -> T,
    {
        action(&self.ado)
    }

    pub fn ado(&self) -> &AuthorizedDecisionObject {
        &self.ado
    }
}

/// Enforces that execution only happens through a valid, verified ADO.
pub struct ExecutionBoundary<'e> {
    evaluator: &'e mut ShaniEvaluator,
}

impl<'e> ExecutionBoundary<'e> {
    pub fn new(evaluator: &'e mut ShaniEvaluator) -> Self {
        Self { evaluator }
    }

    /// Verify an ADO and issue a Capability.
    ///
    /// Verifies signature and expiry, then consumes the nonce to prevent replay.
    pub fn issue_capability(
        &mut self,
        ado: AuthorizedDecisionObject,
    ) -> Result<Capability, ShaniError> {
        self.evaluator.verify_ado(&ado)?;
        self.evaluator.register_executed(&ado)?;
        Ok(Capability { ado })
    }
}
