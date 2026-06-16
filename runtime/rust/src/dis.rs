//! DIS State Machine (SPEC §4.4)

use chrono::Utc;
use crate::schemas::state::{Dis, DisTransition};
use crate::error::ShaniError;

/// The DIS State Machine governs Shani's integrity posture.
///
/// Transitions are explicit and logged. VIOLATED → VALID requires
/// explicit reset with documented justification (SPEC §4.4).
pub struct DisStateMachine {
    state: Dis,
    history: Vec<DisTransition>,
}

impl DisStateMachine {
    pub fn new() -> Self {
        Self {
            state: Dis::Valid,
            history: vec![],
        }
    }

    pub fn state(&self) -> Dis {
        self.state
    }

    pub fn history(&self) -> &[DisTransition] {
        &self.history
    }

    /// Attempt a state transition. VIOLATED → VALID must use reset_to_valid().
    pub fn transition(
        &mut self,
        to: Dis,
        reason: impl Into<String>,
        triggered_by: impl Into<String>,
    ) -> Result<DisTransition, ShaniError> {
        if self.state == Dis::Violated && to == Dis::Valid {
            return Err(ShaniError::DelegationViolation(
                "Use reset_to_valid() with justification to recover from VIOLATED".to_string(),
            ));
        }

        let record = DisTransition {
            from_state: self.state,
            to_state: to,
            reason: reason.into(),
            timestamp: Utc::now().to_rfc3339(),
            triggered_by: triggered_by.into(),
        };
        self.history.push(record.clone());
        self.state = to;

        tracing_log(&record);
        Ok(record)
    }

    /// Reset DIS from VIOLATED to VALID (SPEC §4.4).
    ///
    /// Requires non-empty justification and named human authority.
    pub fn reset_to_valid(
        &mut self,
        justification: impl Into<String>,
        authorized_by: impl Into<String>,
    ) -> Result<DisTransition, ShaniError> {
        if self.state != Dis::Violated {
            return Err(ShaniError::DelegationViolation(format!(
                "reset_to_valid() may only be called from VIOLATED state. Current: {:?}",
                self.state
            )));
        }

        let justification = justification.into();
        let authorized_by = authorized_by.into();

        if justification.trim().is_empty() {
            return Err(ShaniError::DelegationViolation("justification must not be empty".into()));
        }
        if authorized_by.trim().is_empty() {
            return Err(ShaniError::DelegationViolation("authorized_by must name a human".into()));
        }

        let record = DisTransition {
            from_state: Dis::Violated,
            to_state: Dis::Valid,
            reason: format!("MANUAL RESET — {justification}"),
            timestamp: Utc::now().to_rfc3339(),
            triggered_by: authorized_by,
        };
        self.history.push(record.clone());
        self.state = Dis::Valid;

        tracing_log(&record);
        Ok(record)
    }
}

impl Default for DisStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

fn tracing_log(record: &DisTransition) {
    eprintln!(
        "[shani.dis.audit] DIS transition: {:?} → {:?} reason='{}' by='{}'",
        record.from_state, record.to_state, record.reason, record.triggered_by
    );
}
