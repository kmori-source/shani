//! D-SAL and DIS definitions (SPEC §4.3, §4.4)

use serde::{Deserialize, Serialize};

/// Decision System Autonomy Level (SPEC §4.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Dsal {
    ProposalOnly = 0,
    Bounded = 1,
    Supervised = 2,
    PolicyGoverned = 3,
    FullAutonomy = 4,
}

impl Dsal {
    pub fn value(self) -> u8 {
        self as u8
    }

    pub fn requires_human_authority(self) -> bool {
        self >= Dsal::Supervised
    }

    pub fn allows_delegation(self) -> bool {
        self >= Dsal::Supervised
    }
}

impl TryFrom<u8> for Dsal {
    type Error = String;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Dsal::ProposalOnly),
            1 => Ok(Dsal::Bounded),
            2 => Ok(Dsal::Supervised),
            3 => Ok(Dsal::PolicyGoverned),
            4 => Ok(Dsal::FullAutonomy),
            _ => Err(format!("invalid DSAL value: {v}")),
        }
    }
}

/// Decision Integrity State (SPEC §4.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Dis {
    Valid,
    Degraded,
    Violated,
}

impl Dis {
    pub fn allows_execution(self) -> bool {
        self == Dis::Valid
    }

    pub fn requires_human_review(self) -> bool {
        matches!(self, Dis::Degraded | Dis::Violated)
    }
}

/// Records a DIS state transition for audit (SPEC §4.4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisTransition {
    pub from_state: Dis,
    pub to_state: Dis,
    pub reason: String,
    pub timestamp: String,
    pub triggered_by: String,
}
