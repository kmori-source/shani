//! Shani Decision Governance Layer — Rust runtime (v0.4)
//!
//! This crate implements the normative Shani spec (spec/shani-v0.4.md) in Rust.
//! It is the performance-critical runtime for agent execution environments.
//!
//! # Architecture
//!
//! ```text
//! DecisionProposal → PostureEngine → RiskEvaluator → ShaniEvaluator → ADO
//!                                                                       │
//!                                                             ExecutionBoundary
//!                                                                       │
//!                                                                    Capability
//! ```
//!
//! # Quick start
//!
//! ```rust,no_run
//! use shani_runtime::{ShaniEvaluator, DecisionProposal, DecisionType, BlastRadius};
//!
//! let evaluator = ShaniEvaluator::builder()
//!     .max_authorized_dsal(2)
//!     .build();
//!
//! let proposal = DecisionProposal::builder()
//!     .decision_type(DecisionType::Remediation)
//!     .proposed_by("agent-1")
//!     .intent("restart service svc-api")
//!     .blast_radius(BlastRadius::Limited)
//!     .reversible(true)
//!     .build();
//!
//! let result = evaluator.evaluate(&proposal);
//! ```

pub mod schemas;
pub mod evaluator;
pub mod dis;
pub mod crypto;
pub mod boundary;
pub mod error;

pub use schemas::decision::{
    AuthorizedDecisionObject, DecisionProposal, DecisionType, BlastRadius,
    DelegationRules, ExecContext,
};
pub use schemas::state::{Dsal, Dis};
pub use evaluator::{ShaniEvaluator, EvaluationResult, DeniedDecision};
pub use dis::DisStateMachine;
pub use boundary::{ExecutionBoundary, Capability};
pub use error::ShaniError;
