//! Basic evaluation example — proposal → ADO → execution

use shani_runtime::{
    DecisionProposal, DecisionType, BlastRadius, ShaniEvaluator, EvaluationResult,
};
use shani_runtime::boundary::ExecutionBoundary;

fn main() {
    let mut evaluator = ShaniEvaluator::builder()
        .max_authorized_dsal(2)
        .build();

    let proposal = DecisionProposal::builder()
        .decision_type(DecisionType::Remediation)
        .proposed_by("agent-1")
        .intent("restart service svc-api due to memory leak")
        .blast_radius(BlastRadius::Limited)
        .reversible(true)
        .build();

    println!("Proposal: {}", proposal.decision_id);

    match evaluator.evaluate(&proposal) {
        EvaluationResult::Authorized(ado) => {
            println!("ADO issued: {} (D-SAL {})", ado.decision_id, ado.authorized_dsal);

            // Gate execution through the boundary
            let mut boundary = ExecutionBoundary::new(&mut evaluator);
            let capability = boundary.issue_capability(ado).expect("ADO should be valid");

            let result = capability.execute(|ado| {
                println!("Executing with authority: {}", ado.authority);
                "service restarted"
            });

            println!("Result: {result}");
        }
        EvaluationResult::Denied(denied) => {
            println!("Denied: {} — {}", denied.decision_id, denied.reason);
        }
    }
}
