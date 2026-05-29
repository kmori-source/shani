package shani

import "fmt"

// Capability grants the right to execute exactly one action (SPEC §7.2).
//
// Capabilities are single-use. Agents MUST NOT cache or reuse Capabilities.
type Capability struct {
	ado *AuthorizedDecisionObject
	used bool
}

// ADO returns the underlying ADO.
func (c *Capability) ADO() *AuthorizedDecisionObject {
	return c.ado
}

// Execute runs action gated by this capability (single-use).
func (c *Capability) Execute(action func(*AuthorizedDecisionObject) error) error {
	if c.used {
		return fmt.Errorf("capability already used — capabilities are single-use")
	}
	c.used = true
	return action(c.ado)
}

// ExecutionBoundary enforces that execution only happens through a valid ADO.
type ExecutionBoundary struct {
	evaluator *ShaniEvaluator
}

// NewExecutionBoundary creates a boundary backed by the given evaluator.
func NewExecutionBoundary(e *ShaniEvaluator) *ExecutionBoundary {
	return &ExecutionBoundary{evaluator: e}
}

// IssueCapability verifies an ADO and returns a Capability.
//
// Verifies signature and expiry, then consumes the nonce.
func (b *ExecutionBoundary) IssueCapability(ado *AuthorizedDecisionObject) (*Capability, error) {
	if err := b.evaluator.VerifyADO(ado); err != nil {
		return nil, fmt.Errorf("ADO verification: %w", err)
	}
	if err := b.evaluator.RegisterExecuted(ado); err != nil {
		return nil, fmt.Errorf("ADO registration: %w", err)
	}
	return &Capability{ado: ado}, nil
}
