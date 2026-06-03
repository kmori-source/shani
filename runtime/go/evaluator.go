package shani

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AuthorityConfig holds authority configuration for the evaluator.
type AuthorityConfig struct {
	MaxAuthorizedDSAL int
	AuthorityName     string
	SigningKey         []byte
	ADOTTLSeconds     int64
}

// DefaultAuthorityConfig returns safe defaults for development.
func DefaultAuthorityConfig() AuthorityConfig {
	return AuthorityConfig{
		MaxAuthorizedDSAL: 2,
		AuthorityName:     "shani-authority",
		SigningKey:         []byte("shani-dev-key-replace-in-production"),
		ADOTTLSeconds:     300,
	}
}

// ShaniEvaluator is the core evaluation engine (SPEC §5).
//
// Evaluates DecisionProposals and issues ADOs or DeniedDecisions.
type ShaniEvaluator struct {
	config          AuthorityConfig
	dis             *DISStateMachine
	consumedNonces  map[string]struct{}
}

// NewShaniEvaluator creates a new evaluator with the given configuration.
func NewShaniEvaluator(config AuthorityConfig) *ShaniEvaluator {
	return &ShaniEvaluator{
		config:         config,
		dis:            NewDISStateMachine(),
		consumedNonces: make(map[string]struct{}),
	}
}

// DISState returns the current DIS state.
func (e *ShaniEvaluator) DISState() DIS {
	return e.dis.State()
}

// DIS returns the DIS state machine for direct manipulation.
func (e *ShaniEvaluator) DIS() *DISStateMachine {
	return e.dis
}

// Evaluate evaluates a proposal and returns an ADO or denial (SPEC §5).
func (e *ShaniEvaluator) Evaluate(proposal *DecisionProposal) (*AuthorizedDecisionObject, *DeniedDecision) {
	// SPEC §4.4: DIS VALID required
	if !e.dis.State().AllowsExecution() {
		return nil, &DeniedDecision{
			DecisionID: proposal.DecisionID,
			Reason:     fmt.Sprintf("DIS is %s — all proposals suspended", e.dis.State()),
			DeniedAt:   time.Now().UTC(),
		}
	}

	effectiveDSAL := e.computeDSAL(proposal)

	// SPEC §4.3: D-SAL ceiling enforcement
	if effectiveDSAL > e.config.MaxAuthorizedDSAL {
		return nil, &DeniedDecision{
			DecisionID: proposal.DecisionID,
			Reason: fmt.Sprintf(
				"D-SAL %d exceeds ceiling %d", effectiveDSAL, e.config.MaxAuthorizedDSAL,
			),
			DeniedAt: time.Now().UTC(),
		}
	}

	ado, err := e.issueADO(proposal, effectiveDSAL)
	if err != nil {
		return nil, &DeniedDecision{
			DecisionID: proposal.DecisionID,
			Reason:     err.Error(),
			DeniedAt:   time.Now().UTC(),
		}
	}
	return ado, nil
}

// VerifyADO verifies signature and expiry (SPEC §4.2).
func (e *ShaniEvaluator) VerifyADO(ado *AuthorizedDecisionObject) error {
	if ado.IsExpired() {
		return fmt.Errorf("ADO expired at %s", ado.ExpiresAt.Format(time.RFC3339))
	}

	payload, err := canonicalPayload(
		ado.DecisionID,
		ado.AuthorizedDSAL,
		ado.Authority,
		ado.ExpiresAt.Format(time.RFC3339),
		ado.ProposalHash,
		ado.Nonce,
		ado.DelegationRules,
	)
	if err != nil {
		return fmt.Errorf("canonical payload: %w", err)
	}

	if !hmacVerify(e.config.SigningKey, payload, ado.Signature) {
		return fmt.Errorf("ADO signature verification failed")
	}
	return nil
}

// RegisterExecuted consumes the nonce to prevent replay (SPEC §4.2).
func (e *ShaniEvaluator) RegisterExecuted(ado *AuthorizedDecisionObject) error {
	if _, exists := e.consumedNonces[ado.Nonce]; exists {
		return fmt.Errorf("nonce already consumed — replay attack detected")
	}
	e.consumedNonces[ado.Nonce] = struct{}{}
	return nil
}

func (e *ShaniEvaluator) computeDSAL(p *DecisionProposal) int {
	switch p.DecisionType {
	case DecisionTypeRemediation:
		return 1
	case DecisionTypeConfigurationChange:
		return 2
	case DecisionTypeDataAccess:
		return 1
	case DecisionTypeNetworkAction:
		return 3
	case DecisionTypeDelegation:
		return 2
	case DecisionTypePolicyUpdate:
		return 4
	default:
		return 1
	}
}

func (e *ShaniEvaluator) issueADO(proposal *DecisionProposal, effectiveDSAL int) (*AuthorizedDecisionObject, error) {
	nonce := uuid.New().String()
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(time.Duration(e.config.ADOTTLSeconds) * time.Second)

	proposalHash, err := proposal.CanonicalHash()
	if err != nil {
		return nil, fmt.Errorf("proposal hash: %w", err)
	}

	maxChild := effectiveDSAL - 1
	if maxChild < 0 {
		maxChild = 0
	}
	delegationRules := DelegationRules{
		AllowedSubDecisions: []string{},
		MaxChildDSAL:        maxChild,
		MaxDepth:            1,
		MaxChildren:         0,
	}

	payload, err := canonicalPayload(
		proposal.DecisionID,
		effectiveDSAL,
		e.config.AuthorityName,
		expiresAt.Format(time.RFC3339),
		proposalHash,
		nonce,
		delegationRules,
	)
	if err != nil {
		return nil, fmt.Errorf("canonical payload: %w", err)
	}
	signature := hmacSign(e.config.SigningKey, payload)

	return &AuthorizedDecisionObject{
		DecisionID:      proposal.DecisionID,
		ProposalHash:    proposalHash,
		Signature:       signature,
		Authority:       e.config.AuthorityName,
		AuthorizedDSAL:  effectiveDSAL,
		DelegationRules: delegationRules,
		Nonce:           nonce,
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
		ExecContext: ExecContext{
			DecisionType:   proposal.DecisionType,
			IntentBinding:  proposal.Intent,
			Constraints:    map[string]any{},
			RollbackPolicy: "best_effort",
		},
	}, nil
}
