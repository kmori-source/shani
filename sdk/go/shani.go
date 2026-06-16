// Package shani provides the Shani Decision Governance Layer Go SDK (spec v0.4).
//
// The SDK wraps the runtime Go implementation and adds convenience helpers,
// middleware integrations, and idiomatic Go patterns for agent governance.
//
// Quick start:
//
//	import shani "github.com/kmori-source/shani/sdk/go"
//
//	client := shani.NewClient(shani.DefaultConfig())
//
//	proposal := shani.NewProposal(
//	    shani.DecisionTypeRemediation,
//	    "agent-1",
//	    "restart service svc-api",
//	    shani.BlastRadiusLimited,
//	    true,
//	)
//
//	err := client.EvaluateAndExecute(ctx, proposal, func(ado *shani.ADO) error {
//	    // action runs only if ADO is valid
//	    return restartService("svc-api")
//	})
package shani

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ── Types ─────────────────────────────────────────────────────────────────

// DecisionType enumerates valid proposal action types (SPEC §4.1).
type DecisionType = string

const (
	DecisionTypeRemediation         DecisionType = "remediation"
	DecisionTypeConfigurationChange DecisionType = "configuration_change"
	DecisionTypeDataAccess          DecisionType = "data_access"
	DecisionTypeNetworkAction       DecisionType = "network_action"
	DecisionTypeDelegation          DecisionType = "delegation"
	DecisionTypePolicyUpdate        DecisionType = "policy_update"
	DecisionTypeBrowserAction       DecisionType = "browser_action"
	DecisionTypeAgentTask           DecisionType = "agent_task"
	DecisionTypeToolCall            DecisionType = "tool_call"
)

// BlastRadius represents impact scope (SPEC §4.1).
type BlastRadius = string

const (
	BlastRadiusIsolated    BlastRadius = "isolated"
	BlastRadiusLimited     BlastRadius = "limited"
	BlastRadiusSignificant BlastRadius = "significant"
	BlastRadiusCritical    BlastRadius = "critical"
)

// DIS is the Decision Integrity State (SPEC §4.4).
type DIS string

const (
	DISValid    DIS = "VALID"
	DISDegraded DIS = "DEGRADED"
	DISViolated DIS = "VIOLATED"
)

// ADO is the Authorized Decision Object v5 (SPEC §4.2).
// Aliased from the runtime module schema for SDK consumers.
type ADO struct {
	DecisionID      string          `json:"decision_id"`
	ProposalHash    string          `json:"proposal_hash"`
	Signature       string          `json:"signature"`
	Authority       string          `json:"authority"`
	AuthorizedDSAL  int             `json:"authorized_dsal"`
	DelegationRules DelegationRules `json:"delegation_rules"`
	Nonce           string          `json:"nonce"`
	IssuedAt        time.Time       `json:"issued_at"`
	ExpiresAt       time.Time       `json:"expires_at"`
	ExecContext     ExecContext     `json:"exec_context"`
}

// IsExpired returns true if the ADO has passed its expires_at timestamp.
func (a *ADO) IsExpired() bool {
	return time.Now().UTC().After(a.ExpiresAt)
}

// DelegationRules bounds child delegation chains (SPEC §4.2).
type DelegationRules struct {
	AllowedSubDecisions []string `json:"allowed_sub_decisions"`
	MaxChildDSAL        int      `json:"max_child_dsal"`
	MaxDepth            int      `json:"max_depth"`
	MaxChildren         int      `json:"max_children"`
}

// ExecContext groups execution-metadata fields (SPEC §4.2).
type ExecContext struct {
	DecisionType   string         `json:"decision_type"`
	IntentBinding  string         `json:"intent_binding"`
	Constraints    map[string]any `json:"constraints"`
	RollbackPolicy string         `json:"rollback_policy"`
}

// Proposal is a DecisionProposal (SPEC §4.1).
type Proposal struct {
	DecisionID    string         `json:"decision_id"`
	DecisionType  string         `json:"decision_type"`
	ProposedBy    string         `json:"proposed_by"`
	Intent        string         `json:"intent"`
	Reversibility string         `json:"reversibility"`
	BlastRadius   string         `json:"blast_radius"`
	Evidence      []any          `json:"evidence,omitempty"`
	Context       map[string]any `json:"context,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
}

// CanonicalHash returns the SHA-256 of the canonical JSON representation.
func (p *Proposal) CanonicalHash() (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// NewProposal creates a Proposal with a generated decision_id.
func NewProposal(
	decisionType, proposedBy, intent string,
	blastRadius BlastRadius,
	reversible bool,
) *Proposal {
	rev := "reversible"
	if !reversible {
		rev = "irreversible"
	}
	return &Proposal{
		DecisionID:    uuid.New().String(),
		DecisionType:  decisionType,
		ProposedBy:    proposedBy,
		Intent:        intent,
		Reversibility: rev,
		BlastRadius:   blastRadius,
		CreatedAt:     time.Now().UTC(),
	}
}

// ── Config ────────────────────────────────────────────────────────────────

// Config holds client configuration.
type Config struct {
	MaxAuthorizedDSAL int
	AuthorityName     string
	SigningKey         []byte
	ADOTTLSeconds     int64
}

// DefaultConfig returns safe defaults for development.
func DefaultConfig() Config {
	return Config{
		MaxAuthorizedDSAL: 2,
		AuthorityName:     "shani-authority",
		SigningKey:         []byte("shani-dev-key-replace-in-production"),
		ADOTTLSeconds:     300,
	}
}

// ── Client ────────────────────────────────────────────────────────────────

// Client is the primary SDK entry point for agent governance.
type Client struct {
	config         Config
	dis            *DISStateMachine
	consumedNonces map[string]struct{}
}

// NewClient creates a new Shani governance client.
func NewClient(config Config) *Client {
	return &Client{
		config:         config,
		dis:            NewDISStateMachine(),
		consumedNonces: make(map[string]struct{}),
	}
}

// DIS returns the DIS state machine for monitoring and manual control.
func (c *Client) DIS() *DISStateMachine {
	return c.dis
}

// Evaluate evaluates a proposal and returns an ADO or error.
func (c *Client) Evaluate(proposal *Proposal) (*ADO, error) {
	if !c.dis.State().AllowsExecution() {
		return nil, fmt.Errorf("DIS is %s — all proposals suspended", c.dis.State())
	}

	effectiveDSAL := c.computeDSAL(proposal)
	if effectiveDSAL > c.config.MaxAuthorizedDSAL {
		return nil, fmt.Errorf("D-SAL %d exceeds ceiling %d", effectiveDSAL, c.config.MaxAuthorizedDSAL)
	}

	return c.issueADO(proposal, effectiveDSAL)
}

// EvaluateAndExecute evaluates a proposal and runs action only if authorized.
//
// This is the recommended API: it atomically evaluates, verifies, consumes
// the nonce, and runs the action — leaving no window for misuse.
func (c *Client) EvaluateAndExecute(
	_ context.Context,
	proposal *Proposal,
	action func(*ADO) error,
) error {
	ado, err := c.Evaluate(proposal)
	if err != nil {
		return fmt.Errorf("evaluation failed: %w", err)
	}

	if err := c.VerifyADO(ado); err != nil {
		return fmt.Errorf("ADO verification: %w", err)
	}

	if err := c.registerExecuted(ado); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	return action(ado)
}

// VerifyADO verifies signature and expiry (SPEC §4.2).
func (c *Client) VerifyADO(ado *ADO) error {
	if ado.IsExpired() {
		return fmt.Errorf("ADO expired at %s", ado.ExpiresAt.Format(time.RFC3339))
	}

	dr, err := json.Marshal(ado.DelegationRules)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"decision_id":      ado.DecisionID,
		"authorized_dsal":  ado.AuthorizedDSAL,
		"authority":        ado.Authority,
		"expires_at":       ado.ExpiresAt.Format(time.RFC3339),
		"proposal_hash":    ado.ProposalHash,
		"nonce":            ado.Nonce,
		"delegation_rules": json.RawMessage(dr),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, c.config.SigningKey)
	mac.Write(payloadBytes)
	expected := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison
	sig, err := hex.DecodeString(ado.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	exp, _ := hex.DecodeString(expected)
	if !hmac.Equal(sig, exp) {
		return fmt.Errorf("ADO signature verification failed")
	}
	return nil
}

func (c *Client) registerExecuted(ado *ADO) error {
	if _, exists := c.consumedNonces[ado.Nonce]; exists {
		return fmt.Errorf("nonce already consumed — replay attack detected")
	}
	c.consumedNonces[ado.Nonce] = struct{}{}
	return nil
}

func (c *Client) computeDSAL(p *Proposal) int {
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

func (c *Client) issueADO(proposal *Proposal, effectiveDSAL int) (*ADO, error) {
	nonce := uuid.New().String()
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(time.Duration(c.config.ADOTTLSeconds) * time.Second)

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

	dr, err := json.Marshal(delegationRules)
	if err != nil {
		return nil, err
	}
	payloadMap := map[string]any{
		"decision_id":      proposal.DecisionID,
		"authorized_dsal":  effectiveDSAL,
		"authority":        c.config.AuthorityName,
		"expires_at":       expiresAt.Format(time.RFC3339),
		"proposal_hash":    proposalHash,
		"nonce":            nonce,
		"delegation_rules": json.RawMessage(dr),
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, c.config.SigningKey)
	mac.Write(payloadBytes)
	signature := hex.EncodeToString(mac.Sum(nil))

	return &ADO{
		DecisionID:      proposal.DecisionID,
		ProposalHash:    proposalHash,
		Signature:       signature,
		Authority:       c.config.AuthorityName,
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

// ── DIS State Machine ─────────────────────────────────────────────────────

// DISState wraps DIS with AllowsExecution helper.
type DISState DIS

func (d DISState) AllowsExecution() bool {
	return DIS(d) == DISValid
}

// DISStateMachine governs Shani's integrity posture (SPEC §4.4).
type DISStateMachine struct {
	state   DIS
	history []DisTransition
}

// DisTransition records a DIS state transition for audit (SPEC §4.4).
type DisTransition struct {
	FromState   DIS       `json:"from_state"`
	ToState     DIS       `json:"to_state"`
	Reason      string    `json:"reason"`
	Timestamp   time.Time `json:"timestamp"`
	TriggeredBy string    `json:"triggered_by"`
}

// NewDISStateMachine creates a new machine in VALID state.
func NewDISStateMachine() *DISStateMachine {
	return &DISStateMachine{state: DISValid}
}

// State returns the current DIS state.
func (m *DISStateMachine) State() DISState {
	return DISState(m.state)
}

// Transition attempts a state change. VIOLATED → VALID must use ResetToValid.
func (m *DISStateMachine) Transition(to DIS, reason, triggeredBy string) (DisTransition, error) {
	if m.state == DISViolated && to == DISValid {
		return DisTransition{}, fmt.Errorf(
			"use ResetToValid() with justification to recover from VIOLATED state",
		)
	}

	record := DisTransition{
		FromState:   m.state,
		ToState:     to,
		Reason:      reason,
		Timestamp:   time.Now().UTC(),
		TriggeredBy: triggeredBy,
	}
	m.history = append(m.history, record)
	m.state = to
	b, _ := json.Marshal(record)
	slog.Info("DIS transition", "entry", string(b))
	return record, nil
}

// ResetToValid resets DIS from VIOLATED to VALID (SPEC §4.4).
func (m *DISStateMachine) ResetToValid(justification, authorizedBy string) (DisTransition, error) {
	if m.state != DISViolated {
		return DisTransition{}, fmt.Errorf(
			"ResetToValid() may only be called from VIOLATED state; current: %s", m.state,
		)
	}
	if strings.TrimSpace(justification) == "" {
		return DisTransition{}, fmt.Errorf("justification must not be empty")
	}
	if strings.TrimSpace(authorizedBy) == "" {
		return DisTransition{}, fmt.Errorf("authorizedBy must name a human authority")
	}

	record := DisTransition{
		FromState:   DISViolated,
		ToState:     DISValid,
		Reason:      "MANUAL RESET — " + justification,
		Timestamp:   time.Now().UTC(),
		TriggeredBy: authorizedBy,
	}
	m.history = append(m.history, record)
	m.state = DISValid
	b, _ := json.Marshal(record)
	slog.Info("DIS transition", "entry", string(b))
	return record, nil
}
