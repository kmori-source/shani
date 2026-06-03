// Package shani implements the Shani Decision Governance Layer (spec v0.4).
//
// This is the Go runtime implementation. It follows the normative spec at
// spec/shani-v0.4.md and is structurally equivalent to the Python reference
// implementation in shani/.
package shani

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// DecisionType enumerates valid proposal action types (SPEC §4.1).
type DecisionType string

const (
	DecisionTypeRemediation        DecisionType = "remediation"
	DecisionTypeConfigurationChange DecisionType = "configuration_change"
	DecisionTypeDataAccess         DecisionType = "data_access"
	DecisionTypeNetworkAction      DecisionType = "network_action"
	DecisionTypeDelegation         DecisionType = "delegation"
	DecisionTypePolicyUpdate       DecisionType = "policy_update"
	DecisionTypeBrowserAction      DecisionType = "browser_action"
	DecisionTypeAgentTask          DecisionType = "agent_task"
	DecisionTypeToolCall           DecisionType = "tool_call"
)

// BlastRadius represents the impact scope of a proposed action (SPEC §4.1).
type BlastRadius string

const (
	BlastRadiusIsolated    BlastRadius = "isolated"
	BlastRadiusLimited     BlastRadius = "limited"
	BlastRadiusSignificant BlastRadius = "significant"
	BlastRadiusCritical    BlastRadius = "critical"
)

// DSAL is the Decision System Autonomy Level (SPEC §4.3).
type DSAL int

const (
	DSALProposalOnly    DSAL = 0
	DSALBounded         DSAL = 1
	DSALSupervised      DSAL = 2
	DSALPolicyGoverned  DSAL = 3
	DSALFullAutonomy    DSAL = 4
)

// DIS is the Decision Integrity State (SPEC §4.4).
type DIS string

const (
	DISValid    DIS = "VALID"
	DISDegraded DIS = "DEGRADED"
	DISViolated DIS = "VIOLATED"
)

// AllowsExecution returns true only when DIS is VALID.
func (d DIS) AllowsExecution() bool {
	return d == DISValid
}

// DelegationRules bounds child delegation chains (SPEC §4.2).
type DelegationRules struct {
	AllowedSubDecisions []string `json:"allowed_sub_decisions"`
	MaxChildDSAL        int      `json:"max_child_dsal"`
	MaxDepth            int      `json:"max_depth"`
	MaxChildren         int      `json:"max_children"`
}

// ExecContext groups execution-metadata fields in the signed ADO payload (SPEC §4.2).
type ExecContext struct {
	DecisionType      DecisionType   `json:"decision_type"`
	IntentBinding     string         `json:"intent_binding"`
	ParentDecisionID  *string        `json:"parent_decision_id,omitempty"`
	Constraints       map[string]any `json:"constraints"`
	RollbackPolicy    string         `json:"rollback_policy"`
}

// DecisionProposal is a structured request from an agent to Shani (SPEC §4.1).
//
// A proposal MUST NOT be treated as authorization. It is a request only.
type DecisionProposal struct {
	DecisionID   string         `json:"decision_id"`
	DecisionType DecisionType   `json:"decision_type"`
	ProposedBy   string         `json:"proposed_by"`
	Intent       string         `json:"intent"`
	Reversibility string        `json:"reversibility"`
	BlastRadius  BlastRadius    `json:"blast_radius"`
	Evidence     []any          `json:"evidence,omitempty"`
	Context      map[string]any `json:"context,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// CanonicalHash returns the SHA-256 of the canonical JSON representation (SPEC §4.6).
func (p *DecisionProposal) CanonicalHash() (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// AuthorizedDecisionObject (ADO v5) is the exclusive authorization artifact (SPEC §4.2).
//
// An Execution Agent MUST NOT execute any action without a valid ADO.
type AuthorizedDecisionObject struct {
	DecisionID             string           `json:"decision_id"`
	ProposalHash           string           `json:"proposal_hash"`
	Signature              string           `json:"signature"`
	Authority              string           `json:"authority"`
	AuthorizedDSAL         int              `json:"authorized_dsal"`
	DelegationRules        DelegationRules  `json:"delegation_rules"`
	Nonce                  string           `json:"nonce"`
	IssuedAt               time.Time        `json:"issued_at"`
	ExpiresAt              time.Time        `json:"expires_at"`
	ExecContext            ExecContext      `json:"exec_context"`
	SignatureChain         []string         `json:"signature_chain,omitempty"`
	PropagatedConstraints  map[string]any   `json:"propagated_constraints,omitempty"`
	OriginOrg              *string          `json:"origin_org,omitempty"`
}

// IsExpired returns true if the ADO has passed its expires_at timestamp (SPEC §4.2).
func (a *AuthorizedDecisionObject) IsExpired() bool {
	return time.Now().UTC().After(a.ExpiresAt)
}

// DeniedDecision is returned when Shani denies a proposal.
type DeniedDecision struct {
	DecisionID string
	Reason     string
	DeniedAt   time.Time
}

// DisTransition records a DIS state transition for audit (SPEC §4.4).
type DisTransition struct {
	FromState   DIS       `json:"from_state"`
	ToState     DIS       `json:"to_state"`
	Reason      string    `json:"reason"`
	Timestamp   time.Time `json:"timestamp"`
	TriggeredBy string    `json:"triggered_by"`
}

// canonicalPayload builds the signing payload for an ADO (SPEC §4.6).
func canonicalPayload(
	decisionID string,
	authorizedDSAL int,
	authority, expiresAt, proposalHash, nonce string,
	delegationRules DelegationRules,
) ([]byte, error) {
	dr, err := json.Marshal(delegationRules)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"decision_id":      decisionID,
		"authorized_dsal":  authorizedDSAL,
		"authority":        authority,
		"expires_at":       expiresAt,
		"proposal_hash":    proposalHash,
		"nonce":            nonce,
		"delegation_rules": json.RawMessage(dr),
	}
	return json.Marshal(payload)
}

// hmacSign produces an HMAC-SHA256 signature over the payload (SPEC §4.6).
func hmacSign(key, payload []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// hmacVerify verifies an HMAC-SHA256 signature.
func hmacVerify(key, payload []byte, expected string) bool {
	computed := hmacSign(key, payload)
	// Constant-time comparison via HMAC
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	computedBytes, _ := hex.DecodeString(computed)
	return hmac.Equal(computedBytes, expectedBytes)
}
