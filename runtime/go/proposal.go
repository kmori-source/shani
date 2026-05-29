package shani

import (
	"time"

	"github.com/google/uuid"
)

// NewProposal creates a DecisionProposal with a generated decision_id.
func NewProposal(
	decisionType DecisionType,
	proposedBy, intent string,
	blastRadius BlastRadius,
	reversible bool,
) *DecisionProposal {
	reversibility := "reversible"
	if !reversible {
		reversibility = "irreversible"
	}
	return &DecisionProposal{
		DecisionID:    uuid.New().String(),
		DecisionType:  decisionType,
		ProposedBy:    proposedBy,
		Intent:        intent,
		Reversibility: reversibility,
		BlastRadius:   blastRadius,
		CreatedAt:     time.Now().UTC(),
	}
}
