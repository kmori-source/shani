package shani

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// DISStateMachine governs Shani's integrity posture (SPEC §4.4).
//
// Transitions are explicit and logged. VIOLATED → VALID requires
// explicit reset with documented justification.
type DISStateMachine struct {
	state   DIS
	history []DisTransition
}

// NewDISStateMachine creates a new machine in VALID state.
func NewDISStateMachine() *DISStateMachine {
	return &DISStateMachine{state: DISValid}
}

// State returns the current DIS state.
func (m *DISStateMachine) State() DIS {
	return m.state
}

// History returns a copy of all recorded transitions.
func (m *DISStateMachine) History() []DisTransition {
	result := make([]DisTransition, len(m.history))
	copy(result, m.history)
	return result
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
	logTransition(record)
	return record, nil
}

// ResetToValid resets DIS from VIOLATED to VALID (SPEC §4.4).
//
// Requires non-empty justification and named human authority.
func (m *DISStateMachine) ResetToValid(justification, authorizedBy string) (DisTransition, error) {
	if m.state != DISViolated {
		return DisTransition{}, fmt.Errorf(
			"ResetToValid() may only be called from VIOLATED state; current state: %s", m.state,
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
	logTransition(record)
	return record, nil
}

func logTransition(r DisTransition) {
	b, _ := json.Marshal(r)
	slog.Info("DIS transition", "entry", string(b))
}
