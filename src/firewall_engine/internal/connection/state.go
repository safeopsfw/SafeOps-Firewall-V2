// Package connection provides stateful connection tracking for the firewall engine.
package connection

// ============================================================================
// TCP Flags
// ============================================================================

// TCPFlags represents the TCP control flags relevant for state tracking.
type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
	URG bool
}

// ============================================================================
// TCP State Machine
// ============================================================================

// TCPStateMachine implements the TCP connection state machine.
// It handles state transitions based on TCP flags and connection direction.
//
// State Transition Diagram:
//
//	                    ┌──────────────────────────────────────────────┐
//	                    │                    CLOSED                     │
//	                    └─────────────────────┬────────────────────────┘
//	                                          │ SYN sent
//	                                          ▼
//	                    ┌──────────────────────────────────────────────┐
//	                    │                   SYN_SENT                    │
//	                    └─────────────────────┬────────────────────────┘
//	                                          │ SYN+ACK received
//	                                          ▼
//	                    ┌──────────────────────────────────────────────┐
//	                    │                 SYN_RECEIVED                  │
//	                    └─────────────────────┬────────────────────────┘
//	                                          │ ACK received
//	                                          ▼
//	                    ┌──────────────────────────────────────────────┐
//	                    │                 ESTABLISHED                   │
//	                    └─────────────────────┬────────────────────────┘
//	                                          │ FIN sent/received
//	                                          ▼
//	                    ┌─────────────────────────────────────────────┐
//	                    │           FIN_WAIT / CLOSE_WAIT             │
//	                    └─────────────────────┬───────────────────────┘
//	                                          │ Final ACK
//	                                          ▼
//	                    ┌──────────────────────────────────────────────┐
//	                    │                  TIME_WAIT                    │
//	                    └─────────────────────┬────────────────────────┘
//	                                          │ 2×MSL timeout
//	                                          ▼
//	                    ┌──────────────────────────────────────────────┐
//	                    │                    CLOSED                     │
//	                    └──────────────────────────────────────────────┘
type TCPStateMachine struct {
	// No state needed - all transitions are based on current state + flags
}

// NewTCPStateMachine creates a new TCP state machine.
func NewTCPStateMachine() *TCPStateMachine {
	return &TCPStateMachine{}
}

// Transition calculates the next TCP state based on current state and flags.
// Parameters:
//   - current: The current TCP state
//   - flags: TCP flags from the packet
//   - isForward: True if packet is from initiator to responder
//
// Returns the new TCP state after applying the transition.
func (sm *TCPStateMachine) Transition(current TCPState, flags TCPFlags, isForward bool) TCPState {
	// RST always leads to CLOSED (with some exceptions)
	if flags.RST {
		return sm.handleRST(current)
	}

	switch current {
	case TCPStateNew:
		return sm.transitionFromNew(flags, isForward)

	case TCPStateSYNSent:
		return sm.transitionFromSYNSent(flags, isForward)

	case TCPStateSYNReceived:
		return sm.transitionFromSYNReceived(flags, isForward)

	case TCPStateEstablished:
		return sm.transitionFromEstablished(flags, isForward)

	case TCPStateFinWait1:
		return sm.transitionFromFinWait1(flags, isForward)

	case TCPStateFinWait2:
		return sm.transitionFromFinWait2(flags, isForward)

	case TCPStateCloseWait:
		return sm.transitionFromCloseWait(flags, isForward)

	case TCPStateClosing:
		return sm.transitionFromClosing(flags, isForward)

	case TCPStateLastAck:
		return sm.transitionFromLastAck(flags, isForward)

	case TCPStateTimeWait:
		// TIME_WAIT stays until timeout
		return TCPStateTimeWait

	case TCPStateClosed:
		// CLOSED can restart with new SYN
		if flags.SYN && !flags.ACK {
			return TCPStateSYNSent
		}
		return TCPStateClosed

	default:
		return TCPStateInvalid
	}
}

// handleRST handles RST flag in any state.
func (sm *TCPStateMachine) handleRST(current TCPState) TCPState {
	switch current {
	case TCPStateNew, TCPStateSYNSent:
		// RST before connection established - just close
		return TCPStateClosed
	default:
		// RST in any other state - immediate close
		return TCPStateClosed
	}
}

// transitionFromNew handles transitions from NEW state.
func (sm *TCPStateMachine) transitionFromNew(flags TCPFlags, isForward bool) TCPState {
	if flags.SYN && !flags.ACK {
		// SYN only - connection initiation
		return TCPStateSYNSent
	}
	if flags.SYN && flags.ACK {
		// SYN+ACK without prior SYN - simultaneous open or out of sync
		return TCPStateSYNReceived
	}
	if flags.ACK && !flags.SYN {
		// ACK without SYN - could be midstream pickup
		// Treat as established (common for firewall restarts)
		return TCPStateEstablished
	}
	return TCPStateNew
}

// transitionFromSYNSent handles transitions from SYN_SENT state.
func (sm *TCPStateMachine) transitionFromSYNSent(flags TCPFlags, isForward bool) TCPState {
	if flags.SYN && flags.ACK && !isForward {
		// SYN+ACK from responder
		return TCPStateSYNReceived
	}
	if flags.SYN && !flags.ACK && !isForward {
		// SYN from responder - simultaneous open
		return TCPStateSYNReceived
	}
	return TCPStateSYNSent
}

// transitionFromSYNReceived handles transitions from SYN_RECEIVED state.
func (sm *TCPStateMachine) transitionFromSYNReceived(flags TCPFlags, isForward bool) TCPState {
	if flags.ACK && !flags.SYN && !flags.FIN {
		// ACK completes handshake
		return TCPStateEstablished
	}
	if flags.FIN {
		// FIN during handshake
		return TCPStateFinWait1
	}
	return TCPStateSYNReceived
}

// transitionFromEstablished handles transitions from ESTABLISHED state.
func (sm *TCPStateMachine) transitionFromEstablished(flags TCPFlags, isForward bool) TCPState {
	if flags.FIN {
		if isForward {
			// Initiator sends FIN
			return TCPStateFinWait1
		}
		// Responder sends FIN
		return TCPStateCloseWait
	}
	return TCPStateEstablished
}

// transitionFromFinWait1 handles transitions from FIN_WAIT_1 state.
func (sm *TCPStateMachine) transitionFromFinWait1(flags TCPFlags, isForward bool) TCPState {
	if flags.FIN && flags.ACK {
		// FIN+ACK - simultaneous close
		return TCPStateClosing
	}
	if flags.FIN && !isForward {
		// FIN from peer - simultaneous close
		return TCPStateClosing
	}
	if flags.ACK && !flags.FIN {
		// ACK only - our FIN was acknowledged
		return TCPStateFinWait2
	}
	return TCPStateFinWait1
}

// transitionFromFinWait2 handles transitions from FIN_WAIT_2 state.
func (sm *TCPStateMachine) transitionFromFinWait2(flags TCPFlags, isForward bool) TCPState {
	if flags.FIN {
		// Received peer's FIN
		return TCPStateTimeWait
	}
	return TCPStateFinWait2
}

// transitionFromCloseWait handles transitions from CLOSE_WAIT state.
func (sm *TCPStateMachine) transitionFromCloseWait(flags TCPFlags, isForward bool) TCPState {
	if flags.FIN && isForward {
		// Sent our FIN
		return TCPStateLastAck
	}
	return TCPStateCloseWait
}

// transitionFromClosing handles transitions from CLOSING state.
func (sm *TCPStateMachine) transitionFromClosing(flags TCPFlags, isForward bool) TCPState {
	if flags.ACK && !flags.FIN {
		// Received ACK for our FIN
		return TCPStateTimeWait
	}
	return TCPStateClosing
}

// transitionFromLastAck handles transitions from LAST_ACK state.
func (sm *TCPStateMachine) transitionFromLastAck(flags TCPFlags, isForward bool) TCPState {
	if flags.ACK && !isForward {
		// Received ACK for our FIN
		return TCPStateClosed
	}
	return TCPStateLastAck
}

// ============================================================================
// State Validation
// ============================================================================

// ValidatePacket checks if a packet is valid for the current state.
// Returns true if the packet is valid, false if it violates the state machine.
func (sm *TCPStateMachine) ValidatePacket(current TCPState, flags TCPFlags, isForward bool) bool {
	// RST is always valid (aborts connection)
	if flags.RST {
		return true
	}

	switch current {
	case TCPStateNew:
		// Only SYN or midstream pickup allowed
		return true

	case TCPStateSYNSent:
		// Expect SYN+ACK from responder
		if !isForward && flags.SYN && flags.ACK {
			return true
		}
		// Or another SYN (simultaneous open)
		if !isForward && flags.SYN && !flags.ACK {
			return true
		}
		// Retransmission of our SYN
		if isForward && flags.SYN && !flags.ACK {
			return true
		}
		return false

	case TCPStateSYNReceived:
		// Expect ACK to complete handshake
		if flags.ACK {
			return true
		}
		return false

	case TCPStateEstablished:
		// Data packets, ACKs, FINs all valid
		return true

	case TCPStateFinWait1, TCPStateFinWait2, TCPStateCloseWait,
		TCPStateClosing, TCPStateLastAck:
		// Teardown packets valid
		return true

	case TCPStateTimeWait:
		// Should not receive new packets except retransmissions
		return flags.FIN || flags.ACK

	case TCPStateClosed:
		// Only valid if starting new connection
		return flags.SYN && !flags.ACK

	default:
		return false
	}
}

// ============================================================================
// State Helpers
// ============================================================================

// GetExpectedFlags returns the expected flags for a given state transition.
func (sm *TCPStateMachine) GetExpectedFlags(current TCPState, isInitiator bool) TCPFlags {
	switch current {
	case TCPStateNew:
		return TCPFlags{SYN: true}

	case TCPStateSYNSent:
		if !isInitiator {
			return TCPFlags{SYN: true, ACK: true}
		}
		return TCPFlags{ACK: true}

	case TCPStateSYNReceived:
		return TCPFlags{ACK: true}

	case TCPStateEstablished:
		return TCPFlags{ACK: true}

	case TCPStateFinWait1, TCPStateCloseWait:
		return TCPFlags{FIN: true, ACK: true}

	default:
		return TCPFlags{}
	}
}

// CanSendData returns true if data can be sent in the current state.
func (sm *TCPStateMachine) CanSendData(state TCPState, isInitiator bool) bool {
	switch state {
	case TCPStateEstablished:
		return true
	case TCPStateCloseWait:
		// Can still send data before sending our FIN
		return isInitiator
	case TCPStateFinWait1, TCPStateFinWait2:
		// Can still send data if we haven't sent FIN yet (shouldn't be in this state then)
		return false
	default:
		return false
	}
}

// IsTerminated returns true if the connection is fully terminated.
func (sm *TCPStateMachine) IsTerminated(state TCPState) bool {
	return state == TCPStateClosed || state == TCPStateInvalid
}

// NeedsTimeout returns true if the state requires a timeout to transition.
func (sm *TCPStateMachine) NeedsTimeout(state TCPState) bool {
	switch state {
	case TCPStateTimeWait:
		return true // 2×MSL timeout
	case TCPStateSYNSent, TCPStateSYNReceived:
		return true // Connection attempt timeout
	default:
		return false
	}
}
