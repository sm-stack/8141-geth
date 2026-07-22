// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// FrameValidationError represents an EIP-8141 validation-prefix rule violation.
type FrameValidationError struct {
	Rule    string // e.g. "OP-011", "OP-012"
	Message string
}

func (e *FrameValidationError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Rule, e.Message)
}

// bannedOpcodes is the set of opcodes forbidden in an EIP-8141 validation prefix.
// Note: LOG0-4 and CALL with value are already blocked by STATICCALL/readOnly.
var bannedOpcodes = map[OpCode]bool{
	ORIGIN:       true, // 0x32
	GASPRICE:     true, // 0x3a
	BLOCKHASH:    true, // 0x40
	COINBASE:     true, // 0x41
	TIMESTAMP:    true, // 0x42
	NUMBER:       true, // 0x43
	PREVRANDAO:   true, // 0x44 (same as DIFFICULTY)
	GASLIMIT:     true, // 0x45
	BASEFEE:      true, // 0x48
	BLOBHASH:     true, // 0x49
	BLOBBASEFEE:  true, // 0x4a
	SSTORE:       true, // 0x55
	TLOAD:        true, // 0x5c
	TSTORE:       true, // 0x5d
	CREATE:       true, // 0xf0
	CREATE2:      true, // 0xf5
	SELFDESTRUCT: true, // 0xff
	INVALID:      true, // 0xfe [OP-011]
	BALANCE:      true, // 0x31 [OP-080]
	SELFBALANCE:  true, // 0x47 [OP-080]
}

// FrameValidationTracer checks EIP-8141 rules during validation-prefix simulation.
// It is designed to be lightweight and fail-fast: it records the first violation
// and short-circuits all subsequent hooks.
type FrameValidationTracer struct {
	stateDB     StateDB        // For validation target code inspection.
	sender      common.Address // tx.sender — exempt from OP-041, owns storage (STO-010)
	frameTarget common.Address // VERIFY frame target
	precompiles map[common.Address]bool

	lastOp         OpCode // Previous opcode for GAS rule (OP-012)
	lastOpValid    bool   // Whether lastOp is meaningful
	allowTimestamp bool
	options        FrameValidationTracerOptions

	violation *FrameValidationError // First violation (nil = no violation)

}

// FrameValidationTracerOptions configures EIP-8141 validation-prefix exceptions.
type FrameValidationTracerOptions struct {
	// AllowCreate permits CREATE/CREATE2 in the first deploy frame of a validation prefix.
	AllowCreate bool

	// AllowSenderStorageWrites permits SSTORE only when the executing scope is tx.sender.
	AllowSenderStorageWrites bool
}

// NewFrameValidationTracer creates a tracer for VERIFY frame validation.
func NewFrameValidationTracer(stateDB StateDB, sender common.Address, frameTarget common.Address, precompiles []common.Address) *FrameValidationTracer {
	return NewFrameValidationTracerWithOptions(stateDB, sender, frameTarget, precompiles, FrameValidationTracerOptions{})
}

// NewFrameValidationTracerWithOptions creates a tracer with validation-prefix
// exceptions enabled for deploy frames.
func NewFrameValidationTracerWithOptions(stateDB StateDB, sender common.Address, frameTarget common.Address, precompiles []common.Address, opts FrameValidationTracerOptions) *FrameValidationTracer {
	pm := make(map[common.Address]bool, len(precompiles))
	for _, addr := range precompiles {
		pm[addr] = true
	}
	return &FrameValidationTracer{
		stateDB:        stateDB,
		sender:         sender,
		frameTarget:    frameTarget,
		precompiles:    pm,
		allowTimestamp: frameTarget == params.FrameExpiryVerifierAddress && bytes.Equal(stateDB.GetCode(frameTarget), params.FrameExpiryVerifierCode),
		options:        opts,
	}
}

// Violation returns the first detected rule violation, or nil.
func (t *FrameValidationTracer) Violation() *FrameValidationError {
	return t.violation
}

// Hooks returns the tracing hooks to attach to EVM Config.Tracer.
func (t *FrameValidationTracer) Hooks() *tracing.Hooks {
	return &tracing.Hooks{
		OnOpcode: t.OnOpcode,
		OnEnter:  t.OnEnter,
		OnExit:   t.OnExit,
	}
}

// OnOpcode is called before each opcode execution.
func (t *FrameValidationTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	if t.violation != nil {
		return
	}
	opcode := OpCode(op)

	// [OP-012] Check if previous opcode was GAS not followed by CALL.
	if t.lastOpValid && t.lastOp == GAS && !isCallOp(opcode) {
		t.violation = &FrameValidationError{
			Rule:    "OP-012",
			Message: fmt.Sprintf("GAS opcode not followed by CALL (followed by %s at pc=%d depth=%d)", opcode, pc, depth),
		}
		return
	}

	// [OP-011, OP-080] Check banned opcodes.
	if bannedOpcodes[opcode] {
		if (opcode == CREATE || opcode == CREATE2) && t.options.AllowCreate {
			t.lastOp = opcode
			t.lastOpValid = true
			return
		}
		if opcode == TIMESTAMP && t.allowTimestamp {
			t.lastOp = opcode
			t.lastOpValid = true
			return
		}
		if opcode == SSTORE && t.options.AllowSenderStorageWrites && scope != nil && scope.Address() == t.sender {
			t.lastOp = opcode
			t.lastOpValid = true
			return
		}
		rule := "OP-011"
		if opcode == BALANCE || opcode == SELFBALANCE {
			rule = "OP-080"
		}
		t.violation = &FrameValidationError{
			Rule:    rule,
			Message: fmt.Sprintf("banned opcode %s at pc=%d depth=%d", opcode, pc, depth),
		}
		return
	}

	// [OP-041] EXTCODE/CALL targets must have deployed code.
	if isExtOrCallOp(opcode) && scope != nil {
		stackData := scope.StackData()
		addrIdx := 0
		if isCallOp(opcode) {
			addrIdx = 1 // CALL-type: address is stack[1] (after gas argument)
		}
		if len(stackData) > addrIdx {
			addr := common.BytesToAddress(stackData[len(stackData)-addrIdx-1].Bytes())
			// Skip precompiles and sender (OP-042 exception).
			if !t.precompiles[addr] && addr != t.sender {
				code := t.stateDB.GetCode(addr)
				_, delegated := types.ParseDelegation(code)
				if t.stateDB.GetCodeSize(addr) == 0 || delegated {
					t.violation = &FrameValidationError{
						Rule:    "OP-041",
						Message: fmt.Sprintf("%s target %s is empty or delegated at pc=%d depth=%d", opcode, addr.Hex(), pc, depth),
					}
					return
				}
			}
		}
	}

	// EIP-8141 permits validation-prefix storage reads only from tx.sender.
	if opcode == SLOAD && scope != nil {
		if addr := scope.Address(); addr != t.sender {
			t.violation = &FrameValidationError{
				Rule:    "STO-010",
				Message: fmt.Sprintf("storage read outside sender at %s", addr.Hex()),
			}
			return
		}
	}

	// Track lastOp for OP-012.
	t.lastOp = opcode
	t.lastOpValid = true
}

// OnEnter is called when EVM enters a new call scope.
func (t *FrameValidationTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if t.violation != nil {
		return
	}
	opcode := OpCode(typ)
	if opcode != CREATE && opcode != CREATE2 {
		return
	}
	if !t.options.AllowCreate || to != t.sender {
		t.violation = &FrameValidationError{
			Rule:    "OP-011",
			Message: fmt.Sprintf("%s creates %s instead of sender %s", opcode, to.Hex(), t.sender.Hex()),
		}
	}
}

// OnExit is called when EVM exits a call scope.
func (t *FrameValidationTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	if t.violation != nil {
		return
	}
	// [OP-020] Out-of-gas revert is forbidden — prevents gas limit probing.
	if errors.Is(err, ErrOutOfGas) || errors.Is(err, ErrCodeStoreOutOfGas) {
		t.violation = &FrameValidationError{
			Rule:    "OP-020",
			Message: "out-of-gas during VERIFY frame execution",
		}
		return
	}
}

func isCallOp(op OpCode) bool {
	return op == CALL || op == CALLCODE || op == DELEGATECALL || op == STATICCALL
}

func isExtOp(op OpCode) bool {
	return op == EXTCODECOPY || op == EXTCODESIZE || op == EXTCODEHASH
}

func isExtOrCallOp(op OpCode) bool {
	return isExtOp(op) || isCallOp(op)
}
