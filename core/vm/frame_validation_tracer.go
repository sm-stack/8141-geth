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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// FrameValidationError represents a specific ERC-7562 rule violation detected
// during VERIFY frame simulation.
type FrameValidationError struct {
	Rule    string // e.g. "OP-011", "OP-012"
	Message string
}

func (e *FrameValidationError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Rule, e.Message)
}

// bannedOpcodes is the set of opcodes forbidden in VERIFY frames per ERC-7562 [OP-011].
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

// storageAccess records an external storage read for post-execution validation.
type storageAccess struct {
	addr common.Address // The contract whose storage was read
	slot common.Hash    // The storage slot that was read
}

// FrameValidationTracer checks ERC-7562-style rules during VERIFY frame simulation.
// It is designed to be lightweight and fail-fast: it records the first violation
// and short-circuits all subsequent hooks. Storage access rules (STO-xxx) are
// validated post-execution since associated storage detection requires keccak
// preimage matching.
type FrameValidationTracer struct {
	stateDB     StateDB        // For GetCodeSize (OP-041) and GetState (STO-021)
	sender      common.Address // tx.sender — exempt from OP-041, owns storage (STO-010)
	frameTarget common.Address // VERIFY frame target — exempt from STO-021 (entity's own storage)
	precompiles map[common.Address]bool

	lastOp         OpCode // Previous opcode for GAS rule (OP-012)
	lastOpValid    bool   // Whether lastOp is meaningful
	allowTimestamp bool
	options        FrameValidationTracerOptions

	violation *FrameValidationError // First violation (nil = no violation)

	// externalStorageAccesses records SLOAD reads from contracts other than the
	// sender. These are validated post-execution against STO-021 associated
	// storage rules.
	externalStorageAccesses []storageAccess

	// keccakPreimages collects KECCAK256 input data observed during execution.
	// Used post-execution to determine if a slot is "associated" with the sender
	// via keccak256(sender || x) derivation (Solidity mapping pattern).
	keccakPreimages map[string]struct{}
}

// FrameValidationTracerOptions configures EIP-8141 validation-prefix exceptions.
type FrameValidationTracerOptions struct {
	// AllowCreate permits CREATE/CREATE2 in the first deploy frame of a validation prefix.
	AllowCreate bool

	// AllowSenderStorageWrites permits SSTORE only when the executing scope is tx.sender.
	AllowSenderStorageWrites bool
}

// NewFrameValidationTracer creates a tracer for VERIFY frame validation.
// frameTarget is the VERIFY frame's target address — its own storage is exempt
// from STO-021 checks (entity's own storage, analogous to ERC-7562 STO-031).
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
		stateDB:         stateDB,
		sender:          sender,
		frameTarget:     frameTarget,
		precompiles:     pm,
		allowTimestamp:  frameTarget == params.FrameExpiryVerifierAddress && bytes.Equal(stateDB.GetCode(frameTarget), params.FrameExpiryVerifierCode),
		options:         opts,
		keccakPreimages: make(map[string]struct{}),
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

	// Reset lastOp tracking on RETURN/REVERT BEFORE checking OP-012.
	// This matches the erc7562 tracer pattern (erc7562.go:396-400):
	// GAS→RETURN is valid since RETURN ends the call frame.
	if opcode == RETURN || opcode == REVERT {
		t.lastOpValid = false
	}

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
				if t.stateDB.GetCodeSize(addr) == 0 {
					t.violation = &FrameValidationError{
						Rule:    "OP-041",
						Message: fmt.Sprintf("%s target %s has no code at pc=%d depth=%d", opcode, addr.Hex(), pc, depth),
					}
					return
				}
			}
		}
	}

	// [STO-010, STO-021] Track external storage reads for post-execution validation.
	// SSTORE is already blocked by STATICCALL readOnly mode.
	if opcode == SLOAD && scope != nil {
		stackData := scope.StackData()
		if len(stackData) > 0 {
			slot := common.BytesToHash(stackData[len(stackData)-1].Bytes())
			addr := scope.Address()
			// STO-010: sender's own storage is always allowed.
			// STO-031 (adapted): VERIFY frame target's own storage is allowed
			// (entity's own storage — EIP-8141 has no staking, so unconditional).
			if addr != t.sender && addr != t.frameTarget {
				t.externalStorageAccesses = append(t.externalStorageAccesses, storageAccess{addr: addr, slot: slot})
			}
		}
	}

	// Collect KECCAK256 preimages for associated storage detection (STO-021).
	// Solidity mapping keys are keccak256(abi.encode(addr, slot)) = 64 bytes.
	// Cap at 128 to cover nested mappings while filtering irrelevant hashes.
	if opcode == KECCAK256 && scope != nil {
		stackData := scope.StackData()
		if len(stackData) >= 2 {
			dataOffset := stackData[len(stackData)-1].Uint64()
			dataLength := stackData[len(stackData)-2].Uint64()
			if dataLength > 0 && dataLength <= 128 {
				mem := scope.MemoryData()
				if dataOffset+dataLength <= uint64(len(mem)) {
					preimage := make([]byte, dataLength)
					copy(preimage, mem[dataOffset:dataOffset+dataLength])
					t.keccakPreimages[string(preimage)] = struct{}{}
				}
			}
		}
	}

	// Track lastOp for OP-012 (RETURN/REVERT already handled above).
	if opcode != RETURN && opcode != REVERT {
		t.lastOp = opcode
		t.lastOpValid = true
	}
}

// OnEnter is called when EVM enters a new call scope.
func (t *FrameValidationTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// No additional checks needed beyond what OnOpcode handles.
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
	// [STO-021] Post-execution storage access validation.
	// Depth 1 = the VERIFY frame's StaticCall scope exit. At this point all
	// keccak preimages from inner calls have been collected.
	if depth == 1 {
		t.validateStorageAccess()
	}
}

// validateStorageAccess checks all recorded external storage accesses against
// ERC-7562 STO-021 (associated storage) rules. Called post-execution when all
// keccak preimages have been collected.
func (t *FrameValidationTracer) validateStorageAccess() {
	if t.violation != nil || len(t.externalStorageAccesses) == 0 {
		return
	}
	// STO-021 prerequisite: sender must exist in state for associated
	// storage access to be allowed.
	if !t.stateDB.Exist(t.sender) {
		a := t.externalStorageAccesses[0]
		t.violation = &FrameValidationError{
			Rule:    "STO-021",
			Message: fmt.Sprintf("external storage read at %s slot %s: sender %s does not exist", a.addr.Hex(), a.slot.Hex(), t.sender.Hex()),
		}
		return
	}
	senderHash := common.BytesToHash(t.sender.Bytes())
	for _, access := range t.externalStorageAccesses {
		if !t.isAssociatedStorage(access, senderHash) {
			t.violation = &FrameValidationError{
				Rule:    "STO-021",
				Message: fmt.Sprintf("non-associated external storage read at %s slot %s", access.addr.Hex(), access.slot.Hex()),
			}
			return
		}
	}
}

// isAssociatedStorage checks whether a storage slot is "associated" with the
// sender address per ERC-7562:
//  1. The slot's current value equals the sender address (direct match).
//  2. The slot was derived as keccak256(sender || x) + n where n in [0, 128].
func (t *FrameValidationTracer) isAssociatedStorage(access storageAccess, senderHash common.Hash) bool {
	// Check 1: direct value match — slot value equals sender address.
	slotValue := t.stateDB.GetState(access.addr, access.slot)
	if slotValue == senderHash {
		return true
	}
	// Check 2: keccak-derived — slot == keccak256(sender || x) + n.
	for preimage := range t.keccakPreimages {
		preimageBytes := []byte(preimage)
		if len(preimageBytes) < 32 {
			continue
		}
		// First 32 bytes must be the sender address (left-padded).
		if !bytes.Equal(preimageBytes[:32], senderHash[:]) {
			continue
		}
		hash := crypto.Keccak256Hash(preimageBytes)
		diff := new(big.Int).Sub(access.slot.Big(), hash.Big())
		if diff.Sign() >= 0 && diff.Cmp(big.NewInt(128)) <= 0 {
			return true
		}
	}
	return false
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
