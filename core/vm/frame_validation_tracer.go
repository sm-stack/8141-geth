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

// ValidationMutableReadKind identifies the first mutable execution input read
// by an EIP-8141 validation frame.
type ValidationMutableReadKind uint8

const (
	ValidationMutableReadNone ValidationMutableReadKind = iota
	ValidationMutableReadStorage
	ValidationMutableReadLegacyNonce
	ValidationMutableReadCode
	ValidationMutableReadEnvironment
	ValidationMutableReadDeployment
	ValidationMutableReadPriorFrame
)

// ValidationWorkProfile describes the maximum execution gas that may be spent
// after a validation frame first observes mutable input. The bound is the
// frame-wide gas remaining immediately before that read, not the gas actually
// consumed by the observed suffix.
type ValidationWorkProfile struct {
	HasMutableRead            bool
	FirstMutableReadKind      ValidationMutableReadKind
	FirstMutableReadPC        uint64
	FirstMutableReadDepth     int
	FrameGasLimit             uint64
	CachedPrecompileGas       uint64 // Retained native-call gas before the global watershed.
	GasUsedBeforeFirstMutable uint64
	StateDependentGasLimit    uint64
	GasAccountingConservative bool
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
	stateDB        StateDB        // For validation target code inspection.
	sender         common.Address // tx.sender — exempt from OP-041, owns storage (STO-010)
	frameTarget    common.Address // VERIFY frame target
	precompiles    map[common.Address]bool
	storageReads   map[common.Hash]struct{}
	codeReads      map[common.Address]struct{}
	existenceReads map[common.Address]struct{}
	legacyNonce    bool
	blobBaseFee    bool

	lastOp         OpCode // Previous opcode for GAS rule (OP-012)
	lastOpValid    bool   // Whether lastOp is meaningful
	allowTimestamp bool
	options        FrameValidationTracerOptions
	profile        ValidationWorkProfile
	parentRetained map[int]uint64
	rootEntered    bool

	violation *FrameValidationError // First violation (nil = no violation)

}

// FrameValidationTracerOptions configures EIP-8141 validation-prefix exceptions.
type FrameValidationTracerOptions struct {
	// AllowCreate permits CREATE/CREATE2 in the first deploy frame of a validation prefix.
	AllowCreate bool

	// AllowSenderStorageWrites permits SSTORE only when the executing scope is tx.sender.
	AllowSenderStorageWrites bool

	// ProfileOnly records dependencies and work without enforcing public-mempool
	// trace rules. It is used for protocol-recognized validation programs whose
	// existing acceptance semantics must not change.
	ProfileOnly bool

	// Deployment charges the full declared frame execution gas as mutable work.
	Deployment bool

	// PriorFrameMutable marks the whole frame state-dependent because an earlier
	// validation frame observed mutable input. Frame results, gas usage, and the
	// shared access journal can carry that influence across the frame boundary.
	PriorFrameMutable bool

	// BlobBaseFeeAffectsMaxCost marks TXPARAM(max_cost) mutable for blob frame
	// transactions, where the returned value includes the current blob base fee.
	BlobBaseFeeAffectsMaxCost bool

	// FrameGasLimit is the declared execution gas of the validation frame.
	FrameGasLimit uint64

	// RootGasLimit is the execution gas passed to the root EVM call after the
	// frame-target access charge. RootGasLimitSet distinguishes a valid zero
	// budget from callers that do not precharge frame access.
	RootGasLimit    uint64
	RootGasLimitSet bool

	// PrecompileMemo is the frame-local memo view used by this validation EVM.
	// The tracer marks it after the first mutable read so memo statistics can
	// distinguish structural pure-prefix reuse.
	PrecompileMemo *PrecompileCache
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
		storageReads:   make(map[common.Hash]struct{}),
		codeReads:      make(map[common.Address]struct{}),
		existenceReads: make(map[common.Address]struct{}),
		allowTimestamp: frameTarget == params.FrameExpiryVerifierAddress && bytes.Equal(stateDB.GetCode(frameTarget), params.FrameExpiryVerifierCode),
		options:        opts,
		profile: ValidationWorkProfile{
			FrameGasLimit: opts.FrameGasLimit,
		},
		parentRetained: make(map[int]uint64),
	}
}

// WorkProfile returns the mutable-work measurement for this frame.
func (t *FrameValidationTracer) WorkProfile() ValidationWorkProfile {
	profile := t.profile
	if !profile.GasAccountingConservative {
		profile.CachedPrecompileGas = t.options.PrecompileMemo.ReusableValidationGas()
	}
	return profile
}

// StorageReads returns the tx.sender storage slots read by the validation frame.
// The validation rules reject storage reads in any other account.
func (t *FrameValidationTracer) StorageReads() []common.Hash {
	reads := make([]common.Hash, 0, len(t.storageReads))
	for slot := range t.storageReads {
		reads = append(reads, slot)
	}
	return reads
}

// CodeReads returns addresses whose code identity was observed through CALL*
// or EXTCODE*. EXTCODE* remains an identity read at precompile addresses even
// though calling the active precompile itself is pure.
// Callers can snapshot their code hashes to decide whether a pending validation
// result remains reusable at a later head.
func (t *FrameValidationTracer) CodeReads() []common.Address {
	reads := make([]common.Address, 0, len(t.codeReads))
	for addr := range t.codeReads {
		reads = append(reads, addr)
	}
	return reads
}

// AccountExistenceReads returns addresses whose existence was observed by
// EXTCODEHASH. An account can move from non-existent to empty-code through a
// balance or nonce change without a code write.
func (t *FrameValidationTracer) AccountExistenceReads() []common.Address {
	reads := make([]common.Address, 0, len(t.existenceReads))
	for addr := range t.existenceReads {
		reads = append(reads, addr)
	}
	return reads
}

// ReadsLegacyNonce reports whether validation introspected the sender's
// pre-state legacy account nonce through TXPARAM.
func (t *FrameValidationTracer) ReadsLegacyNonce() bool {
	return t.legacyNonce
}

// ReadsBlobBaseFee reports whether validation read TXPARAM(max_cost) for a blob
// transaction, whose result changes with the block's blob base fee.
func (t *FrameValidationTracer) ReadsBlobBaseFee() bool {
	return t.blobBaseFee
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
	if t.options.Deployment {
		t.recordMutableRead(ValidationMutableReadDeployment, pc, depth, gas)
	}
	if opcode == TXPARAM && scope != nil {
		stackData := scope.StackData()
		if len(stackData) > 0 {
			selector, overflow := stackData[len(stackData)-1].Uint64WithOverflow()
			if !overflow {
				switch selector {
				case txParamLegacyNonce:
					t.legacyNonce = true
					t.recordMutableRead(ValidationMutableReadLegacyNonce, pc, depth, gas)
				case txParamMaxCost:
					if t.options.BlobBaseFeeAffectsMaxCost {
						t.blobBaseFee = true
						t.recordMutableRead(ValidationMutableReadEnvironment, pc, depth, gas)
					}
				}
			}
		}
	}
	if opcode == SLOAD {
		t.recordMutableRead(ValidationMutableReadStorage, pc, depth, gas)
	}
	if opcode == TIMESTAMP && t.allowTimestamp {
		t.recordMutableRead(ValidationMutableReadEnvironment, pc, depth, gas)
	}
	if isExtOrCallOp(opcode) && scope != nil {
		if addr, ok := validationCodeTarget(opcode, scope); ok {
			if opcode == EXTCODEHASH {
				t.existenceReads[addr] = struct{}{}
			}
			mutableIdentity := isExtOp(opcode) || !t.precompiles[addr]
			if mutableIdentity && addr != t.sender && addr != t.frameTarget {
				t.recordMutableRead(ValidationMutableReadCode, pc, depth, gas)
			}
		}
	}
	if isCallOp(opcode) {
		t.trackParentRetainedGas(depth, gas, cost)
	}

	// [OP-012] Check if previous opcode was GAS not followed by CALL.
	if !t.options.ProfileOnly && t.lastOpValid && t.lastOp == GAS && !isCallOp(opcode) {
		t.violation = &FrameValidationError{
			Rule:    "OP-012",
			Message: fmt.Sprintf("GAS opcode not followed by CALL (followed by %s at pc=%d depth=%d)", opcode, pc, depth),
		}
		return
	}

	// [OP-011, OP-080] Check banned opcodes.
	if !t.options.ProfileOnly && bannedOpcodes[opcode] {
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
		if addr, ok := validationCodeTarget(opcode, scope); ok {
			if isExtOp(opcode) || !t.precompiles[addr] {
				t.codeReads[addr] = struct{}{}
			}
			// Skip precompiles and sender (OP-042 exception).
			if !t.options.ProfileOnly && !t.precompiles[addr] && addr != t.sender {
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
		addr := scope.Address()
		if !t.options.ProfileOnly && addr != t.sender {
			t.violation = &FrameValidationError{
				Rule:    "STO-010",
				Message: fmt.Sprintf("storage read outside sender at %s", addr.Hex()),
			}
			return
		}
		if addr == t.sender {
			stackData := scope.StackData()
			if len(stackData) > 0 {
				t.storageReads[common.Hash(stackData[len(stackData)-1].Bytes32())] = struct{}{}
			}
		}
	}

	// Track lastOp for OP-012.
	if !t.options.ProfileOnly {
		t.lastOp = opcode
		t.lastOpValid = true
	}
}

// OnEnter is called when EVM enters a new call scope.
func (t *FrameValidationTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if t.violation != nil {
		return
	}
	if depth == 0 {
		if t.rootEntered {
			t.markGasAccountingConservative()
		} else {
			t.rootEntered = true
			expectedRootGas := t.profile.FrameGasLimit
			if t.options.RootGasLimitSet {
				expectedRootGas = t.options.RootGasLimit
			}
			if t.profile.FrameGasLimit == 0 && !t.options.RootGasLimitSet {
				t.profile.FrameGasLimit = gas
			} else if gas != expectedRootGas {
				t.markGasAccountingConservative()
			}
			if t.options.Deployment {
				t.recordMutableRead(ValidationMutableReadDeployment, 0, 0, t.profile.FrameGasLimit)
			} else if t.options.PriorFrameMutable {
				t.recordMutableRead(ValidationMutableReadPriorFrame, 0, 0, t.profile.FrameGasLimit)
			}
		}
	} else if depth > 0 {
		if _, ok := t.parentRetained[depth]; !ok {
			t.markGasAccountingConservative()
		}
	}
	opcode := OpCode(typ)
	if opcode != CREATE && opcode != CREATE2 {
		return
	}
	if !t.options.ProfileOnly && (!t.options.AllowCreate || to != t.sender) {
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
	if depth == 0 && len(t.parentRetained) != 0 {
		t.markGasAccountingConservative()
	} else if depth > 0 {
		if _, ok := t.parentRetained[depth]; !ok {
			t.markGasAccountingConservative()
		} else {
			delete(t.parentRetained, depth)
		}
	}
	// [OP-020] Out-of-gas revert is forbidden — prevents gas limit probing.
	if !t.options.ProfileOnly && (errors.Is(err, ErrOutOfGas) || errors.Is(err, ErrCodeStoreOutOfGas)) {
		t.violation = &FrameValidationError{
			Rule:    "OP-020",
			Message: "out-of-gas during VERIFY frame execution",
		}
		return
	}
}

func validationCodeTarget(opcode OpCode, scope tracing.OpContext) (common.Address, bool) {
	stackData := scope.StackData()
	addrIndex := 0
	if isCallOp(opcode) {
		addrIndex = 1 // CALL-type: address is stack[1] (after gas argument)
	}
	if len(stackData) <= addrIndex {
		return common.Address{}, false
	}
	return common.BytesToAddress(stackData[len(stackData)-addrIndex-1].Bytes()), true
}

func (t *FrameValidationTracer) trackParentRetainedGas(depth int, gas, cost uint64) {
	if depth <= 0 {
		t.markGasAccountingConservative()
		return
	}
	if _, exists := t.parentRetained[depth]; exists || cost > gas {
		t.markGasAccountingConservative()
		return
	}
	t.parentRetained[depth] = gas - cost
}

func (t *FrameValidationTracer) recordMutableRead(kind ValidationMutableReadKind, pc uint64, depth int, localGas uint64) {
	t.options.PrecompileMemo.MarkValidationMutable()
	if t.profile.HasMutableRead {
		return
	}
	t.profile.HasMutableRead = true
	t.profile.FirstMutableReadKind = kind
	t.profile.FirstMutableReadPC = pc
	t.profile.FirstMutableReadDepth = depth
	if t.profile.GasAccountingConservative {
		t.profile.StateDependentGasLimit = t.profile.FrameGasLimit
		return
	}
	remaining := localGas
	for parentDepth, retained := range t.parentRetained {
		if parentDepth >= depth || ^uint64(0)-remaining < retained {
			t.markGasAccountingConservative()
			return
		}
		remaining += retained
	}
	if t.profile.FrameGasLimit == 0 || remaining > t.profile.FrameGasLimit {
		t.markGasAccountingConservative()
		return
	}
	t.profile.StateDependentGasLimit = remaining
	t.profile.GasUsedBeforeFirstMutable = t.profile.FrameGasLimit - remaining
}

func (t *FrameValidationTracer) markGasAccountingConservative() {
	t.options.PrecompileMemo.MarkValidationMutable()
	t.profile.GasAccountingConservative = true
	t.profile.StateDependentGasLimit = t.profile.FrameGasLimit
	t.profile.GasUsedBeforeFirstMutable = 0
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
