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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
)

// mockStateDB implements StateDB for tracer tests.
type mockStateDB struct {
	codeSize map[common.Address]int
	code     map[common.Address][]byte
	state    map[common.Address]map[common.Hash]common.Hash // For GetState (STO-021)
	exists   map[common.Address]bool                        // For Exist (STO-021)
}

func (m *mockStateDB) GetCodeSize(addr common.Address) int { return m.codeSize[addr] }

// Boilerplate — unused by the tracer.
func (m *mockStateDB) CreateAccount(common.Address)  {}
func (m *mockStateDB) CreateContract(common.Address) {}
func (m *mockStateDB) SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (m *mockStateDB) AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int {
	return uint256.Int{}
}
func (m *mockStateDB) GetBalance(common.Address) *uint256.Int                          { return new(uint256.Int) }
func (m *mockStateDB) GetNonce(common.Address) uint64                                  { return 0 }
func (m *mockStateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason)      {}
func (m *mockStateDB) GetCodeHash(common.Address) common.Hash                          { return common.Hash{} }
func (m *mockStateDB) GetCode(addr common.Address) []byte                              { return m.code[addr] }
func (m *mockStateDB) SetCode(common.Address, []byte, tracing.CodeChangeReason) []byte { return nil }
func (m *mockStateDB) AddRefund(uint64)                                                {}
func (m *mockStateDB) SubRefund(uint64)                                                {}
func (m *mockStateDB) GetRefund() uint64                                               { return 0 }
func (m *mockStateDB) GetStateAndCommittedState(common.Address, common.Hash) (common.Hash, common.Hash) {
	return common.Hash{}, common.Hash{}
}
func (m *mockStateDB) GetState(addr common.Address, slot common.Hash) common.Hash {
	if m.state != nil {
		if slots, ok := m.state[addr]; ok {
			return slots[slot]
		}
	}
	return common.Hash{}
}
func (m *mockStateDB) SetState(common.Address, common.Hash, common.Hash) common.Hash {
	return common.Hash{}
}
func (m *mockStateDB) GetStorageRoot(common.Address) common.Hash { return common.Hash{} }
func (m *mockStateDB) GetTransientState(common.Address, common.Hash) common.Hash {
	return common.Hash{}
}
func (m *mockStateDB) SetTransientState(common.Address, common.Hash, common.Hash) {}
func (m *mockStateDB) ResetTransientStorage()                                     {}
func (m *mockStateDB) SelfDestruct(common.Address) uint256.Int                    { return uint256.Int{} }
func (m *mockStateDB) HasSelfDestructed(common.Address) bool                      { return false }
func (m *mockStateDB) SelfDestruct6780(common.Address) (uint256.Int, bool) {
	return uint256.Int{}, false
}
func (m *mockStateDB) Exist(addr common.Address) bool {
	if m.exists != nil {
		return m.exists[addr]
	}
	return false
}
func (m *mockStateDB) Empty(common.Address) bool                                 { return true }
func (m *mockStateDB) AddressInAccessList(common.Address) bool                   { return false }
func (m *mockStateDB) SlotInAccessList(common.Address, common.Hash) (bool, bool) { return false, false }
func (m *mockStateDB) AddAddressToAccessList(common.Address)                     {}
func (m *mockStateDB) AddSlotToAccessList(common.Address, common.Hash)           {}
func (m *mockStateDB) PointCache() *utils.PointCache                             { return nil }
func (m *mockStateDB) Prepare(params.Rules, common.Address, common.Address, *common.Address, []common.Address, types.AccessList) {
}
func (m *mockStateDB) RevertToSnapshot(int)              {}
func (m *mockStateDB) Snapshot() int                     { return 0 }
func (m *mockStateDB) AddLog(*types.Log)                 {}
func (m *mockStateDB) AddPreimage(common.Hash, []byte)   {}
func (m *mockStateDB) TxLogSize() int                    { return 0 }
func (m *mockStateDB) Witness() *stateless.Witness       { return nil }
func (m *mockStateDB) AccessEvents() *state.AccessEvents { return nil }
func (m *mockStateDB) Finalise(bool)                     {}

// mockScope implements tracing.OpContext for tests.
type mockScope struct {
	stackData  []uint256.Int
	memoryData []byte         // For KECCAK256 preimage reads
	address    common.Address // Contract address for SLOAD scope
}

func (s *mockScope) MemoryData() []byte       { return s.memoryData }
func (s *mockScope) StackData() []uint256.Int { return s.stackData }
func (s *mockScope) Caller() common.Address   { return common.Address{} }
func (s *mockScope) Address() common.Address  { return s.address }
func (s *mockScope) CallValue() *uint256.Int  { return new(uint256.Int) }
func (s *mockScope) CallInput() []byte        { return nil }
func (s *mockScope) ContractCode() []byte     { return nil }

var (
	testSender      = common.HexToAddress("0x1111111111111111111111111111111111111111")
	testPrecompile1 = common.HexToAddress("0x01") // ecrecover
	testContract    = common.HexToAddress("0x2222222222222222222222222222222222222222")
	testEmpty       = common.HexToAddress("0x3333333333333333333333333333333333333333")
)

func newTestTracer() *FrameValidationTracer {
	state := &mockStateDB{
		codeSize: map[common.Address]int{
			testContract:    100,
			testPrecompile1: 0, // precompiles have no code but are whitelisted
		},
	}
	return NewFrameValidationTracer(state, testSender, testSender, []common.Address{testPrecompile1})
}

// scopeForExt creates a mock scope for EXT* opcodes (address at stack top).
func scopeForExt(addr common.Address) *mockScope {
	val := new(uint256.Int).SetBytes(addr.Bytes())
	return &mockScope{stackData: []uint256.Int{*val}}
}

// scopeForCall creates a mock scope for CALL opcodes (address at stack[1], gas at top).
func scopeForCall(addr common.Address) *mockScope {
	val := new(uint256.Int).SetBytes(addr.Bytes())
	gas := *uint256.NewInt(100000)
	// Stack bottom→top: addr, gas
	return &mockScope{stackData: []uint256.Int{*val, gas}}
}

func emptyScope() *mockScope {
	return &mockScope{stackData: []uint256.Int{*uint256.NewInt(0)}}
}

// TestFrameValidationBannedOpcodes verifies OP-011 and OP-080 banned opcodes.
func TestFrameValidationBannedOpcodes(t *testing.T) {
	cases := []struct {
		op   OpCode
		rule string
	}{
		{ORIGIN, "OP-011"},
		{GASPRICE, "OP-011"},
		{BLOCKHASH, "OP-011"},
		{COINBASE, "OP-011"},
		{TIMESTAMP, "OP-011"},
		{NUMBER, "OP-011"},
		{PREVRANDAO, "OP-011"},
		{GASLIMIT, "OP-011"},
		{BASEFEE, "OP-011"},
		{BLOBHASH, "OP-011"},
		{BLOBBASEFEE, "OP-011"},
		{SSTORE, "OP-011"},
		{TLOAD, "OP-011"},
		{TSTORE, "OP-011"},
		{CREATE, "OP-011"},
		{CREATE2, "OP-011"},
		{SELFDESTRUCT, "OP-011"},
		{INVALID, "OP-011"},
		{BALANCE, "OP-080"},
		{SELFBALANCE, "OP-080"},
	}
	for _, tc := range cases {
		t.Run(tc.op.String(), func(t *testing.T) {
			tracer := newTestTracer()
			tracer.OnOpcode(0, byte(tc.op), 100000, 3, emptyScope(), nil, 1, nil)
			v := tracer.Violation()
			if v == nil {
				t.Fatalf("expected violation for %s", tc.op)
			}
			if v.Rule != tc.rule {
				t.Fatalf("expected rule %s, got %s", tc.rule, v.Rule)
			}
		})
	}
}

func TestFrameValidationDeployOptions(t *testing.T) {
	state := &mockStateDB{
		codeSize: map[common.Address]int{
			testContract: 100,
		},
	}
	tracer := NewFrameValidationTracerWithOptions(state, testSender, testSender, []common.Address{testPrecompile1}, FrameValidationTracerOptions{
		AllowCreate:              true,
		AllowSenderStorageWrites: true,
	})
	tracer.OnOpcode(0, byte(CREATE), 100000, 32000, emptyScope(), nil, 1, nil)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation for CREATE with deploy option: %s", v)
	}
	tracer.OnOpcode(1, byte(CREATE2), 100000, 32000, emptyScope(), nil, 1, nil)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation for CREATE2 with deploy option: %s", v)
	}
	tracer.OnOpcode(2, byte(SSTORE), 100000, 100, &mockScope{address: testSender}, nil, 1, nil)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation for sender SSTORE with deploy option: %s", v)
	}

	tracer = NewFrameValidationTracerWithOptions(state, testSender, testSender, []common.Address{testPrecompile1}, FrameValidationTracerOptions{
		AllowCreate:              true,
		AllowSenderStorageWrites: true,
	})
	tracer.OnOpcode(0, byte(SSTORE), 100000, 100, &mockScope{address: testContract}, nil, 1, nil)
	if v := tracer.Violation(); v == nil {
		t.Fatal("expected SSTORE violation outside sender storage")
	}
}

func TestFrameValidationExpiryVerifierAllowsTimestamp(t *testing.T) {
	state := &mockStateDB{
		codeSize: map[common.Address]int{
			params.FrameExpiryVerifierAddress: len(params.FrameExpiryVerifierCode),
		},
		code: map[common.Address][]byte{
			params.FrameExpiryVerifierAddress: params.FrameExpiryVerifierCode,
		},
	}
	tracer := NewFrameValidationTracer(state, testSender, params.FrameExpiryVerifierAddress, []common.Address{testPrecompile1})
	tracer.OnOpcode(0, byte(TIMESTAMP), 100000, 2, emptyScope(), nil, 1, nil)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation for canonical expiry verifier TIMESTAMP: %s", v)
	}
}

func TestFrameValidationExpiryVerifierRejectsTimestampWithoutCanonicalCode(t *testing.T) {
	state := &mockStateDB{
		codeSize: map[common.Address]int{
			params.FrameExpiryVerifierAddress: 1,
		},
		code: map[common.Address][]byte{
			params.FrameExpiryVerifierAddress: []byte{byte(STOP)},
		},
	}
	tracer := NewFrameValidationTracer(state, testSender, params.FrameExpiryVerifierAddress, []common.Address{testPrecompile1})
	tracer.OnOpcode(0, byte(TIMESTAMP), 100000, 2, emptyScope(), nil, 1, nil)
	if v := tracer.Violation(); v == nil {
		t.Fatal("expected TIMESTAMP violation without canonical expiry verifier code")
	}
}

// TestFrameValidationAllowedOpcodes verifies allowed opcodes pass.
func TestFrameValidationAllowedOpcodes(t *testing.T) {
	allowed := []OpCode{
		APPROVE, TXPARAM, FRAMEDATALOAD, FRAMEDATACOPY, FRAMEPARAM, SIGPARAM,
		STATICCALL, SLOAD, KECCAK256, PUSH1, POP, ADD, MLOAD, MSTORE,
		RETURN, REVERT, STOP, JUMP, JUMPI, JUMPDEST, CALLDATALOAD,
	}
	for _, op := range allowed {
		t.Run(op.String(), func(t *testing.T) {
			tracer := newTestTracer()
			var scope *mockScope
			if op == STATICCALL {
				scope = scopeForCall(testContract)
			} else {
				scope = emptyScope()
			}
			tracer.OnOpcode(0, byte(op), 100000, 3, scope, nil, 1, nil)
			if v := tracer.Violation(); v != nil {
				t.Fatalf("unexpected violation for %s: %s", op, v)
			}
		})
	}
}

// TestFrameValidationGasFollowedByCall verifies OP-012.
func TestFrameValidationGasFollowedByCall(t *testing.T) {
	t.Run("GAS_then_STATICCALL", func(t *testing.T) {
		tracer := newTestTracer()
		tracer.OnOpcode(0, byte(GAS), 100000, 2, emptyScope(), nil, 1, nil)
		tracer.OnOpcode(1, byte(STATICCALL), 100000, 100, scopeForCall(testContract), nil, 1, nil)
		if v := tracer.Violation(); v != nil {
			t.Fatalf("unexpected violation: %s", v)
		}
	})

	t.Run("GAS_then_CALL", func(t *testing.T) {
		tracer := newTestTracer()
		tracer.OnOpcode(0, byte(GAS), 100000, 2, emptyScope(), nil, 1, nil)
		tracer.OnOpcode(1, byte(CALL), 100000, 100, scopeForCall(testContract), nil, 1, nil)
		if v := tracer.Violation(); v != nil {
			t.Fatalf("unexpected violation: %s", v)
		}
	})

	t.Run("GAS_then_ADD", func(t *testing.T) {
		tracer := newTestTracer()
		tracer.OnOpcode(0, byte(GAS), 100000, 2, emptyScope(), nil, 1, nil)
		tracer.OnOpcode(1, byte(ADD), 100000, 3, emptyScope(), nil, 1, nil)
		v := tracer.Violation()
		if v == nil {
			t.Fatal("expected OP-012 violation")
		}
		if v.Rule != "OP-012" {
			t.Fatalf("expected rule OP-012, got %s", v.Rule)
		}
	})

	t.Run("GAS_then_PUSH1", func(t *testing.T) {
		tracer := newTestTracer()
		tracer.OnOpcode(0, byte(GAS), 100000, 2, emptyScope(), nil, 1, nil)
		tracer.OnOpcode(1, byte(PUSH1), 100000, 3, emptyScope(), nil, 1, nil)
		v := tracer.Violation()
		if v == nil {
			t.Fatal("expected OP-012 violation")
		}
		if v.Rule != "OP-012" {
			t.Fatalf("expected rule OP-012, got %s", v.Rule)
		}
	})
}

// TestFrameValidationGasResetOnReturn verifies lastOp tracking resets on RETURN.
func TestFrameValidationGasResetOnReturn(t *testing.T) {
	tracer := newTestTracer()
	tracer.OnOpcode(0, byte(GAS), 100000, 2, emptyScope(), nil, 1, nil)
	tracer.OnOpcode(1, byte(RETURN), 100000, 0, emptyScope(), nil, 1, nil)
	tracer.OnOpcode(2, byte(ADD), 100000, 3, emptyScope(), nil, 1, nil)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation: %s", v)
	}
}

// TestFrameValidationExtCodeEmptyAddress verifies OP-041.
func TestFrameValidationExtCodeEmptyAddress(t *testing.T) {
	for _, op := range []OpCode{EXTCODEHASH, EXTCODESIZE, EXTCODECOPY} {
		t.Run(op.String(), func(t *testing.T) {
			tracer := newTestTracer()
			tracer.OnOpcode(0, byte(op), 100000, 100, scopeForExt(testEmpty), nil, 1, nil)
			v := tracer.Violation()
			if v == nil {
				t.Fatalf("expected OP-041 violation for %s", op)
			}
			if v.Rule != "OP-041" {
				t.Fatalf("expected rule OP-041, got %s", v.Rule)
			}
		})
	}

	t.Run("STATICCALL_empty", func(t *testing.T) {
		tracer := newTestTracer()
		tracer.OnOpcode(0, byte(STATICCALL), 100000, 100, scopeForCall(testEmpty), nil, 1, nil)
		v := tracer.Violation()
		if v == nil {
			t.Fatal("expected OP-041 violation")
		}
		if v.Rule != "OP-041" {
			t.Fatalf("expected rule OP-041, got %s", v.Rule)
		}
	})
}

// TestFrameValidationExtCodeSenderException verifies OP-042 sender exemption.
func TestFrameValidationExtCodeSenderException(t *testing.T) {
	tracer := newTestTracer()
	tracer.OnOpcode(0, byte(EXTCODEHASH), 100000, 100, scopeForExt(testSender), nil, 1, nil)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation for sender: %s", v)
	}
}

// TestFrameValidationExtCodePrecompile verifies OP-062 precompile exemption.
func TestFrameValidationExtCodePrecompile(t *testing.T) {
	tracer := newTestTracer()
	tracer.OnOpcode(0, byte(STATICCALL), 100000, 100, scopeForCall(testPrecompile1), nil, 1, nil)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation for precompile: %s", v)
	}
}

// TestFrameValidationExtCodeWithCode verifies address with code passes OP-041.
func TestFrameValidationExtCodeWithCode(t *testing.T) {
	tracer := newTestTracer()
	tracer.OnOpcode(0, byte(EXTCODEHASH), 100000, 100, scopeForExt(testContract), nil, 1, nil)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation: %s", v)
	}
}

// TestFrameValidationOutOfGas verifies OP-020.
func TestFrameValidationOutOfGas(t *testing.T) {
	t.Run("ErrOutOfGas", func(t *testing.T) {
		tracer := newTestTracer()
		tracer.OnExit(1, nil, 100000, ErrOutOfGas, true)
		v := tracer.Violation()
		if v == nil {
			t.Fatal("expected OP-020 violation")
		}
		if v.Rule != "OP-020" {
			t.Fatalf("expected rule OP-020, got %s", v.Rule)
		}
	})

	t.Run("ErrCodeStoreOutOfGas", func(t *testing.T) {
		tracer := newTestTracer()
		tracer.OnExit(1, nil, 100000, ErrCodeStoreOutOfGas, true)
		v := tracer.Violation()
		if v == nil {
			t.Fatal("expected OP-020 violation")
		}
		if v.Rule != "OP-020" {
			t.Fatalf("expected rule OP-020, got %s", v.Rule)
		}
	})

	t.Run("NormalRevert", func(t *testing.T) {
		tracer := newTestTracer()
		tracer.OnExit(1, nil, 100000, ErrExecutionReverted, true)
		if v := tracer.Violation(); v != nil {
			t.Fatalf("unexpected violation: %s", v)
		}
	})
}

// TestFrameValidationFailFast verifies only first violation is recorded.
func TestFrameValidationFailFast(t *testing.T) {
	tracer := newTestTracer()
	tracer.OnOpcode(0, byte(ORIGIN), 100000, 2, emptyScope(), nil, 1, nil)
	first := tracer.Violation()
	if first == nil {
		t.Fatal("expected violation")
	}
	tracer.OnOpcode(1, byte(TIMESTAMP), 100000, 2, emptyScope(), nil, 1, nil)
	if tracer.Violation() != first {
		t.Fatal("violation should not change after first detection")
	}
}

// --- STO-xxx storage access rule tests ---

var (
	testExternalContract = common.HexToAddress("0x4444444444444444444444444444444444444444")
	testSlot             = common.HexToHash("0x01")
)

// newSTOTracer creates a tracer with configurable state and existence for STO tests.
func newSTOTracer(state map[common.Address]map[common.Hash]common.Hash, exists map[common.Address]bool) *FrameValidationTracer {
	db := &mockStateDB{
		codeSize: map[common.Address]int{
			testContract:         100,
			testExternalContract: 100,
		},
		state:  state,
		exists: exists,
	}
	return NewFrameValidationTracer(db, testSender, testSender, []common.Address{testPrecompile1})
}

// scopeForSload creates a scope for SLOAD: slot at stack top, with contract address.
func scopeForSload(contractAddr common.Address, slot common.Hash) *mockScope {
	slotVal := new(uint256.Int).SetBytes(slot.Bytes())
	return &mockScope{
		stackData: []uint256.Int{*slotVal},
		address:   contractAddr,
	}
}

// scopeForKeccak creates a scope for KECCAK256: offset=0, length on stack, data in memory.
func scopeForKeccak(preimage []byte) *mockScope {
	offset := uint256.NewInt(0)
	length := uint256.NewInt(uint64(len(preimage)))
	// Stack bottom→top: length, offset (KECCAK256 pops offset first, then length)
	return &mockScope{
		stackData:  []uint256.Int{*length, *offset},
		memoryData: preimage,
	}
}

// TestSTO010_SenderOwnStorage verifies sender's own storage is always allowed.
func TestSTO010_SenderOwnStorage(t *testing.T) {
	tracer := newSTOTracer(nil, map[common.Address]bool{testSender: true})
	scope := scopeForSload(testSender, testSlot)
	tracer.OnOpcode(0, byte(SLOAD), 100000, 200, scope, nil, 1, nil)
	tracer.OnExit(1, nil, 50000, nil, false)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation for sender own storage: %s", v)
	}
}

// TestSTO021_SenderNotExist verifies external storage rejected when sender doesn't exist.
func TestSTO021_SenderNotExist(t *testing.T) {
	tracer := newSTOTracer(nil, nil) // sender does not exist
	scope := scopeForSload(testExternalContract, testSlot)
	tracer.OnOpcode(0, byte(SLOAD), 100000, 200, scope, nil, 1, nil)
	tracer.OnExit(1, nil, 50000, nil, false)
	v := tracer.Violation()
	if v == nil {
		t.Fatal("expected STO-021 violation")
	}
	if v.Rule != "STO-021" {
		t.Fatalf("expected STO-021, got %s", v.Rule)
	}
}

// TestSTO021_DirectValueMatch verifies associated storage via direct value match.
func TestSTO021_DirectValueMatch(t *testing.T) {
	// External contract's slot value equals the sender address.
	senderHash := common.BytesToHash(testSender.Bytes())
	tracer := newSTOTracer(
		map[common.Address]map[common.Hash]common.Hash{
			testExternalContract: {testSlot: senderHash},
		},
		map[common.Address]bool{testSender: true},
	)
	scope := scopeForSload(testExternalContract, testSlot)
	tracer.OnOpcode(0, byte(SLOAD), 100000, 200, scope, nil, 1, nil)
	tracer.OnExit(1, nil, 50000, nil, false)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation: %s", v)
	}
}

// TestSTO021_KeccakDerived verifies associated storage via keccak derivation.
func TestSTO021_KeccakDerived(t *testing.T) {
	// Simulate: mapping(address => uint256) at storage position 0x05
	// Solidity computes: keccak256(abi.encode(sender, 0x05))
	senderHash := common.BytesToHash(testSender.Bytes())
	mappingSlot := common.BytesToHash([]byte{0x05})
	preimage := make([]byte, 64)
	copy(preimage[:32], senderHash[:])
	copy(preimage[32:], mappingSlot[:])
	derivedSlot := crypto.Keccak256Hash(preimage)

	tracer := newSTOTracer(nil, map[common.Address]bool{testSender: true})

	// First: KECCAK256 to record preimage.
	tracer.OnOpcode(0, byte(KECCAK256), 100000, 30, scopeForKeccak(preimage), nil, 1, nil)
	// Then: SLOAD on the derived slot.
	tracer.OnOpcode(1, byte(SLOAD), 100000, 200, scopeForSload(testExternalContract, derivedSlot), nil, 1, nil)
	tracer.OnExit(1, nil, 50000, nil, false)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation: %s", v)
	}
}

// TestSTO021_KeccakDerivedWithOffset verifies keccak + offset (struct in mapping).
func TestSTO021_KeccakDerivedWithOffset(t *testing.T) {
	senderHash := common.BytesToHash(testSender.Bytes())
	mappingSlot := common.BytesToHash([]byte{0x05})
	preimage := make([]byte, 64)
	copy(preimage[:32], senderHash[:])
	copy(preimage[32:], mappingSlot[:])
	baseSlot := crypto.Keccak256Hash(preimage)

	// Access slot = baseSlot + 3 (e.g., 4th field of a struct).
	offsetSlot := common.BigToHash(new(uint256.Int).Add(
		new(uint256.Int).SetBytes(baseSlot[:]),
		uint256.NewInt(3),
	).ToBig())

	tracer := newSTOTracer(nil, map[common.Address]bool{testSender: true})
	tracer.OnOpcode(0, byte(KECCAK256), 100000, 30, scopeForKeccak(preimage), nil, 1, nil)
	tracer.OnOpcode(1, byte(SLOAD), 100000, 200, scopeForSload(testExternalContract, offsetSlot), nil, 1, nil)
	tracer.OnExit(1, nil, 50000, nil, false)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation for offset 3: %s", v)
	}
}

// TestSTO021_KeccakOffsetExceeded verifies keccak + offset > 128 is rejected.
func TestSTO021_KeccakOffsetExceeded(t *testing.T) {
	senderHash := common.BytesToHash(testSender.Bytes())
	mappingSlot := common.BytesToHash([]byte{0x05})
	preimage := make([]byte, 64)
	copy(preimage[:32], senderHash[:])
	copy(preimage[32:], mappingSlot[:])
	baseSlot := crypto.Keccak256Hash(preimage)

	// Access slot = baseSlot + 129 (exceeds 128 limit).
	offsetSlot := common.BigToHash(new(uint256.Int).Add(
		new(uint256.Int).SetBytes(baseSlot[:]),
		uint256.NewInt(129),
	).ToBig())

	tracer := newSTOTracer(nil, map[common.Address]bool{testSender: true})
	tracer.OnOpcode(0, byte(KECCAK256), 100000, 30, scopeForKeccak(preimage), nil, 1, nil)
	tracer.OnOpcode(1, byte(SLOAD), 100000, 200, scopeForSload(testExternalContract, offsetSlot), nil, 1, nil)
	tracer.OnExit(1, nil, 50000, nil, false)
	v := tracer.Violation()
	if v == nil {
		t.Fatal("expected STO-021 violation for offset 129")
	}
	if v.Rule != "STO-021" {
		t.Fatalf("expected STO-021, got %s", v.Rule)
	}
}

// TestSTO021_NonAssociated verifies non-associated external storage is rejected.
func TestSTO021_NonAssociated(t *testing.T) {
	tracer := newSTOTracer(nil, map[common.Address]bool{testSender: true})
	// SLOAD on external contract — no keccak preimage, slot value doesn't match sender.
	scope := scopeForSload(testExternalContract, testSlot)
	tracer.OnOpcode(0, byte(SLOAD), 100000, 200, scope, nil, 1, nil)
	tracer.OnExit(1, nil, 50000, nil, false)
	v := tracer.Violation()
	if v == nil {
		t.Fatal("expected STO-021 violation")
	}
	if v.Rule != "STO-021" {
		t.Fatalf("expected STO-021, got %s", v.Rule)
	}
}

// TestSTO021_MixedAccesses verifies violation on third access in a mixed sequence.
func TestSTO021_MixedAccesses(t *testing.T) {
	senderHash := common.BytesToHash(testSender.Bytes())
	associatedSlot := common.HexToHash("0x10")
	nonAssociatedSlot := common.HexToHash("0x20")

	tracer := newSTOTracer(
		map[common.Address]map[common.Hash]common.Hash{
			testExternalContract: {associatedSlot: senderHash}, // direct value match
		},
		map[common.Address]bool{testSender: true},
	)
	// 1. Sender own storage — STO-010, always allowed.
	tracer.OnOpcode(0, byte(SLOAD), 100000, 200, scopeForSload(testSender, testSlot), nil, 1, nil)
	// 2. External associated storage — STO-021, allowed (direct match).
	tracer.OnOpcode(1, byte(SLOAD), 100000, 200, scopeForSload(testExternalContract, associatedSlot), nil, 1, nil)
	// 3. External non-associated — should fail.
	tracer.OnOpcode(2, byte(SLOAD), 100000, 200, scopeForSload(testExternalContract, nonAssociatedSlot), nil, 1, nil)
	tracer.OnExit(1, nil, 50000, nil, false)
	v := tracer.Violation()
	if v == nil {
		t.Fatal("expected STO-021 violation on third access")
	}
	if v.Rule != "STO-021" {
		t.Fatalf("expected STO-021, got %s", v.Rule)
	}
}

// TestSTO031_FrameTargetOwnStorage verifies that a VERIFY frame's target can
// read its own storage without STO-021 violation (entity's own storage exempt,
// analogous to ERC-7562 STO-031 without staking requirement).
func TestSTO031_FrameTargetOwnStorage(t *testing.T) {
	paymaster := common.HexToAddress("0x5555555555555555555555555555555555555555")
	db := &mockStateDB{
		codeSize: map[common.Address]int{
			testContract: 100,
			paymaster:    100,
		},
		exists: map[common.Address]bool{testSender: true},
	}
	// Tracer where sender != frameTarget (paymaster scenario).
	tracer := NewFrameValidationTracer(db, testSender, paymaster, []common.Address{testPrecompile1})

	// Paymaster reads its own storage — should be allowed.
	tracer.OnOpcode(0, byte(SLOAD), 100000, 200, scopeForSload(paymaster, testSlot), nil, 1, nil)
	tracer.OnExit(1, nil, 50000, nil, false)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation for frame target's own storage: %s", v)
	}
}

// TestSTO_NoExternalAccess verifies no violation when only sender storage is accessed.
func TestSTO_NoExternalAccess(t *testing.T) {
	tracer := newSTOTracer(nil, map[common.Address]bool{testSender: true})
	tracer.OnOpcode(0, byte(SLOAD), 100000, 200, scopeForSload(testSender, testSlot), nil, 1, nil)
	tracer.OnOpcode(1, byte(SLOAD), 100000, 200, scopeForSload(testSender, common.HexToHash("0x02")), nil, 1, nil)
	tracer.OnExit(1, nil, 50000, nil, false)
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation: %s", v)
	}
}
