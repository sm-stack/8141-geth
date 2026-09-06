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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/types/bal"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// mockStateDB implements StateDB for tracer tests.
type mockStateDB struct {
	codeSize map[common.Address]int
	code     map[common.Address][]byte
	state    map[common.Address]map[common.Hash]common.Hash
	exists   map[common.Address]bool
	touches  map[common.Address]int
}

func (m *mockStateDB) GetCodeSize(addr common.Address) int { return m.codeSize[addr] }
func (m *mockStateDB) StorageEmpty(common.Address) bool    { return true }

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
func (m *mockStateDB) SelfDestruct(common.Address)                                {}
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
func (m *mockStateDB) Empty(common.Address) bool         { return true }
func (m *mockStateDB) IsNewContract(common.Address) bool { return false }
func (m *mockStateDB) Touch(addr common.Address) {
	if m.touches != nil {
		m.touches[addr]++
	}
}
func (m *mockStateDB) AddressInAccessList(common.Address) bool                   { return false }
func (m *mockStateDB) SlotInAccessList(common.Address, common.Hash) (bool, bool) { return false, false }
func (m *mockStateDB) AddAddressToAccessList(common.Address)                     {}
func (m *mockStateDB) AddSlotToAccessList(common.Address, common.Hash)           {}
func (m *mockStateDB) Prepare(params.Rules, common.Address, common.Address, *common.Address, []common.Address, types.AccessList) {
}
func (m *mockStateDB) RevertToSnapshot(int)                                   {}
func (m *mockStateDB) Snapshot() int                                          { return 0 }
func (m *mockStateDB) AddLog(*types.Log)                                      {}
func (m *mockStateDB) LogsForBurnAccounts() []*types.Log                      { return nil }
func (m *mockStateDB) AddPreimage(common.Hash, []byte)                        {}
func (m *mockStateDB) TxLogSize() int                                         { return 0 }
func (m *mockStateDB) Witness() *stateless.Witness                            { return nil }
func (m *mockStateDB) AccessEvents() *state.AccessEvents                      { return nil }
func (m *mockStateDB) Finalise(params.Rules) *bal.ConstructionBlockAccessList { return nil }
func (m *mockStateDB) SetTxContext(common.Hash, int, uint32)                  {}

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
	tracer.OnEnter(2, byte(CREATE), testContract, testSender, nil, 50000, new(big.Int))
	if v := tracer.Violation(); v != nil {
		t.Fatalf("unexpected violation for CREATE with deploy option: %s", v)
	}
	tracer.OnOpcode(1, byte(CREATE2), 100000, 32000, emptyScope(), nil, 1, nil)
	tracer.OnEnter(2, byte(CREATE2), testContract, testSender, nil, 50000, new(big.Int))
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

	tracer = NewFrameValidationTracerWithOptions(state, testSender, testSender, []common.Address{testPrecompile1}, FrameValidationTracerOptions{
		AllowCreate: true,
	})
	tracer.OnOpcode(0, byte(CREATE2), 100000, 32000, emptyScope(), nil, 1, nil)
	tracer.OnEnter(2, byte(CREATE2), testContract, testContract, nil, 50000, new(big.Int))
	if v := tracer.Violation(); v == nil {
		t.Fatal("expected CREATE2 targeting an address other than sender to be rejected")
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
			} else if op == SLOAD {
				scope = scopeForSload(testSender, testSlot)
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

// TestFrameValidationRejectsGasBeforeReturn verifies only CALL-type opcodes may follow GAS.
func TestFrameValidationRejectsGasBeforeReturn(t *testing.T) {
	tracer := newTestTracer()
	tracer.OnOpcode(0, byte(GAS), 100000, 2, emptyScope(), nil, 1, nil)
	tracer.OnOpcode(1, byte(RETURN), 100000, 0, emptyScope(), nil, 1, nil)
	if v := tracer.Violation(); v == nil || v.Rule != "OP-012" {
		t.Fatalf("expected OP-012 violation, got %v", v)
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
	if reads := tracer.CodeReads(); len(reads) != 0 {
		t.Fatalf("precompile call recorded mutable code identity: %v", reads)
	}
}

func TestFrameValidationExtCodeHashTracksAccountExistence(t *testing.T) {
	tracer := newTestTracer()
	tracer.OnOpcode(0, byte(EXTCODEHASH), 100000, 100, scopeForExt(testPrecompile1), nil, 1, nil)
	if reads := tracer.CodeReads(); len(reads) != 1 || reads[0] != testPrecompile1 {
		t.Fatalf("precompile EXTCODEHASH code reads = %v", reads)
	}
	if reads := tracer.AccountExistenceReads(); len(reads) != 1 || reads[0] != testPrecompile1 {
		t.Fatalf("precompile EXTCODEHASH existence reads = %v", reads)
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

func TestFrameValidationRejectsDelegatedTarget(t *testing.T) {
	tracer := newTestTracer()
	db := tracer.stateDB.(*mockStateDB)
	db.code = make(map[common.Address][]byte)
	db.code[testContract] = types.AddressToDelegation(common.HexToAddress("0x9999"))
	tracer.OnOpcode(0, byte(STATICCALL), 100000, 100, scopeForCall(testContract), nil, 1, nil)
	if v := tracer.Violation(); v == nil || v.Rule != "OP-041" {
		t.Fatalf("expected delegated target OP-041 violation, got %v", v)
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

func TestFrameValidationTracerRecordsDependencies(t *testing.T) {
	t.Run("sender storage", func(t *testing.T) {
		tracer := newSTOTracer(nil, map[common.Address]bool{testSender: true})
		tracer.OnOpcode(0, byte(SLOAD), 100000, 200, scopeForSload(testSender, testSlot), nil, 1, nil)
		reads := tracer.StorageReads()
		if len(reads) != 1 || reads[0] != testSlot {
			t.Fatalf("storage reads: have %v want [%s]", reads, testSlot)
		}
	})

	t.Run("external code", func(t *testing.T) {
		tracer := newTestTracer()
		tracer.OnOpcode(0, byte(EXTCODEHASH), 100000, 200, scopeForExt(testContract), nil, 1, nil)
		reads := tracer.CodeReads()
		if len(reads) != 1 || reads[0] != testContract {
			t.Fatalf("code reads: have %v want [%s]", reads, testContract)
		}
	})

	t.Run("precompile extcode identity", func(t *testing.T) {
		tracer := newTestTracer()
		tracer.OnOpcode(0, byte(EXTCODEHASH), 100000, 200, scopeForExt(testPrecompile1), nil, 1, nil)
		if reads := tracer.CodeReads(); len(reads) != 1 || reads[0] != testPrecompile1 {
			t.Fatalf("precompile code reads: have %v want [%s]", reads, testPrecompile1)
		}
	})

	t.Run("legacy nonce introspection", func(t *testing.T) {
		tracer := newTestTracer()
		selector := *uint256.NewInt(txParamLegacyNonce)
		tracer.OnOpcode(0, byte(TXPARAM), 100000, 2, &mockScope{stackData: []uint256.Int{selector}}, nil, 1, nil)
		if !tracer.ReadsLegacyNonce() {
			t.Fatal("legacy nonce TXPARAM read was not recorded")
		}
	})
}

func TestFrameValidationRejectsStorageOutsideSender(t *testing.T) {
	for _, addr := range []common.Address{testExternalContract, common.HexToAddress("0x5555555555555555555555555555555555555555")} {
		t.Run(addr.Hex(), func(t *testing.T) {
			tracer := newTestTracer()
			tracer.OnOpcode(0, byte(SLOAD), 100000, 200, scopeForSload(addr, testSlot), nil, 1, nil)
			v := tracer.Violation()
			if v == nil || v.Rule != "STO-010" {
				t.Fatalf("expected STO-010 violation, got %v", v)
			}
		})
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

func newProfileTracer(gasLimit uint64) *FrameValidationTracer {
	state := &mockStateDB{
		codeSize: map[common.Address]int{
			testContract:    100,
			testPrecompile1: 0,
		},
	}
	tracer := NewFrameValidationTracerWithOptions(state, testSender, testSender, []common.Address{testPrecompile1}, FrameValidationTracerOptions{FrameGasLimit: gasLimit})
	tracer.OnEnter(0, byte(STATICCALL), common.Address{}, testSender, nil, gasLimit, nil)
	return tracer
}

func TestFrameValidationWorkProfile(t *testing.T) {
	const gasLimit = uint64(100_000)
	t.Run("pure", func(t *testing.T) {
		tracer := newProfileTracer(gasLimit)
		tracer.OnOpcode(0, byte(ADD), gasLimit, 3, emptyScope(), nil, 1, nil)
		profile := tracer.WorkProfile()
		if profile.HasMutableRead || profile.StateDependentGasLimit != 0 {
			t.Fatalf("pure profile: %+v", profile)
		}
	})
	t.Run("prior frame mutable", func(t *testing.T) {
		state := &mockStateDB{}
		tracer := NewFrameValidationTracerWithOptions(state, testSender, testSender, nil, FrameValidationTracerOptions{
			FrameGasLimit:     gasLimit,
			PriorFrameMutable: true,
		})
		tracer.OnEnter(0, byte(STATICCALL), common.Address{}, testSender, nil, gasLimit, nil)
		profile := tracer.WorkProfile()
		if profile.FirstMutableReadKind != ValidationMutableReadPriorFrame || profile.StateDependentGasLimit != gasLimit {
			t.Fatalf("prior-frame profile: %+v", profile)
		}
	})
	t.Run("blob max cost", func(t *testing.T) {
		state := &mockStateDB{}
		tracer := NewFrameValidationTracerWithOptions(state, testSender, testSender, nil, FrameValidationTracerOptions{
			FrameGasLimit:             gasLimit,
			BlobBaseFeeAffectsMaxCost: true,
		})
		tracer.OnEnter(0, byte(STATICCALL), common.Address{}, testSender, nil, gasLimit, nil)
		selector := *uint256.NewInt(txParamMaxCost)
		tracer.OnOpcode(3, byte(TXPARAM), 99_000, 2, &mockScope{stackData: []uint256.Int{selector}}, nil, 1, nil)
		profile := tracer.WorkProfile()
		if !tracer.ReadsBlobBaseFee() || profile.FirstMutableReadKind != ValidationMutableReadEnvironment {
			t.Fatalf("blob max-cost profile: %+v", profile)
		}
	})
	t.Run("precompile extcode", func(t *testing.T) {
		tracer := newProfileTracer(gasLimit)
		tracer.OnOpcode(4, byte(EXTCODEHASH), 99_000, 100, scopeForExt(testPrecompile1), nil, 1, nil)
		profile := tracer.WorkProfile()
		if profile.FirstMutableReadKind != ValidationMutableReadCode || profile.StateDependentGasLimit != 99_000 {
			t.Fatalf("precompile extcode profile: %+v", profile)
		}
	})
	t.Run("first sload", func(t *testing.T) {
		tracer := newProfileTracer(gasLimit)
		tracer.OnOpcode(7, byte(SLOAD), 99_000, 2_100, scopeForSload(testSender, testSlot), nil, 1, nil)
		profile := tracer.WorkProfile()
		if !profile.HasMutableRead || profile.FirstMutableReadKind != ValidationMutableReadStorage || profile.FirstMutableReadPC != 7 || profile.FirstMutableReadDepth != 1 {
			t.Fatalf("first mutable read: %+v", profile)
		}
		if profile.StateDependentGasLimit != 99_000 || profile.GasUsedBeforeFirstMutable != 1_000 {
			t.Fatalf("remaining-gas bound: %+v", profile)
		}
		tracer.OnOpcode(8, byte(SLOAD), 80_000, 100, scopeForSload(testSender, common.HexToHash("0x02")), nil, 1, nil)
		if got := tracer.WorkProfile(); got != profile {
			t.Fatalf("second mutable read overwrote profile: have %+v want %+v", got, profile)
		}
	})
	t.Run("late sload", func(t *testing.T) {
		tracer := newProfileTracer(gasLimit)
		tracer.OnOpcode(90_000, byte(SLOAD), 10_000, 2_100, scopeForSload(testSender, testSlot), nil, 1, nil)
		profile := tracer.WorkProfile()
		if profile.StateDependentGasLimit != 10_000 || profile.GasUsedBeforeFirstMutable != 90_000 {
			t.Fatalf("late remaining-gas bound: %+v", profile)
		}
	})
	t.Run("suffix branch does not change bound", func(t *testing.T) {
		cheap := newProfileTracer(gasLimit)
		expensive := newProfileTracer(gasLimit)
		for _, tracer := range []*FrameValidationTracer{cheap, expensive} {
			tracer.OnOpcode(1, byte(SLOAD), 80_000, 2_100, scopeForSload(testSender, testSlot), nil, 1, nil)
		}
		cheap.OnOpcode(2, byte(STOP), 77_900, 0, emptyScope(), nil, 1, nil)
		expensive.OnOpcode(2, byte(ADD), 77_900, 3, emptyScope(), nil, 1, nil)
		if cheap.WorkProfile() != expensive.WorkProfile() {
			t.Fatalf("post-watershed branch changed bound: cheap=%+v expensive=%+v", cheap.WorkProfile(), expensive.WorkProfile())
		}
	})
	t.Run("legacy nonce only", func(t *testing.T) {
		tracer := newProfileTracer(gasLimit)
		other := *uint256.NewInt(txParamLegacyNonce + 1)
		tracer.OnOpcode(0, byte(TXPARAM), gasLimit, 2, &mockScope{stackData: []uint256.Int{other}}, nil, 1, nil)
		if tracer.WorkProfile().HasMutableRead {
			t.Fatal("immutable TXPARAM selector was classified as mutable")
		}
		legacy := *uint256.NewInt(txParamLegacyNonce)
		tracer.OnOpcode(1, byte(TXPARAM), gasLimit-2, 2, &mockScope{stackData: []uint256.Int{legacy}}, nil, 1, nil)
		if got := tracer.WorkProfile().FirstMutableReadKind; got != ValidationMutableReadLegacyNonce {
			t.Fatalf("mutable kind: have %d want legacy nonce", got)
		}
	})
	t.Run("precompile and external code", func(t *testing.T) {
		tracer := newProfileTracer(gasLimit)
		tracer.OnOpcode(0, byte(STATICCALL), gasLimit, 10_000, scopeForCall(testPrecompile1), nil, 1, nil)
		tracer.OnEnter(1, byte(STATICCALL), testSender, testPrecompile1, nil, 9_000, nil)
		tracer.OnExit(1, nil, 0, nil, false)
		if tracer.WorkProfile().HasMutableRead {
			t.Fatal("precompile call was classified as a mutable code read")
		}
		tracer.OnOpcode(1, byte(EXTCODEHASH), 89_000, 100, scopeForExt(testContract), nil, 1, nil)
		if got := tracer.WorkProfile().FirstMutableReadKind; got != ValidationMutableReadCode {
			t.Fatalf("mutable kind: have %d want code", got)
		}
	})
	t.Run("fail closed", func(t *testing.T) {
		tracer := newProfileTracer(gasLimit)
		tracer.OnOpcode(0, byte(STATICCALL), 10, 11, scopeForCall(testPrecompile1), nil, 1, nil)
		profile := tracer.WorkProfile()
		if !profile.GasAccountingConservative || profile.StateDependentGasLimit != gasLimit {
			t.Fatalf("underflow profile: %+v", profile)
		}
	})
	t.Run("depth mismatch fails closed", func(t *testing.T) {
		tracer := newProfileTracer(gasLimit)
		tracer.OnEnter(2, byte(STATICCALL), testSender, testSender, nil, 50_000, nil)
		profile := tracer.WorkProfile()
		if !profile.GasAccountingConservative || profile.StateDependentGasLimit != gasLimit {
			t.Fatalf("depth-mismatch profile: %+v", profile)
		}
	})
	t.Run("unclosed child fails closed", func(t *testing.T) {
		tracer := newProfileTracer(gasLimit)
		tracer.OnOpcode(0, byte(STATICCALL), 90_000, 50_000, scopeForCall(testPrecompile1), nil, 1, nil)
		tracer.OnExit(0, nil, 50_000, nil, false)
		profile := tracer.WorkProfile()
		if !profile.GasAccountingConservative || profile.StateDependentGasLimit != gasLimit {
			t.Fatalf("unclosed-child profile: %+v", profile)
		}
	})
}

func TestFrameValidationEnvironmentAndDeploymentProfiles(t *testing.T) {
	const gasLimit = uint64(100_000)
	state := &mockStateDB{
		codeSize: map[common.Address]int{params.FrameExpiryVerifierAddress: len(params.FrameExpiryVerifierCode)},
		code:     map[common.Address][]byte{params.FrameExpiryVerifierAddress: params.FrameExpiryVerifierCode},
	}
	expiry := NewFrameValidationTracerWithOptions(state, testSender, params.FrameExpiryVerifierAddress, nil, FrameValidationTracerOptions{FrameGasLimit: gasLimit})
	expiry.OnEnter(0, byte(STATICCALL), common.Address{}, params.FrameExpiryVerifierAddress, nil, gasLimit, nil)
	expiry.OnOpcode(3, byte(TIMESTAMP), 99_000, 2, emptyScope(), nil, 1, nil)
	if profile := expiry.WorkProfile(); profile.FirstMutableReadKind != ValidationMutableReadEnvironment || profile.StateDependentGasLimit != 99_000 {
		t.Fatalf("expiry profile: %+v", profile)
	}

	deploy := NewFrameValidationTracerWithOptions(state, testSender, testSender, nil, FrameValidationTracerOptions{Deployment: true, FrameGasLimit: gasLimit})
	deploy.OnEnter(0, byte(CALL), common.Address{}, testSender, nil, gasLimit, nil)
	if profile := deploy.WorkProfile(); profile.FirstMutableReadKind != ValidationMutableReadDeployment || profile.StateDependentGasLimit != gasLimit {
		t.Fatalf("deployment profile: %+v", profile)
	}
}

func TestFrameValidationAcceptsPrechargedRootGas(t *testing.T) {
	const (
		frameGas = uint64(100_000)
		rootGas  = frameGas - params.WarmAccountAccessAmsterdam
	)
	tracer := NewFrameValidationTracerWithOptions(newTestTracer().stateDB, testSender, testSender, nil, FrameValidationTracerOptions{
		FrameGasLimit:   frameGas,
		RootGasLimit:    rootGas,
		RootGasLimitSet: true,
	})
	tracer.OnEnter(0, byte(STATICCALL), common.Address{}, testSender, nil, rootGas, nil)
	tracer.OnOpcode(0, byte(SLOAD), rootGas, 2_100, scopeForSload(testSender, testSlot), nil, 1, nil)
	profile := tracer.WorkProfile()
	if profile.GasAccountingConservative || profile.StateDependentGasLimit != rootGas {
		t.Fatalf("precharged root profile: %+v", profile)
	}
	if profile.GasUsedBeforeFirstMutable != params.WarmAccountAccessAmsterdam {
		t.Fatalf("gas before mutable read = %d, want %d", profile.GasUsedBeforeFirstMutable, params.WarmAccountAccessAmsterdam)
	}
}

func TestFrameValidationProfileOnlyDoesNotEnforceRules(t *testing.T) {
	state := &mockStateDB{codeSize: map[common.Address]int{testContract: 100}}
	tracer := NewFrameValidationTracerWithOptions(state, testSender, testContract, nil, FrameValidationTracerOptions{
		ProfileOnly:   true,
		FrameGasLimit: 100_000,
	})
	tracer.OnEnter(0, byte(STATICCALL), common.Address{}, testContract, nil, 100_000, nil)
	tracer.OnOpcode(0, byte(SLOAD), 99_000, 2_100, scopeForSload(testContract, testSlot), nil, 1, nil)
	tracer.OnOpcode(1, byte(BALANCE), 90_000, 100, emptyScope(), nil, 1, nil)
	if violation := tracer.Violation(); violation != nil {
		t.Fatalf("profile-only tracer changed validation result: %v", violation)
	}
	if got := tracer.WorkProfile().FirstMutableReadKind; got != ValidationMutableReadStorage {
		t.Fatalf("profile-only mutable kind: have %d want storage", got)
	}
}

func TestFrameValidationNestedCallUsesFrameWideGas(t *testing.T) {
	const gasLimit = uint64(100_000)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(testSender)
	// The top-level invocation has empty calldata and STATICCALLs itself with a
	// one-byte input. The child branch then executes SLOAD. Calling the same
	// validation program avoids introducing an external-code watershed first.
	code := []byte{
		byte(CALLDATASIZE), byte(PUSH1), 0x2b, byte(JUMPI),
		byte(PUSH1), 0x01, byte(PUSH1), 0x00, byte(MSTORE),
		byte(PUSH1), 0x00, byte(PUSH1), 0x00, byte(PUSH1), 0x01, byte(PUSH1), 0x1f,
		byte(PUSH20),
	}
	code = append(code, testSender.Bytes()...)
	code = append(code,
		byte(PUSH2), 0xff, 0xff, byte(STATICCALL), byte(STOP),
		byte(JUMPDEST), byte(PUSH1), 0x00, byte(SLOAD), byte(STOP),
	)
	statedb.SetCode(testSender, code, tracing.CodeChangeUnspecified)
	tracer := NewFrameValidationTracerWithOptions(statedb, testSender, testSender, ActivePrecompiles(params.TestRules), FrameValidationTracerOptions{FrameGasLimit: gasLimit})
	evm := NewEVM(BlockContext{BlockNumber: new(big.Int), Time: 1}, statedb, params.TestChainConfig, Config{Tracer: tracer.Hooks()})
	_, _, err := evm.StaticCall(common.Address{}, testSender, nil, NewGasBudget(gasLimit, 0))
	if err != nil {
		t.Fatalf("nested validation call failed: %v", err)
	}
	if violation := tracer.Violation(); violation != nil {
		t.Fatalf("nested validation trace failed: %v", violation)
	}
	profile := tracer.WorkProfile()
	if profile.FirstMutableReadKind != ValidationMutableReadStorage || profile.FirstMutableReadDepth != 2 {
		t.Fatalf("nested first mutable read: %+v", profile)
	}
	if profile.GasAccountingConservative || profile.StateDependentGasLimit == 0 || profile.StateDependentGasLimit > gasLimit {
		t.Fatalf("nested frame-wide gas: %+v", profile)
	}
	if profile.StateDependentGasLimit <= 60_000 {
		t.Fatalf("nested bound appears to contain child-local gas only: %+v", profile)
	}
}

func TestFrameValidationTwoLevelNestedCallsUseFrameWideGas(t *testing.T) {
	const gasLimit = uint64(200_000)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.CreateAccount(testSender)

	// Calldata sizes select root -> STATICCALL -> DELEGATECALL -> SLOAD. Both
	// calls target the already fingerprinted sender, so code identity does not
	// become the first mutable read. PUSH2 asks for more gas than EIP-150 may
	// forward at the second level, exercising the interpreter's dynamic cost.
	code := []byte{
		byte(CALLDATASIZE), byte(PUSH1), 2, byte(EQ), byte(PUSH2), 0, 0, byte(JUMPI),
		byte(CALLDATASIZE), byte(PUSH1), 1, byte(EQ), byte(PUSH2), 0, 0, byte(JUMPI),
	}
	sloadPatch, delegatePatch := 5, 13
	code = append(code, byte(PUSH1), 1, byte(PUSH1), 0, byte(MSTORE))
	code = append(code, byte(PUSH1), 0, byte(PUSH1), 0, byte(PUSH1), 1, byte(PUSH1), 31, byte(PUSH20))
	code = append(code, testSender.Bytes()...)
	code = append(code, byte(PUSH2), 0xff, 0xff, byte(STATICCALL), byte(STOP))
	delegatePC := len(code)
	code = append(code, byte(JUMPDEST), byte(PUSH1), 1, byte(PUSH1), 0, byte(MSTORE))
	code = append(code, byte(PUSH1), 0, byte(PUSH1), 0, byte(PUSH1), 2, byte(PUSH1), 30, byte(PUSH20))
	code = append(code, testSender.Bytes()...)
	code = append(code, byte(PUSH2), 0xff, 0xff, byte(DELEGATECALL), byte(STOP))
	sloadPC := len(code)
	code = append(code, byte(JUMPDEST), byte(PUSH1), 0, byte(SLOAD), byte(STOP))
	code[sloadPatch], code[sloadPatch+1] = byte(sloadPC>>8), byte(sloadPC)
	code[delegatePatch], code[delegatePatch+1] = byte(delegatePC>>8), byte(delegatePC)

	statedb.SetCode(testSender, code, tracing.CodeChangeUnspecified)
	tracer := NewFrameValidationTracerWithOptions(statedb, testSender, testSender, ActivePrecompiles(params.TestRules), FrameValidationTracerOptions{FrameGasLimit: gasLimit})
	evm := NewEVM(BlockContext{BlockNumber: new(big.Int), Time: 1}, statedb, params.TestChainConfig, Config{Tracer: tracer.Hooks()})
	if _, _, err := evm.StaticCall(common.Address{}, testSender, nil, NewGasBudget(gasLimit, 0)); err != nil {
		t.Fatalf("nested validation call failed: %v", err)
	}
	if violation := tracer.Violation(); violation != nil {
		t.Fatalf("nested validation trace failed: %v", violation)
	}
	profile := tracer.WorkProfile()
	if profile.FirstMutableReadKind != ValidationMutableReadStorage || profile.FirstMutableReadDepth != 3 {
		t.Fatalf("two-level first mutable read: %+v", profile)
	}
	if profile.GasAccountingConservative || profile.StateDependentGasLimit <= 150_000 || profile.StateDependentGasLimit > gasLimit {
		t.Fatalf("two-level frame-wide gas: %+v", profile)
	}
}
