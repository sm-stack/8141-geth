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

package core

import (
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// Bytecode constants for test contracts.
var (
	// APPROVE(0x3): approve both execution and payment.
	// PUSH1 0x03, PUSH1 0x00, PUSH1 0x00, APPROVE(0xaa)
	approveBothCode = []byte{0x60, 0x03, 0x60, 0x00, 0x60, 0x00, 0xaa}

	// APPROVE(0x2): approve execution only.
	approveExecCode = []byte{0x60, 0x02, 0x60, 0x00, 0x60, 0x00, 0xaa}

	// APPROVE(0x1): approve payment only.
	approvePayCode = []byte{0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0xaa}

	// Simple RETURN: PUSH1 0x00, PUSH1 0x00, RETURN(0xf3)
	returnCode = []byte{0x60, 0x00, 0x60, 0x00, 0xf3}

	// Simple REVERT: PUSH1 0x00, PUSH1 0x00, REVERT(0xfd)
	revertCode = []byte{0x60, 0x00, 0x60, 0x00, 0xfd}

	// Store CALLVALUE at storage slot 0, then RETURN.
	callValueStoreCode = []byte{0x34, 0x60, 0x00, 0x55, 0x60, 0x00, 0x60, 0x00, 0xf3}

	// Store 1 at storage slot 0, then RETURN.
	storeOneCode = []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0x60, 0x00, 0x60, 0x00, 0xf3}

	// Store 2 at storage slot 1, then RETURN.
	storeTwoCode = []byte{0x60, 0x02, 0x60, 0x01, 0x55, 0x60, 0x00, 0x60, 0x00, 0xf3}
)

// newFrameTestEnv creates a test EVM and state for frame transaction tests.
func newFrameTestEnv() (*vm.EVM, *state.StateDB, *params.ChainConfig) {
	config := *params.MergedTestChainConfig
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())

	random := common.Hash{0x01}
	blockCtx := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(n uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.HexToAddress("0xc014"),
		BlockNumber: big.NewInt(1),
		Time:        0,
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(params.InitialBaseFee),
		BlobBaseFee: big.NewInt(1),
		Random:      &random,
		GasLimit:    30_000_000,
	}
	evm := vm.NewEVM(blockCtx, statedb, &config, vm.Config{})
	return evm, statedb, &config
}

// applyFrameTx creates and applies a frame transaction, returning the result.
func applyFrameTx(evm *vm.EVM, config *params.ChainConfig, msg *Message) (*ExecutionResult, error) {
	gp := NewGasPool(30_000_000)
	evm.SetTxContext(NewEVMTxContext(msg))
	return newStateTransition(evm, msg, gp).execute()
}

// makeFrameMsg creates a Message from a FrameTx for testing.
func makeFrameMsg(ftx *types.FrameTx, config *params.ChainConfig, baseFee *big.Int) *Message {
	tx := types.NewTx(ftx)
	signer := types.LatestSigner(config)
	msg, err := TransactionToMessage(tx, signer, baseFee)
	if err != nil {
		panic(err)
	}
	return msg
}

func expiryFrameData(deadline uint64) []byte {
	data := make([]byte, params.FrameExpiryDataLength)
	binary.BigEndian.PutUint64(data, deadline)
	return data
}

type fixedSlotProvider uint64

func (p fixedSlotProvider) CurrentSlot() uint64 { return uint64(p) }

func TestFrameTxRecentRootReferenceValidation(t *testing.T) {
	const currentSlot = uint64(9000)
	tests := []struct {
		name      string
		slot      uint64
		changeRef func(*types.RecentRootRef)
		valid     bool
	}{
		{name: "previous slot", slot: currentSlot - 1, valid: true},
		{name: "oldest usable slot", slot: currentSlot - 8191, valid: true},
		{name: "same slot", slot: currentSlot},
		{name: "expired slot", slot: currentSlot - 8192},
		{name: "wrong root", slot: currentSlot - 1, changeRef: func(ref *types.RecentRootRef) { ref.Root[0] ^= 0xff }},
		{name: "wrong source", slot: currentSlot - 1, changeRef: func(ref *types.RecentRootRef) { ref.SourceID[0] ^= 0xff }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evm, statedb, config := newFrameTestEnv()
			evm.Context.SlotProvider = fixedSlotProvider(currentSlot)
			sender := common.HexToAddress("0x1111")
			statedb.CreateAccount(sender)
			statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
			statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
			storedRef := types.RecentRootRef{SourceID: common.HexToHash("0x1234"), Slot: tt.slot, Root: common.HexToHash("0x5678")}
			key := types.RecentRootStorageKey(storedRef.SourceID, storedRef.Slot)
			statedb.SetState(params.RecentRootAddress, key, types.RecentRootEntryHash(storedRef.SourceID, storedRef.Slot, storedRef.Root))
			txRef := storedRef
			if tt.changeRef != nil {
				tt.changeRef(&txRef)
			}
			ftx := &types.FrameTx{
				ChainID: uint256.NewInt(config.ChainID.Uint64()), NonceKeys: []*uint256.Int{uint256.NewInt(0)}, Sender: sender,
				Frames: []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}, RecentRootRefs: []types.RecentRootRef{txRef},
				GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(uint64(params.InitialBaseFee)), BlobFeeCap: new(uint256.Int),
			}
			_, err := applyFrameTx(evm, config, makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee)))
			if tt.valid && err != nil {
				t.Fatalf("valid reference rejected: %v", err)
			}
			if tt.valid {
				addressWarm, slotWarm := statedb.SlotInAccessList(params.RecentRootAddress, types.RecentRootStorageKey(txRef.SourceID, txRef.Slot))
				if !addressWarm || !slotWarm {
					t.Fatal("validated recent root reference was not warmed")
				}
			}
			if !tt.valid && err == nil {
				t.Fatal("invalid reference accepted")
			}
		})
	}
}

// TestFrameTxSimple tests the simplest frame transaction: VERIFY(APPROVE 0x3) + SENDER(RETURN).
// This replicates Example 1 from EIP-8141.
func TestFrameTxSimple(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	target := common.HexToAddress("0x2222")

	// Setup: sender has APPROVE(0x3) code and plenty of ETH.
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Target has simple RETURN code.
	statedb.CreateAccount(target)
	statedb.SetCode(target, returnCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}
	if result.UsedGas == 0 {
		t.Fatal("expected non-zero gas usage")
	}

	// Verify nonce was incremented (payer approval increments nonce).
	if got := statedb.GetNonce(sender); got != 1 {
		t.Fatalf("sender nonce: got %d, want 1", got)
	}
}

func TestFrameTxSenderValueTransferAndCallValue(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	target := common.HexToAddress("0x2222")
	value := uint256.NewInt(7)

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	statedb.CreateAccount(target)
	statedb.SetCode(target, callValueStoreCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 100000, Value: value, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}
	if got := statedb.GetBalance(target); got.Cmp(value) != 0 {
		t.Fatalf("target balance: got %v, want %v", got, value)
	}
	wantCallValue := common.Hash{}
	wantCallValue[31] = byte(value.Uint64())
	if got := statedb.GetState(target, common.Hash{}); got != wantCallValue {
		t.Fatalf("CALLVALUE storage: got %v, want %v", got, wantCallValue)
	}
}

func TestFrameTxSenderValueTransferToEOATarget(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	target := common.HexToAddress("0x2222")
	value := uint256.NewInt(7)

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 100000, Value: value, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}
	if len(result.frameResults) != 2 || result.frameResults[1] == 0 {
		t.Fatalf("frame results: got %v, want successful EOA target SENDER frame", result.frameResults)
	}
	if got := statedb.GetBalance(target); got.Cmp(value) != 0 {
		t.Fatalf("target balance: got %v, want %v", got, value)
	}
}

func TestFrameTxSenderValueInsufficientBalanceRevertsFrame(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	target := common.HexToAddress("0x2222")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)

	statedb.CreateAccount(target)
	statedb.SetCode(target, callValueStoreCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 100000, Value: uint256.NewInt(1), Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	maxCostU256 := new(uint256.Int).SetUint64(msg.GasLimit)
	_, overflow := maxCostU256.MulOverflow(maxCostU256, msg.GasFeeCap)
	if overflow {
		t.Fatal("max cost overflow")
	}
	statedb.SetBalance(sender, maxCostU256, tracing.BalanceChangeUnspecified)

	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}
	if len(result.frameResults) != 2 || result.frameResults[0] == 0 || result.frameResults[1] != 0 {
		t.Fatalf("frame results: got %v, want approve then reverted SENDER frame", result.frameResults)
	}
	if got := statedb.GetBalance(target); !got.IsZero() {
		t.Fatalf("target balance: got %v, want zero", got)
	}
	if got := statedb.GetState(target, common.Hash{}); got != (common.Hash{}) {
		t.Fatalf("target storage changed despite reverted frame: %v", got)
	}
}

func TestFrameTxExpiryVerifierValidDeadline(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()
	evm.Context.Time = 100

	sender := common.HexToAddress("0x1111")
	expiry := params.FrameExpiryVerifierAddress

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	statedb.CreateAccount(expiry)
	statedb.SetCode(expiry, params.FrameExpiryVerifierCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Target: &expiry, GasLimit: 50000, Data: expiryFrameData(100)},
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}
	if got, want := result.frameResults, []uint8{types.FrameReceiptStatusSuccessful, types.FrameReceiptStatusSuccessful}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("frame results: got %v want %v", got, want)
	}
}

func TestFrameTxExpiryVerifierExpiredDeadlineFails(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()
	evm.Context.Time = 100

	sender := common.HexToAddress("0x1111")
	expiry := params.FrameExpiryVerifierAddress

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	statedb.CreateAccount(expiry)
	statedb.SetCode(expiry, params.FrameExpiryVerifierCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Target: &expiry, GasLimit: 50000, Data: expiryFrameData(99)},
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	if _, err := applyFrameTx(evm, config, msg); err == nil {
		t.Fatal("expected expired expiry verifier frame to fail")
	}
}

func TestFrameTxKeyedNonceFirstUseGas(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()
	sender := common.HexToAddress("0x1111")
	key := uint256.NewInt(7)
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	run := func(seq uint64) *ExecutionResult {
		ftx := &types.FrameTx{
			ChainID: uint256.NewInt(config.ChainID.Uint64()), NonceKeys: []*uint256.Int{new(uint256.Int).Set(key)}, NonceSeq: seq,
			Sender: sender, Frames: []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}},
			GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(uint64(params.InitialBaseFee)), BlobFeeCap: new(uint256.Int),
		}
		result, err := applyFrameTx(evm, config, makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee)))
		if err != nil || result.Failed() {
			t.Fatalf("sequence %d failed: result=%v err=%v", seq, result, err)
		}
		return result
	}
	first := run(0)
	second := run(1)
	if got, want := first.frameGasUsed[0]-second.frameGasUsed[0], params.KeyedNonceFirstUseGas; got != want {
		t.Fatalf("first-use gas delta = %d, want %d", got, want)
	}
	if got := statedb.GetState(params.NonceManagerAddress, types.NonceManagerSlot(sender, key)).Big().Uint64(); got != 2 {
		t.Fatalf("keyed nonce sequence = %d, want 2", got)
	}
	if got := statedb.GetNonce(sender); got != 0 {
		t.Fatalf("keyed nonce changed account nonce to %d", got)
	}
}

func TestNonceManagerRuntimeRejectsDirectCalls(t *testing.T) {
	evm, statedb, _ := newFrameTestEnv()
	caller := common.HexToAddress("0x1111")
	statedb.CreateAccount(caller)
	statedb.CreateAccount(params.NonceManagerAddress)
	statedb.SetCode(params.NonceManagerAddress, params.NonceManagerCode, tracing.CodeChangeUnspecified)
	if _, _, err := evm.Call(caller, params.NonceManagerAddress, nil, vm.NewGasBudget(50_000, 0), new(uint256.Int)); !errors.Is(err, vm.ErrExecutionReverted) {
		t.Fatalf("nonce manager direct call error = %v, want revert", err)
	}
}

func TestFrameTxAtomicBatchFailureRollsBackAndSkips(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	firstTarget := common.HexToAddress("0x2222")
	failingTarget := common.HexToAddress("0x3333")
	skippedTarget := common.HexToAddress("0x4444")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	statedb.CreateAccount(firstTarget)
	statedb.SetCode(firstTarget, storeOneCode, tracing.CodeChangeUnspecified)
	statedb.CreateAccount(failingTarget)
	statedb.SetCode(failingTarget, revertCode, tracing.CodeChangeUnspecified)
	statedb.CreateAccount(skippedTarget)
	statedb.SetCode(skippedTarget, storeTwoCode, tracing.CodeChangeUnspecified)

	tx := newFrameTx(config, 0, sender, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
		{Mode: types.FrameModeSender, Flags: types.FrameFlagAtomicBatch, Target: &firstTarget, GasLimit: 100000, Data: nil},
		{Mode: types.FrameModeSender, Flags: types.FrameFlagAtomicBatch, Target: &failingTarget, GasLimit: 50000, Data: nil},
		{Mode: types.FrameModeSender, Target: &skippedTarget, GasLimit: 100000, Data: nil},
	})
	receipt := applyFrameTxAndReceipt(t, evm, statedb, config, tx)

	assertFrameStatuses(t, receipt, []uint8{1, 1, 0, types.FrameReceiptStatusSkipped})
	if got := receipt.FrameReceipts[3].GasUsed; got != 0 {
		t.Fatalf("skipped frame gas used: got %d want 0", got)
	}
	if got := statedb.GetState(firstTarget, common.Hash{}); got != (common.Hash{}) {
		t.Fatalf("first atomic frame storage was not rolled back: got %v", got)
	}
	if got := statedb.GetState(skippedTarget, common.BytesToHash([]byte{0x01})); got != (common.Hash{}) {
		t.Fatalf("skipped frame executed unexpectedly: storage[1] = %v", got)
	}
}

func TestFrameTxAtomicBatchPreservesApprovalEffects(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	sponsor := common.HexToAddress("0x2222")
	failingTarget := common.HexToAddress("0x3333")
	skippedTarget := common.HexToAddress("0x5555")
	successTarget := common.HexToAddress("0x4444")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e15), tracing.BalanceChangeUnspecified)

	statedb.CreateAccount(sponsor)
	statedb.SetCode(sponsor, approvePayCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sponsor, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	statedb.CreateAccount(failingTarget)
	statedb.SetCode(failingTarget, revertCode, tracing.CodeChangeUnspecified)
	statedb.CreateAccount(skippedTarget)
	statedb.SetCode(skippedTarget, storeOneCode, tracing.CodeChangeUnspecified)
	statedb.CreateAccount(successTarget)
	statedb.SetCode(successTarget, storeTwoCode, tracing.CodeChangeUnspecified)

	sponsorBalBefore := statedb.GetBalance(sponsor).Clone()
	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(1), uint256.NewInt(2)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: nil},
			{Mode: types.FrameModeVerify, Flags: 1, Target: &sponsor, GasLimit: 50000, Data: nil},
			{Mode: types.FrameModeSender, Flags: types.FrameFlagAtomicBatch, Target: &failingTarget, GasLimit: 50000, Data: nil},
			{Mode: types.FrameModeSender, Target: &skippedTarget, GasLimit: 50000, Data: nil},
			{Mode: types.FrameModeSender, Target: &successTarget, GasLimit: 100000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}
	wantResults := []uint8{
		types.FrameReceiptStatusSuccessful,
		types.FrameReceiptStatusSuccessful,
		types.FrameReceiptStatusFailed,
		types.FrameReceiptStatusSkipped,
		types.FrameReceiptStatusSuccessful,
	}
	if got := result.frameResults; len(got) != len(wantResults) {
		t.Fatalf("frame results length: got %d want %d (%v)", len(got), len(wantResults), got)
	} else {
		for i := range got {
			if got[i] != wantResults[i] {
				t.Fatalf("frame results: got %v want %v", got, wantResults)
			}
		}
	}
	if got := statedb.GetNonce(sender); got != 0 {
		t.Fatalf("sender account nonce: got %d, want 0", got)
	}
	for _, key := range ftx.NonceKeys {
		if got := statedb.GetState(params.NonceManagerAddress, types.NonceManagerSlot(sender, key)).Big().Uint64(); got != 1 {
			t.Fatalf("keyed nonce %d after atomic rollback: got %d, want 1", key.Uint64(), got)
		}
	}
	if sponsorBalAfter := statedb.GetBalance(sponsor); sponsorBalAfter.Cmp(sponsorBalBefore) >= 0 {
		t.Fatalf("sponsor balance should have paid gas: before=%s after=%s", sponsorBalBefore, sponsorBalAfter)
	}
	if got, want := statedb.GetState(successTarget, common.BytesToHash([]byte{0x01})), common.BytesToHash([]byte{0x02}); got != want {
		t.Fatalf("post-batch SENDER frame storage: got %v, want %v", got, want)
	}
}

// TestFrameTxSenderNotApproved tests that SENDER mode before sender approval fails.
func TestFrameTxSenderNotApproved(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	target := common.HexToAddress("0x2222")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	statedb.CreateAccount(target)
	statedb.SetCode(target, returnCode, tracing.CodeChangeUnspecified)

	// SENDER mode is first, before any VERIFY — should fail.
	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 50000, Data: nil},
			{Mode: types.FrameModeVerify, Target: nil, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for SENDER mode before sender approved")
	}
	t.Logf("got expected error: %v", err)
}

// TestFrameTxNoPayerApproval tests that missing payer approval fails.
func TestFrameTxNoPayerApproval(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	target := common.HexToAddress("0x2222")

	// Sender code approves execution only (0x2), not payment.
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	statedb.CreateAccount(target)
	statedb.SetCode(target, returnCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: nil},
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for missing payer approval")
	}
	t.Logf("got expected error: %v", err)
}

// TestFrameTxVerifyFailure tests that a VERIFY frame that doesn't APPROVE causes tx failure.
func TestFrameTxVerifyFailure(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")

	// Sender code REVERTs instead of APPROVEing.
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, revertCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Target: nil, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for VERIFY frame that did not APPROVE")
	}
	t.Logf("got expected error: %v", err)
}

func TestFrameTxVerifyReturnWithoutApproveFails(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, returnCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for VERIFY frame that returned without APPROVE")
	}
}

// TestFrameTxSponsoredTransaction tests a sponsored transaction where sender and payer are different.
// Frame 0: VERIFY on sender → APPROVE(0x2) (execution)
// Frame 1: VERIFY on sponsor → APPROVE(0x1) (payment)
// Frame 2: SENDER calls target
func TestFrameTxSponsoredTransaction(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	sponsor := common.HexToAddress("0x3333")
	target := common.HexToAddress("0x2222")

	// Sender approves execution only.
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e15), tracing.BalanceChangeUnspecified) // little ETH

	// Sponsor approves payment only and has plenty of ETH.
	statedb.CreateAccount(sponsor)
	statedb.SetCode(sponsor, approvePayCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sponsor, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Target just returns.
	statedb.CreateAccount(target)
	statedb.SetCode(target, returnCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: nil},
			{Mode: types.FrameModeVerify, Flags: 1, Target: &sponsor, GasLimit: 50000, Data: nil},
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	sponsorBalBefore := statedb.GetBalance(sponsor).Clone()

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("sponsored tx failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}

	// Sponsor should have paid gas (balance decreased).
	sponsorBalAfter := statedb.GetBalance(sponsor)
	if sponsorBalAfter.Cmp(sponsorBalBefore) >= 0 {
		t.Fatalf("sponsor balance should have decreased: before=%v, after=%v", sponsorBalBefore, sponsorBalAfter)
	}

	// Sender nonce should be incremented.
	if got := statedb.GetNonce(sender); got != 1 {
		t.Fatalf("sender nonce: got %d, want 1", got)
	}

	t.Logf("gas used: %d, sponsor paid: %v", result.UsedGas,
		new(uint256.Int).Sub(sponsorBalBefore, sponsorBalAfter))
}

// TestFrameTxGasAccounting verifies that gas usage is correctly tracked per frame.
func TestFrameTxGasAccounting(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 100000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("frame tx failed: %v", err)
	}

	// Gas used should be > 0 and <= total gas limit.
	if result.UsedGas == 0 {
		t.Fatal("expected non-zero gas usage")
	}
	if result.UsedGas > msg.GasLimit {
		t.Fatalf("gas used %d exceeds gas limit %d", result.UsedGas, msg.GasLimit)
	}

	// The actual gas used by the APPROVE bytecode is small (~30 gas for 3 PUSH1 + APPROVE).
	// The intrinsic metadata gas (base + per-frame + calldata) is the bulk.
	// Total = intrinsicGas + frameGasUsed
	t.Logf("total gas used: %d, gas limit: %d", result.UsedGas, msg.GasLimit)
}

// TestFrameTxDefaultMode tests DEFAULT mode frames (caller = ENTRY_POINT).
func TestFrameTxDefaultMode(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	deployer := common.HexToAddress("0x4444")

	// Sender code approves both.
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Deployer code just returns.
	statedb.CreateAccount(deployer)
	statedb.SetCode(deployer, returnCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeDefault, Target: &deployer, GasLimit: 50000, Data: nil},
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("frame tx with DEFAULT mode failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution failed: %v", result.Err)
	}
}

// TestFrameTxPayerInsufficientBalance tests that payer with insufficient balance causes tx failure.
func TestFrameTxPayerInsufficientBalance(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1), tracing.BalanceChangeUnspecified) // 1 wei — not enough

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for insufficient payer balance")
	}
	t.Logf("got expected error: %v", err)
}

func TestFrameTxApproveScopeMustBeAllowedByFrameFlags(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error: APPROVE(0x3) must not be accepted when frame.flags only allow execution")
	}
}

func TestFrameTxApproveScopeZeroRejected(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	approveZeroCode := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xaa}

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveZeroCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error: APPROVE(0x0) must be rejected")
	}
}

// TestFrameTxReApproveExecution tests that re-approving execution is rejected.
// Per spec: "If sender_approved is already set, revert the frame."
// Two VERIFY(sender) frames both APPROVE(0x2) → second frame reverts → tx invalid (VERIFY must APPROVE).
func TestFrameTxReApproveExecution(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: []byte{0x02}},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error: re-approving execution should fail")
	}
	t.Logf("got expected error: %v", err)
}

// TestFrameTxPayBeforeSenderApproval tests that payment approval before sender approval is rejected.
// Per spec, payment approval before sender approval reverts the frame.
func TestFrameTxPayBeforeSenderApproval(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sponsor := common.HexToAddress("0x3333")

	statedb.CreateAccount(sponsor)
	statedb.SetCode(sponsor, approvePayCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sponsor, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Sponsor tries to APPROVE(0x1) first, before any sender APPROVE(0x2).
	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    common.HexToAddress("0x1111"),
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 1, Target: &sponsor, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error: payment approval before sender approval should fail")
	}
	t.Logf("got expected error: %v", err)
}

// TestFrameTxApproveBothAfterExec tests that APPROVE(0x3) after separate APPROVE(0x2) is rejected.
// Per spec: "If sender_approved is already set, revert the frame."
func TestFrameTxApproveBothAfterExec(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")

	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Sender code: calldata-dependent APPROVE.
	// If calldata is non-zero → APPROVE(0x2) (execution only).
	// If calldata is zero/empty → APPROVE(0x3) (both).
	conditionalApproveCode := []byte{
		0x60, 0x00, 0x35, 0x15, // PUSH1 0, CALLDATALOAD, ISZERO
		0x60, 0x0f, 0x57, // PUSH1 0x0f, JUMPI
		0x60, 0x02, 0x60, 0x00, 0x60, 0x00, 0xaa, 0x00, // APPROVE(0x2), STOP
		0x5b,                                     // JUMPDEST @15
		0x60, 0x03, 0x60, 0x00, 0x60, 0x00, 0xaa, // APPROVE(0x3)
	}
	statedb.SetCode(sender, conditionalApproveCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			// Frame 0: non-zero calldata → APPROVE(0x2)
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000,
				Data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			// Frame 1: empty calldata → APPROVE(0x3)
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error: APPROVE(0x3) after separate APPROVE(0x2) should fail")
	}
	t.Logf("got expected error: %v", err)
}

// TestFrameTxTransientStorageReset tests that transient storage is reset between frames.
// Per spec: "Discard the TSTORE and TLOAD transient storage between frames."
func TestFrameTxTransientStorageReset(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	target := common.HexToAddress("0x2222")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Target code:
	//   TLOAD(slot=1) → SSTORE(slot=0, value)  -- store transient value in persistent storage
	//   TSTORE(slot=1, value=0x42)               -- set transient for next frame
	//   RETURN
	tstoreCode := []byte{
		0x60, 0x01, 0x5c, // PUSH1 1, TLOAD
		0x60, 0x00, 0x55, // PUSH1 0, SSTORE
		0x60, 0x42, 0x60, 0x01, 0x5d, // PUSH1 0x42, PUSH1 1, TSTORE
		0x60, 0x00, 0x60, 0x00, 0xf3, // PUSH1 0, PUSH1 0, RETURN
	}
	statedb.CreateAccount(target)
	statedb.SetCode(target, tstoreCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 50000, Data: nil},
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 50000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("frame tx failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution failed: %v", result.Err)
	}

	// Frame 1: TLOAD(1)=0, SSTORE(0, 0), TSTORE(1, 0x42)
	// Frame 2: if transient reset → TLOAD(1)=0, SSTORE(0, 0)
	//          if NOT reset → TLOAD(1)=0x42, SSTORE(0, 0x42)
	slot0 := statedb.GetState(target, common.Hash{})
	if slot0 != (common.Hash{}) {
		t.Fatalf("transient storage was NOT reset between frames: storage[0] = %v, want 0", slot0)
	}
}

// TestFrameTxDeploymentFlow tests the 3-frame deployment pattern (Example 1b from spec).
// Frame 0: DEFAULT(deployer) — simulates account deployment
// Frame 1: VERIFY(sender) → APPROVE(0x3)
// Frame 2: SENDER(sender) — executes on behalf of sender
func TestFrameTxDeploymentFlow(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	deployer := common.HexToAddress("0x4444")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	statedb.CreateAccount(deployer)
	statedb.SetCode(deployer, returnCode, tracing.CodeChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeDefault, Target: &deployer, GasLimit: 50000, Data: []byte{0xde, 0xad}},
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
			{Mode: types.FrameModeSender, Target: nil, GasLimit: 50000, Data: []byte{0xca, 0xfe}},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("deployment flow failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution failed: %v", result.Err)
	}
	if got := statedb.GetNonce(sender); got != 1 {
		t.Fatalf("sender nonce: got %d, want 1", got)
	}
}

// TestFrameTxTxParam tests that the TXPARAM opcode returns correct values.
// Verifies nonce, frame_count, and sender parameters.
func TestFrameTxTxParam(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	target := common.HexToAddress("0x2222")

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Target code: TXPARAM(nonce) -> SSTORE(0),
	//              TXPARAM(frame_count) -> SSTORE(1),
	//              TXPARAM(sender) -> SSTORE(2), RETURN
	txparamCode := []byte{
		// TXPARAM(0x01=nonce) -> SSTORE(slot=0)
		0x60, 0x01, 0xb0,
		0x60, 0x00, 0x55,
		// TXPARAM(0x09=frame_count) -> SSTORE(slot=1)
		0x60, 0x09, 0xb0,
		0x60, 0x01, 0x55,
		// TXPARAM(0x02=sender) -> SSTORE(slot=2)
		0x60, 0x02, 0xb0,
		0x60, 0x02, 0x55,
		// RETURN
		0x60, 0x00, 0x60, 0x00, 0xf3,
	}
	statedb.CreateAccount(target)
	statedb.SetCode(target, txparamCode, tracing.CodeChangeUnspecified)

	nonce := uint64(42)
	statedb.SetNonce(sender, nonce, tracing.NonceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  nonce,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 100000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("frame tx failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution failed: %v", result.Err)
	}

	// Verify nonce at slot 0.
	nonceHash := common.Hash{}
	nonceHash[31] = byte(nonce)
	got := statedb.GetState(target, common.Hash{})
	if got != nonceHash {
		t.Fatalf("TXPARAM nonce: got %v, want %v", got, nonceHash)
	}

	// Verify frame_count at slot 1.
	frameCountHash := common.Hash{}
	frameCountHash[31] = 2
	got = statedb.GetState(target, common.BytesToHash([]byte{0x01}))
	if got != frameCountHash {
		t.Fatalf("TXPARAM frame_count: got %v, want %v", got, frameCountHash)
	}

	// Verify sender at slot 2. Sender is left-padded in 32-byte word.
	var senderHash common.Hash
	copy(senderHash[12:], sender[:])
	got = statedb.GetState(target, common.BytesToHash([]byte{0x02}))
	if got != senderHash {
		t.Fatalf("TXPARAM sender: got %v, want %v", got, senderHash)
	}
}

// TestFrameTxFrameIntrospectionOpcodes verifies frame-level EIP-8141 introspection opcodes.
func TestFrameTxFrameIntrospectionOpcodes(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	sender := common.HexToAddress("0x1111")
	target := common.HexToAddress("0x2222")
	frameData := []byte{0xde, 0xad, 0xbe, 0xef}

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	introspectionCode := []byte{
		// FRAMEPARAM(0x00=target, frame=0) -> SSTORE(slot=0)
		0x60, 0x00, 0x60, 0x00, 0xb3,
		0x60, 0x00, 0x55,
		// FRAMEPARAM(0x01=gas_limit, frame=0) -> SSTORE(slot=1)
		0x60, 0x01, 0x60, 0x00, 0xb3,
		0x60, 0x01, 0x55,
		// FRAMEPARAM(0x04=len(data), frame=0) -> SSTORE(slot=2)
		0x60, 0x04, 0x60, 0x00, 0xb3,
		0x60, 0x02, 0x55,
		// FRAMEPARAM(0x05=status, frame=0) -> SSTORE(slot=3)
		0x60, 0x05, 0x60, 0x00, 0xb3,
		0x60, 0x03, 0x55,
		// FRAMEDATALOAD(offset=0, frame=0) -> SSTORE(slot=4)
		0x60, 0x00, 0x60, 0x00, 0xb1,
		0x60, 0x04, 0x55,
		// FRAMEDATACOPY(mem=0, data=1, len=2, frame=0); MLOAD(0) -> SSTORE(slot=5)
		0x60, 0x00, 0x60, 0x02, 0x60, 0x01, 0x60, 0x00, 0xb2,
		0x60, 0x00, 0x51,
		0x60, 0x05, 0x55,
		// TXPARAM(0x0b=signature_count) -> SSTORE(slot=6)
		0x60, 0x0b, 0xb0,
		0x60, 0x06, 0x55,
		// RETURN
		0x60, 0x00, 0x60, 0x00, 0xf3,
	}
	statedb.CreateAccount(target)
	statedb.SetCode(target, introspectionCode, tracing.CodeChangeUnspecified)

	frameGas := uint64(50000)
	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: frameGas, Data: frameData},
			{Mode: types.FrameModeSender, Target: &target, GasLimit: 300000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("frame tx failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution failed: %v", result.Err)
	}
	if len(result.frameResults) != 2 || result.frameResults[1] == 0 {
		t.Fatalf("frame results: got %v, want second frame success", result.frameResults)
	}

	var senderHash common.Hash
	copy(senderHash[12:], sender[:])
	if got := statedb.GetState(target, common.Hash{}); got != senderHash {
		t.Fatalf("FRAMEPARAM target: got %v, want %v", got, senderHash)
	}

	gasHash := common.Hash{}
	gasHash[30] = byte(frameGas >> 8)
	gasHash[31] = byte(frameGas)
	if got := statedb.GetState(target, common.BytesToHash([]byte{0x01})); got != gasHash {
		t.Fatalf("FRAMEPARAM gas_limit: got %v, want %v", got, gasHash)
	}

	dataLenHash := common.Hash{}
	dataLenHash[31] = byte(len(frameData))
	if got := statedb.GetState(target, common.BytesToHash([]byte{0x02})); got != dataLenHash {
		t.Fatalf("FRAMEPARAM data length: got %v, want %v", got, dataLenHash)
	}

	statusHash := common.Hash{}
	statusHash[31] = 1
	if got := statedb.GetState(target, common.BytesToHash([]byte{0x03})); got != statusHash {
		t.Fatalf("FRAMEPARAM status: got %v, want %v", got, statusHash)
	}

	var loadHash common.Hash
	copy(loadHash[:], common.RightPadBytes(frameData, 32))
	if got := statedb.GetState(target, common.BytesToHash([]byte{0x04})); got != loadHash {
		t.Fatalf("FRAMEDATALOAD: got %v, want %v", got, loadHash)
	}

	var copyHash common.Hash
	copy(copyHash[:], []byte{0xad, 0xbe})
	if got := statedb.GetState(target, common.BytesToHash([]byte{0x05})); got != copyHash {
		t.Fatalf("FRAMEDATACOPY: got %v, want %v", got, copyHash)
	}

	if got := statedb.GetState(target, common.BytesToHash([]byte{0x06})); got != (common.Hash{}) {
		t.Fatalf("TXPARAM signature count: got %v, want zero", got)
	}
}

// TestFrameTxFrameGasSumOverflow verifies that execute detects when the sum
// of per-frame gas limits overflows uint64 and returns ErrFrameTxInvalid.
func TestFrameTxFrameGasSumOverflow(t *testing.T) {
	evm, _, _ := newFrameTestEnv()

	sender := common.HexToAddress("0xaaaa")
	// Frame 1: MaxUint64 - 100. Frame 2: 200. Sum = MaxUint64 - 100 + 200 overflows.
	msg := &Message{
		From:            sender,
		GasLimit:        100_000,
		GasFeeCap:       uint256.NewInt(uint64(params.InitialBaseFee)),
		GasTipCap:       new(uint256.Int),
		GasPrice:        uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobGasFeeCap:   new(uint256.Int),
		Value:           new(uint256.Int),
		SkipNonceChecks: true,
		Frames: []types.Frame{
			{Mode: types.FrameModeDefault, GasLimit: math.MaxUint64 - 100},
			{Mode: types.FrameModeDefault, GasLimit: 200},
		},
	}

	_, err := applyFrameTx(evm, nil, msg)
	if err == nil {
		t.Fatal("expected error for frame gas sum overflow, got nil")
	}
	if !errors.Is(err, ErrFrameTxInvalid) {
		t.Errorf("expected ErrFrameTxInvalid, got: %v", err)
	}
}

// TestFrameTxOsakaGasCap verifies that execute enforces the EIP-7825
// per-transaction gas limit cap (params.MaxTxGas) when Osaka is active.
func TestFrameTxOsakaGasCap(t *testing.T) {
	// MergedTestChainConfig has OsakaTime=0, so Osaka is always active.
	evm, _, _ := newFrameTestEnv()

	sender := common.HexToAddress("0xbbbb")
	// Construct a message whose GasLimit exceeds MaxTxGas.
	// GasFeeCap must be >= BaseFee (params.InitialBaseFee) to pass London check.
	msg := &Message{
		From:            sender,
		GasLimit:        params.MaxTxGas + 1,
		GasFeeCap:       uint256.NewInt(uint64(params.InitialBaseFee)),
		GasTipCap:       new(uint256.Int),
		GasPrice:        uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobGasFeeCap:   new(uint256.Int),
		Value:           new(uint256.Int),
		SkipNonceChecks: true,
		Frames: []types.Frame{
			{Mode: types.FrameModeDefault, GasLimit: params.MaxTxGas},
		},
	}

	_, err := applyFrameTx(evm, nil, msg)
	if err == nil {
		t.Fatal("expected ErrGasLimitTooHigh for Osaka gas cap, got nil")
	}
	if !errors.Is(err, ErrGasLimitTooHigh) {
		t.Errorf("expected ErrGasLimitTooHigh, got: %v", err)
	}
}
