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

var (
	integrationApproveBothCode = []byte{0x60, 0x03, 0x60, 0x00, 0x60, 0x00, 0xaa}
	integrationReturnCode      = []byte{0x60, 0x00, 0x60, 0x00, 0xf3}
)

func applyFrameTxAndReceipt(t *testing.T, evm *vm.EVM, statedb *state.StateDB, config *params.ChainConfig, tx *types.Transaction) *types.Receipt {
	t.Helper()

	msg, err := TransactionToMessage(tx, types.LatestSigner(config), evm.Context.BaseFee)
	if err != nil {
		t.Fatalf("TransactionToMessage failed: %v", err)
	}
	gp := NewGasPool(evm.Context.GasLimit)

	statedb.SetTxContext(tx.Hash(), 0, 0)
	receipt, _, err := ApplyTransactionWithEVM(
		msg,
		gp,
		statedb,
		new(big.Int).Set(evm.Context.BlockNumber),
		common.HexToHash("0x8141"),
		evm.Context.Time,
		tx,
		evm,
	)
	if err != nil {
		t.Fatalf("ApplyTransactionWithEVM failed: %v", err)
	}
	return receipt
}

func newFrameTx(config *params.ChainConfig, nonce uint64, sender common.Address, frames []types.Frame) *types.Transaction {
	return types.NewTx(&types.FrameTx{
		ChainID:    uint256.MustFromBig(config.ChainID),
		NonceKeys:  []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:   nonce,
		Sender:     sender,
		Frames:     frames,
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	})
}

func assertFrameStatuses(t *testing.T, receipt *types.Receipt, want []uint8) {
	t.Helper()

	if len(receipt.FrameReceipts) != len(want) {
		t.Fatalf("frame receipt length mismatch: got %d want %d", len(receipt.FrameReceipts), len(want))
	}
	for i, s := range want {
		if got := receipt.FrameReceipts[i].Status; got != s {
			t.Fatalf("frame %d status mismatch: got %d want %d", i, got, s)
		}
	}
}

func createContract(statedb *state.StateDB, addr common.Address, code []byte, balance *uint256.Int) {
	statedb.CreateAccount(addr)
	statedb.SetCode(addr, code, tracing.CodeChangeUnspecified)
	statedb.SetBalance(addr, balance, tracing.BalanceChangeUnspecified)
}

// approveIfEntryPointElseReturn returns code that:
// - caller == ENTRY_POINT: APPROVE(scope)
// - otherwise: RETURN(0,0)
func approveIfEntryPointElseReturn(entryPoint common.Address, scope byte) []byte {
	code := []byte{0x33, 0x73}
	code = append(code, entryPoint[:]...)
	code = append(code,
		0x14, 0x60, 0x1f, 0x57,
		0x60, 0x00, 0x60, 0x00, 0xf3,
		0x5b,
		0x60, scope, 0x60, 0x00, 0x60, 0x00, 0xaa,
	)
	return code
}

// approveIfCalldataElseReturn returns code that:
// - calldata size > 0: APPROVE(scope)
// - calldata size == 0: RETURN(0,0)
func approveIfCalldataElseReturn(scope byte) []byte {
	return []byte{
		0x36, 0x15, 0x60, 0x0c, 0x57,
		0x60, scope, 0x60, 0x00, 0x60, 0x00, 0xaa,
		0x5b, 0x60, 0x00, 0x60, 0x00, 0xf3,
	}
}

// approveIfEntryPointElseTransferOneWei returns code that:
// - caller == ENTRY_POINT: APPROVE(0x3)
// - otherwise: transfer 1 wei to recipient, then RETURN(0,0)
func approveIfEntryPointElseTransferOneWei(entryPoint, recipient common.Address) []byte {
	code := []byte{0x33, 0x73}
	code = append(code, entryPoint[:]...)
	code = append(code,
		0x14, 0x60, 0x41, 0x57,
		0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x01,
		0x73,
	)
	code = append(code, recipient[:]...)
	code = append(code,
		0x5a, 0xf1, 0x50,
		0x60, 0x00, 0x60, 0x00, 0xf3,
		0x5b, 0x60, 0x03, 0x60, 0x00, 0x60, 0x00, 0xaa,
	)
	return code
}

// Example 1 from .context/eip-8141.md:
// [VERIFY(sender), SENDER(target)].
func TestFrameTxExample1Integration(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()
	sender := common.HexToAddress("0x1111")
	target := common.HexToAddress("0x2222")

	createContract(statedb, sender, integrationApproveBothCode, uint256.NewInt(1e18))
	createContract(statedb, target, integrationReturnCode, uint256.NewInt(0))

	tx := newFrameTx(config, 0, sender, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 60_000, Data: []byte("signature")},
		{Mode: types.FrameModeSender, Target: &target, GasLimit: 80_000, Data: []byte("call")},
	})
	receipt := applyFrameTxAndReceipt(t, evm, statedb, config, tx)

	if receipt.Type != types.FrameTxType {
		t.Fatalf("receipt type mismatch: got %d want %d", receipt.Type, types.FrameTxType)
	}
	if receipt.Payer != sender {
		t.Fatalf("payer mismatch: got %s want %s", receipt.Payer, sender)
	}
	assertFrameStatuses(t, receipt, []uint8{1, 1})
	if got := statedb.GetNonce(sender); got != 1 {
		t.Fatalf("sender nonce mismatch: got %d want 1", got)
	}
}

// Example 1a from .context/eip-8141.md:
// [VERIFY(sender), SENDER(sender)] where sender code transfers ETH.
func TestFrameTxExample1aIntegration(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()
	sender := common.HexToAddress("0x1111")
	recipient := common.HexToAddress("0x2222")

	createContract(
		statedb,
		sender,
		approveIfEntryPointElseTransferOneWei(params.FrameEntryPointAddress, recipient),
		uint256.NewInt(1e18),
	)
	statedb.CreateAccount(recipient)
	statedb.SetBalance(recipient, uint256.NewInt(0), tracing.BalanceChangeUnspecified)

	tx := newFrameTx(config, 0, sender, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 60_000, Data: []byte("signature")},
		{Mode: types.FrameModeSender, Target: nil, GasLimit: 120_000, Data: append(recipient.Bytes(), []byte{1}...)},
	})
	receipt := applyFrameTxAndReceipt(t, evm, statedb, config, tx)

	if receipt.Payer != sender {
		t.Fatalf("payer mismatch: got %s want %s", receipt.Payer, sender)
	}
	assertFrameStatuses(t, receipt, []uint8{1, 1})
	if got := statedb.GetBalance(recipient); got.Cmp(uint256.NewInt(1)) != 0 {
		t.Fatalf("recipient balance mismatch: got %v want 1", got)
	}
}

// Example 1b from .context/eip-8141.md:
// [DEFAULT(deployer), VERIFY(sender), SENDER(sender)].
// This test focuses on frame ordering and receipt behavior.
func TestFrameTxExample1bIntegration(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()
	sender := common.HexToAddress("0x1111")
	deployer := common.HexToAddress("0x4444")

	createContract(statedb, deployer, integrationReturnCode, uint256.NewInt(0))
	createContract(statedb, sender, approveIfEntryPointElseReturn(params.FrameEntryPointAddress, 0x3), uint256.NewInt(1e18))

	tx := newFrameTx(config, 0, sender, []types.Frame{
		{Mode: types.FrameModeDefault, Target: &deployer, GasLimit: 50_000, Data: []byte("initcode+salt")},
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 60_000, Data: []byte("signature")},
		{Mode: types.FrameModeSender, Target: nil, GasLimit: 70_000, Data: []byte("execution")},
	})
	receipt := applyFrameTxAndReceipt(t, evm, statedb, config, tx)

	if receipt.Payer != sender {
		t.Fatalf("payer mismatch: got %s want %s", receipt.Payer, sender)
	}
	assertFrameStatuses(t, receipt, []uint8{1, 1, 1})
	if got := statedb.GetNonce(sender); got != 1 {
		t.Fatalf("sender nonce mismatch: got %d want 1", got)
	}
}

// Example 2 from .context/eip-8141.md (sponsored flow):
// [VERIFY(sender), VERIFY(sponsor), SENDER(erc20), SENDER(target), DEFAULT(sponsor)].
func TestFrameTxExample2Integration(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()
	sender := common.HexToAddress("0x1111")
	sponsor := common.HexToAddress("0x3333")
	erc20 := common.HexToAddress("0x5555")
	target := common.HexToAddress("0x2222")

	createContract(statedb, sender, approveIfEntryPointElseReturn(params.FrameEntryPointAddress, 0x2), uint256.NewInt(1e15))
	createContract(statedb, sponsor, approveIfCalldataElseReturn(0x1), uint256.NewInt(1e18))
	createContract(statedb, erc20, integrationReturnCode, uint256.NewInt(0))
	createContract(statedb, target, integrationReturnCode, uint256.NewInt(0))

	sponsorBefore := statedb.GetBalance(sponsor).Clone()
	tx := newFrameTx(config, 0, sender, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 60_000, Data: []byte("signature")},
		{Mode: types.FrameModeVerify, Flags: 1, Target: &sponsor, GasLimit: 60_000, Data: []byte("sponsor-data")},
		{Mode: types.FrameModeSender, Target: &erc20, GasLimit: 70_000, Data: make([]byte, 68)},
		{Mode: types.FrameModeSender, Target: &target, GasLimit: 70_000, Data: []byte("user-call")},
		{Mode: types.FrameModeDefault, Target: &sponsor, GasLimit: 50_000, Data: nil},
	})
	receipt := applyFrameTxAndReceipt(t, evm, statedb, config, tx)

	if receipt.Payer != sponsor {
		t.Fatalf("payer mismatch: got %s want %s", receipt.Payer, sponsor)
	}
	assertFrameStatuses(t, receipt, []uint8{1, 1, 1, 1, 1})
	if got := statedb.GetNonce(sender); got != 1 {
		t.Fatalf("sender nonce mismatch: got %d want 1", got)
	}
	if sponsorAfter := statedb.GetBalance(sponsor); sponsorAfter.Cmp(sponsorBefore) >= 0 {
		t.Fatalf("sponsor should pay gas: before=%v after=%v", sponsorBefore, sponsorAfter)
	}
}
