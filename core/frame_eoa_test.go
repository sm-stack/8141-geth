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
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func addEOADefaultSignature(ftx *types.FrameTx, chainID *big.Int, key *ecdsa.PrivateKey) {
	addEOADefaultSignatureForMsg(ftx, chainID, key, nil)
}

func addEOADefaultSignatureForMsg(ftx *types.FrameTx, chainID *big.Int, key *ecdsa.PrivateKey, msg []byte) {
	signer := crypto.PubkeyToAddress(key.PublicKey)
	ftx.Signatures = append(ftx.Signatures, types.TxSignature{
		Scheme: types.SignatureSchemeSecp256k1,
		Signer: signer,
		Msg:    common.CopyBytes(msg),
	})
	signingMsg := msg
	if len(signingMsg) == 0 {
		sigHash := ftx.SigHash(chainID)
		signingMsg = sigHash[:]
	}
	sig, err := crypto.Sign(signingMsg, key)
	if err != nil {
		panic(err)
	}
	vrs := make([]byte, 65)
	vrs[0] = sig[64]
	copy(vrs[1:33], sig[0:32])
	copy(vrs[33:65], sig[32:64])
	ftx.Signatures[len(ftx.Signatures)-1].Signature = vrs
}

// TestEOADefaultCodeSimple tests the simplest EOA frame transaction:
// VERIFY with ECDSA signature + SENDER with a simple ETH transfer.
// This replicates Example 1 from EIP-8141 but with an EOA sender.
func TestEOADefaultCodeSimple(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	// Generate a real ECDSA key.
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	recipient := common.HexToAddress("0x2222")

	// Setup: sender is an EOA with no code, plenty of ETH.
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Recipient exists.
	statedb.CreateAccount(recipient)
	transfer := uint256.NewInt(1_000_000_000_000_000)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 100000, Data: nil},
			{Mode: types.FrameModeSender, Target: &recipient, GasLimit: 100000, Value: transfer, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	addEOADefaultSignature(ftx, config.ChainID, key)

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}

	// Verify nonce was incremented.
	if got := statedb.GetNonce(sender); got != 1 {
		t.Fatalf("sender nonce: got %d, want 1", got)
	}

	// Verify recipient received ETH.
	recipientBal := statedb.GetBalance(recipient)
	if recipientBal.Cmp(transfer) != 0 {
		t.Fatalf("recipient balance: got %s, want %s", recipientBal, transfer)
	}
}

// TestEOADefaultCodeVerifyOnly tests EOA VERIFY with APPROVE(0x3) and no SENDER frame.
func TestEOADefaultCodeVerifyOnly(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
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
	addEOADefaultSignature(ftx, config.ChainID, key)

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}
	if got := statedb.GetNonce(sender); got != 1 {
		t.Fatalf("sender nonce: got %d, want 1", got)
	}
}

// TestEOADefaultCodeWrongSigner tests that an ECDSA signature from a different key fails.
func TestEOADefaultCodeWrongSigner(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	wrongKey, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
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
	addEOADefaultSignature(ftx, config.ChainID, wrongKey)

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for wrong signer, got nil")
	}
	t.Logf("got expected error: %v", err)
}

func TestEOADefaultCodeTxSignatureRequiresAllowedScope(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Target: nil, GasLimit: 100000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}
	addEOADefaultSignature(ftx, config.ChainID, key)

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error when tx-level signature has no allowed APPROVE scope")
	}
}

// TestEOADefaultCodeRejectsFrameDataSignature tests that old VERIFY frame-data
// signatures are ignored; approval requires a matching tx.signatures entry.
func TestEOADefaultCodeRejectsFrameDataSignature(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 100000,
				// Old layout: byte0, sig_type=secp256k1, v, r, s. This must not be parsed.
				Data: append([]byte{0x21, 0x00}, make([]byte, 65)...)},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for old frame-data signature without tx-level signature")
	}
	t.Logf("got expected error: %v", err)
}

// TestEOADefaultCodeDefaultModeSucceeds tests that DEFAULT mode on an EOA
// behaves like a call to empty code.
func TestEOADefaultCodeDefaultModeSucceeds(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	target := common.HexToAddress("0x3333")
	statedb.CreateAccount(target)
	// target has NO code — EOA

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
			{Mode: types.FrameModeDefault, Target: &target, GasLimit: 50000,
				Data: []byte{0x00}},
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
	if got := result.frameResults; len(got) != 2 || got[1] != types.FrameReceiptStatusSuccessful {
		t.Fatalf("frame results: got %v, want DEFAULT EOA frame success", got)
	}
}

// TestEOADefaultCodeSplitApproval tests EOA with split approval:
// Frame 0: VERIFY with APPROVE(0x2) — execution only
// Frame 1: VERIFY with APPROVE(0x1) — payment only (using a contract)
// Frame 2: SENDER — execute a call
func TestEOADefaultCodeSplitApproval(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	sponsor := common.HexToAddress("0x5555")
	recipient := common.HexToAddress("0x2222")

	// Sender is an EOA with no code.
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Sponsor has APPROVE(0x1) code and ETH to pay gas.
	statedb.CreateAccount(sponsor)
	statedb.SetCode(sponsor, approvePayCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sponsor, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Recipient exists.
	statedb.CreateAccount(recipient)
	transfer := uint256.NewInt(1_000_000_000_000_000)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 100000, Data: nil},               // EOA VERIFY
			{Mode: types.FrameModeVerify, Flags: 1, Target: &sponsor, GasLimit: 100000, Data: nil},          // Sponsor VERIFY
			{Mode: types.FrameModeSender, Target: &recipient, GasLimit: 100000, Value: transfer, Data: nil}, // SENDER call
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	addEOADefaultSignature(ftx, config.ChainID, key)

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}

	// Verify recipient got ETH.
	if got := statedb.GetBalance(recipient); got.Cmp(transfer) != 0 {
		t.Fatalf("recipient balance: got %s, want %s", got, transfer)
	}
}

// TestEOADefaultCodeMissingTxSignature tests that VERIFY fails without a
// matching tx-level signature even when frame data is empty.
func TestEOADefaultCodeMissingTxSignature(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 100000, Data: []byte{}},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for missing tx-level signature")
	}
	t.Logf("got expected error: %v", err)
}

func TestEOADefaultCodeRequiresEmptyMsgSignature(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
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
	msg32 := make([]byte, 32)
	msg32[31] = 1
	addEOADefaultSignatureForMsg(ftx, config.ChainID, key, msg32)

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for explicit-msg tx-level signature")
	}
	t.Logf("got expected error: %v", err)
}

// TestEOADefaultCodeSenderModeSucceedsAsEmptyCall tests that SENDER mode
// targeting the EOA itself ignores calldata and succeeds like empty code.
func TestEOADefaultCodeSenderModeSucceedsAsEmptyCall(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID:   uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  0,
		Sender:    sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 100000, Data: nil},
			{Mode: types.FrameModeSender, Target: nil, GasLimit: 200000, Data: []byte{0xff, 0xee}},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	addEOADefaultSignature(ftx, config.ChainID, key)

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}
	if got := result.frameResults; len(got) != 2 || got[1] != types.FrameReceiptStatusSuccessful {
		t.Fatalf("frame results: got %v, want SENDER EOA frame success", got)
	}
}
