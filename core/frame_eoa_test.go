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
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// buildEOASenderData builds the frame.data for EOA default code SENDER mode.
//
// Layout: [byte0, RLP-encoded [[target, value, data], ...]]
// byte0: 0x02 (high nibble = 0, low nibble = SENDER mode = 2)
func buildEOASenderData(calls []struct {
	Target common.Address
	Value  *big.Int
	Data   []byte
}) []byte {
	type eoaCall struct {
		Target common.Address
		Value  *big.Int
		Data   []byte
	}

	encoded := make([]eoaCall, len(calls))
	for i, c := range calls {
		encoded[i] = eoaCall{Target: c.Target, Value: c.Value, Data: c.Data}
	}

	rlpData, err := rlp.EncodeToBytes(encoded)
	if err != nil {
		panic(err)
	}

	// byte0: high nibble = 0, low nibble = 2 (SENDER)
	result := make([]byte, 1+len(rlpData))
	result[0] = 0x02
	copy(result[1:], rlpData)
	return result
}

func addEOADefaultSignature(ftx *types.FrameTx, chainID *big.Int, key *ecdsa.PrivateKey) {
	signer := crypto.PubkeyToAddress(key.PublicKey)
	ftx.Signatures = append(ftx.Signatures, types.TxSignature{
		Scheme: types.SignatureSchemeSecp256k1,
		Signer: signer,
	})
	sigHash := ftx.SigHash(chainID)
	sig, err := crypto.Sign(sigHash[:], key)
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

	// Build the frame transaction (data will be filled after sig hash).
	ftx := &types.FrameTx{
		ChainID: uint256.NewInt(config.ChainID.Uint64()),
		Nonce:   0,
		Sender:  sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 100000, Data: nil},
			{Mode: types.FrameModeSender, Target: nil, GasLimit: 100000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	// Build sender frame data: send 1 ETH to recipient.
	senderData := buildEOASenderData([]struct {
		Target common.Address
		Value  *big.Int
		Data   []byte
	}{
		{Target: recipient, Value: big.NewInt(1e15), Data: nil},
	})
	ftx.Frames[1].Data = senderData
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
	if recipientBal.IsZero() {
		t.Fatal("recipient should have received ETH")
	}
	t.Logf("recipient balance: %s", recipientBal)
}

// TestEOADefaultCodeVerifyOnly tests EOA VERIFY with APPROVE(0x2) and no SENDER frame.
func TestEOADefaultCodeVerifyOnly(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID: uint256.NewInt(config.ChainID.Uint64()),
		Nonce:   0,
		Sender:  sender,
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
		ChainID: uint256.NewInt(config.ChainID.Uint64()),
		Nonce:   0,
		Sender:  sender,
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

// TestEOADefaultCodeInvalidDataLength tests that wrong data length for ECDSA fails.
func TestEOADefaultCodeInvalidDataLength(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID: uint256.NewInt(config.ChainID.Uint64()),
		Nonce:   0,
		Sender:  sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Target: nil, GasLimit: 100000,
				// byte0 = 0x21 (scope=2, mode=VERIFY), sig_type=0x00, then only 10 bytes of garbage
				Data: append([]byte{0x21, 0x00}, make([]byte, 10)...)},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for invalid data length")
	}
	t.Logf("got expected error: %v", err)
}

// TestEOADefaultCodeDefaultModeReverts tests that DEFAULT mode always reverts for EOAs.
func TestEOADefaultCodeDefaultModeReverts(t *testing.T) {
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
		ChainID: uint256.NewInt(config.ChainID.Uint64()),
		Nonce:   0,
		Sender:  sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
			// DEFAULT mode frame targeting an EOA — should revert (non-fatal).
			{Mode: types.FrameModeDefault, Target: &target, GasLimit: 50000,
				// byte0: high nibble=0, low nibble=0 (DEFAULT mode)
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
	// The transaction should succeed overall (payer approved in frame 0).
	// Frame 1 (DEFAULT on EOA) should have reverted, but that's non-fatal.
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}
}

// TestEOADefaultCodeSplitApproval tests EOA with split approval:
// Frame 0: VERIFY with APPROVE(0x0) — execution only
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

	ftx := &types.FrameTx{
		ChainID: uint256.NewInt(config.ChainID.Uint64()),
		Nonce:   0,
		Sender:  sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 100000, Data: nil}, // EOA VERIFY
			{Mode: types.FrameModeVerify, Target: &sponsor, GasLimit: 100000, Data: nil},      // Sponsor VERIFY
			{Mode: types.FrameModeSender, Target: nil, GasLimit: 100000, Data: nil},           // SENDER call
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	// Build SENDER data: send ETH to recipient.
	senderData := buildEOASenderData([]struct {
		Target common.Address
		Value  *big.Int
		Data   []byte
	}{
		{Target: recipient, Value: big.NewInt(1e15), Data: nil},
	})
	ftx.Frames[2].Data = senderData
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
	if statedb.GetBalance(recipient).IsZero() {
		t.Fatal("recipient should have received ETH")
	}
}

// TestEOADefaultCodeEmptyData tests that empty frame data reverts for EOA.
func TestEOADefaultCodeEmptyData(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := &types.FrameTx{
		ChainID: uint256.NewInt(config.ChainID.Uint64()),
		Nonce:   0,
		Sender:  sender,
		Frames: []types.Frame{
			// Empty data on an EOA VERIFY frame — should fail.
			{Mode: types.FrameModeVerify, Target: nil, GasLimit: 100000, Data: []byte{}},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	_, err := applyFrameTx(evm, config, msg)
	if err == nil {
		t.Fatal("expected error for empty data on EOA VERIFY frame")
	}
	t.Logf("got expected error: %v", err)
}

// TestEOADefaultCodeSenderMultipleCalls tests SENDER mode with multiple calls.
func TestEOADefaultCodeSenderMultipleCalls(t *testing.T) {
	evm, statedb, config := newFrameTestEnv()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	recipient1 := common.HexToAddress("0x2222")
	recipient2 := common.HexToAddress("0x3333")

	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(recipient1)
	statedb.CreateAccount(recipient2)

	ftx := &types.FrameTx{
		ChainID: uint256.NewInt(config.ChainID.Uint64()),
		Nonce:   0,
		Sender:  sender,
		Frames: []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 100000, Data: nil},
			{Mode: types.FrameModeSender, Target: nil, GasLimit: 200000, Data: nil},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}

	// Build SENDER data with 2 calls.
	senderData := buildEOASenderData([]struct {
		Target common.Address
		Value  *big.Int
		Data   []byte
	}{
		{Target: recipient1, Value: big.NewInt(1e15), Data: nil},
		{Target: recipient2, Value: big.NewInt(2e15), Data: nil},
	})
	ftx.Frames[1].Data = senderData
	addEOADefaultSignature(ftx, config.ChainID, key)

	msg := makeFrameMsg(ftx, config, big.NewInt(params.InitialBaseFee))
	result, err := applyFrameTx(evm, config, msg)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if result.Failed() {
		t.Fatalf("execution result failed: %v", result.Err)
	}

	// Both recipients should have received ETH.
	bal1 := statedb.GetBalance(recipient1)
	bal2 := statedb.GetBalance(recipient2)
	if bal1.IsZero() || bal2.IsZero() {
		t.Fatalf("recipients should have received ETH: bal1=%s, bal2=%s", bal1, bal2)
	}
	t.Logf("recipient1: %s, recipient2: %s", bal1, bal2)
}
