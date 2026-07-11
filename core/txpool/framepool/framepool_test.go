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

package framepool

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// --- Test helpers ---

// testChain implements BlockChain for tests.
type testChain struct {
	config  *params.ChainConfig
	statedb *state.StateDB
	head    *types.Header
}

func (c *testChain) Config() *params.ChainConfig                 { return c.config }
func (c *testChain) CurrentBlock() *types.Header                 { return c.head }
func (c *testChain) StateAt(common.Hash) (*state.StateDB, error) { return c.statedb, nil }

// reserver implements txpool.Reserver for tests.
type reserver struct {
	lock     sync.Mutex
	accounts map[common.Address]struct{}
}

func newReserver() *reserver {
	return &reserver{accounts: make(map[common.Address]struct{})}
}

func (r *reserver) Hold(addr common.Address) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, exists := r.accounts[addr]; exists {
		return nil // allow re-reservation in tests
	}
	r.accounts[addr] = struct{}{}
	return nil
}

func (r *reserver) Release(addr common.Address) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	delete(r.accounts, addr)
	return nil
}

func (r *reserver) Has(addr common.Address) bool {
	r.lock.Lock()
	defer r.lock.Unlock()
	_, exists := r.accounts[addr]
	return exists
}

// Bytecode constants.
var (
	// APPROVE(0x3): PUSH1 0x03, PUSH1 0x00, PUSH1 0x00, APPROVE(0xaa)
	approveBothCode = []byte{0x60, 0x03, 0x60, 0x00, 0x60, 0x00, 0xaa}

	// APPROVE(0x2): PUSH1 0x02, PUSH1 0x00, PUSH1 0x00, APPROVE(0xaa)
	approveExecCode = []byte{0x60, 0x02, 0x60, 0x00, 0x60, 0x00, 0xaa}

	// Simple RETURN: PUSH1 0x00, PUSH1 0x00, RETURN(0xf3)
	returnCode = []byte{0x60, 0x00, 0x60, 0x00, 0xf3}

	// TIMESTAMP then APPROVE(0x3): TIMESTAMP, PUSH1 0x03, PUSH1 0x00, PUSH1 0x00, APPROVE(0xaa)
	// For use in VERIFY frames only (proves TIMESTAMP is OP-011 banned in VERIFY).
	timestampThenApproveCode = []byte{0x42, 0x60, 0x03, 0x60, 0x00, 0x60, 0x00, 0xaa}

	// TIMESTAMP then RETURN: TIMESTAMP(0x42), POP(0x50), PUSH1 0x00, PUSH1 0x00, RETURN(0xf3)
	// For use in DEFAULT frames to verify TIMESTAMP is not banned outside VERIFY context.
	timestampThenReturnCode = []byte{0x42, 0x50, 0x60, 0x00, 0x60, 0x00, 0xf3}

	// GAS, ADD (OP-012 violation), then APPROVE(0x3):
	// GAS(0x5a), PUSH1 0x00, ADD(0x01), POP(0x50), PUSH1 0x03, PUSH1 0x00, PUSH1 0x00, APPROVE(0xaa)
	gasAddThenApproveCode = []byte{0x5a, 0x60, 0x00, 0x01, 0x50, 0x60, 0x03, 0x60, 0x00, 0x60, 0x00, 0xaa}

	// BALANCE (OP-080 violation) then APPROVE(0x3):
	// PUSH20 <addr>, BALANCE(0x31), POP, APPROVE(0x3)
	// PUSH20 0x00..00, BALANCE, POP, PUSH1 0x03, PUSH1 0x00, PUSH1 0x00, APPROVE
	balanceThenApproveCode = append(
		append([]byte{0x73}, make([]byte, 20)...), // PUSH20 0x00..00
		0x31, 0x50, 0x60, 0x03, 0x60, 0x00, 0x60, 0x00, 0xaa,
	)

	// APPROVE(0x1) — payment approval: PUSH1 0x01, PUSH1 0x00, PUSH1 0x00, APPROVE(0xaa)
	approvePayCode = []byte{0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0xaa}
)

func newTestEnv() (*FramePool, *state.StateDB, *params.ChainConfig) {
	config := params.MergedTestChainConfig
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())

	head := &types.Header{
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(0),
		Time:       0,
	}

	chain := &testChain{
		config:  config,
		statedb: statedb,
		head:    head,
	}

	pool := New(chain)
	pool.Init(0, head, newReserver())
	return pool, statedb, config
}

// makeFrameTx creates a wrapped *types.Transaction from a FrameTx.
func makeFrameTx(ftx *types.FrameTx) *types.Transaction {
	return types.NewTx(ftx)
}

// baseFTX returns a valid FrameTx skeleton for the given sender.
func baseFTX(sender common.Address, nonce uint64, config *params.ChainConfig) *types.FrameTx {
	return &types.FrameTx{
		ChainID:    uint256.NewInt(config.ChainID.Uint64()),
		Nonce:      nonce,
		Sender:     sender,
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(uint64(params.InitialBaseFee)),
		BlobFeeCap: new(uint256.Int),
	}
}

func expiryFrameData(deadline uint64) []byte {
	data := make([]byte, params.FrameExpiryDataLength)
	binary.BigEndian.PutUint64(data, deadline)
	return data
}

func addFramePoolEOASignature(ftx *types.FrameTx, chainID *big.Int, key *ecdsa.PrivateKey) {
	addFramePoolEOASignatureForMsg(ftx, chainID, key, nil)
}

func addFramePoolEOASignatureForMsg(ftx *types.FrameTx, chainID *big.Int, key *ecdsa.PrivateKey, msg []byte) {
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

// --- Tests ---

func TestFramePoolFilter(t *testing.T) {
	pool, _, _ := newTestEnv()

	// Frame tx should be accepted.
	ftx := &types.FrameTx{
		ChainID:    uint256.NewInt(1),
		GasTipCap:  uint256.NewInt(0),
		GasFeeCap:  uint256.NewInt(0),
		BlobFeeCap: new(uint256.Int),
		Frames:     []types.Frame{{Mode: types.FrameModeVerify, GasLimit: 50000}},
	}
	if !pool.Filter(makeFrameTx(ftx)) {
		t.Fatal("expected Filter to accept FrameTxType")
	}

	// Legacy tx should be rejected.
	legacy := types.NewTx(&types.LegacyTx{Nonce: 0, Gas: 21000, GasPrice: big.NewInt(1)})
	if pool.Filter(legacy) {
		t.Fatal("expected Filter to reject LegacyTxType")
	}
}

func TestFramePoolValidFrameTx(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] != nil {
		t.Fatalf("expected valid frame tx to be accepted, got: %v", errs[0])
	}

	// Should be in pool.
	if pending, _ := pool.Stats(); pending != 1 {
		t.Fatalf("expected 1 pending, got %d", pending)
	}
}

func TestFramePoolRejectsInvalidTxSignature(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}
	ftx.Signatures = []types.TxSignature{{
		Scheme:    types.SignatureSchemeSecp256k1,
		Signer:    sender,
		Signature: make([]byte, 65),
	}}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for invalid tx-level signature")
	}
}

func TestFramePoolEOADefaultCodeUsesTxSignatures(t *testing.T) {
	pool, statedb, config := newTestEnv()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: nil},
	}
	addFramePoolEOASignature(ftx, config.ChainID, key)

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] != nil {
		t.Fatalf("expected EOA default VERIFY with tx-level signature to be accepted, got: %v", errs[0])
	}
}

func TestFramePoolEOADefaultCodeRejectsFrameDataSignature(t *testing.T) {
	pool, statedb, config := newTestEnv()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000,
			// Old default-code frame signature layout must not approve validation.
			Data: append([]byte{0x21, 0x00}, make([]byte, 65)...)},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for old frame-data signature without tx-level signature")
	}
}

func TestFramePoolEOADefaultCodeRejectsExplicitMsgSignature(t *testing.T) {
	pool, statedb, config := newTestEnv()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: nil},
	}
	msg32 := make([]byte, 32)
	msg32[31] = 1
	addFramePoolEOASignatureForMsg(ftx, config.ChainID, key, msg32)

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for explicit-msg tx-level signature")
	}
}

func TestFramePoolBannedOpcode(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, timestampThenApproveCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for banned opcode TIMESTAMP")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestFramePoolExpiryVerifierFrame(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	expiry := params.FrameExpiryVerifierAddress
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(expiry)
	statedb.SetCode(expiry, params.FrameExpiryVerifierCode, tracing.CodeChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Target: &expiry, GasLimit: 1_000_000, Data: expiryFrameData(pool.currentHead.Time + 12)},
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] != nil {
		t.Fatalf("expected valid expiry verifier frame to be accepted, got: %v", errs[0])
	}
}

func TestFramePoolExpiryVerifierExpiredDeadline(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	expiry := params.FrameExpiryVerifierAddress
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(expiry)
	statedb.SetCode(expiry, params.FrameExpiryVerifierCode, tracing.CodeChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Target: &expiry, GasLimit: 50000, Data: expiryFrameData(pool.currentHead.Time + 11)},
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected expired expiry verifier frame to be rejected")
	}
}

func TestFramePoolResetDropsExpiredExpiryVerifierTx(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	expiry := params.FrameExpiryVerifierAddress
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(expiry)
	statedb.SetCode(expiry, params.FrameExpiryVerifierCode, tracing.CodeChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Target: &expiry, GasLimit: 1_000_000, Data: expiryFrameData(pool.currentHead.Time + 12)},
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}
	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] != nil {
		t.Fatalf("expected initial tx to be accepted, got: %v", errs[0])
	}

	newHead := *pool.currentHead
	newHead.Time = 13
	pool.Reset(pool.currentHead, &newHead)
	if pending, _ := pool.Stats(); pending != 0 {
		t.Fatalf("expected expired tx to be dropped during reset, got %d pending", pending)
	}
}

func TestFramePoolGasRule(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, gasAddThenApproveCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for GAS not followed by CALL (OP-012)")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestFramePoolBalanceBanned(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, balanceThenApproveCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for BALANCE opcode (OP-080)")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestFramePoolNoApprove(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, returnCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for VERIFY frame without APPROVE")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestFramePoolRejectsApproveScopeOutsideFrameFlags(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection when APPROVE scope is not allowed by frame flags")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestFramePoolGasCap(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: maxVerifyGas + 1, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for VERIFY frame exceeding gas cap")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestFramePoolSignatureGasCountsAgainstVerifyBudget(t *testing.T) {
	pool, statedb, config := newTestEnv()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: maxVerifyGas - params.SigGasSecp256k1 + 1},
	}
	addFramePoolEOASignature(ftx, config.ChainID, key)

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection when signature gas pushes validation prefix above MAX_VERIFY_GAS")
	}
}

func TestFramePoolRejectsAtomicBatchInValidationPrefix(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(target)
	statedb.SetCode(target, returnCode, tracing.CodeChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3 | types.FrameFlagAtomicBatch, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
		{Mode: types.FrameModeDefault, Target: &target, GasLimit: 10000, Data: []byte{0x02}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for atomic batch flag inside validation prefix")
	}
}

func TestFramePoolDeployValidationPrefixShapes(t *testing.T) {
	t.Run("deploy_self_verify", func(t *testing.T) {
		pool, statedb, config := newTestEnv()

		sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
		factory := common.HexToAddress("0x2222222222222222222222222222222222222222")
		statedb.CreateAccount(sender)
		statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
		statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
		statedb.CreateAccount(factory)
		statedb.SetCode(factory, returnCode, tracing.CodeChangeUnspecified)

		ftx := baseFTX(sender, 0, config)
		ftx.Frames = []types.Frame{
			{Mode: types.FrameModeDefault, Target: &factory, GasLimit: 10000, Data: []byte{0x01}},
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x02}},
		}
		errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
		if errs[0] != nil {
			t.Fatalf("expected deploy+self VERIFY prefix to be accepted, got: %v", errs[0])
		}
	})

	t.Run("deploy_only_verify_pay", func(t *testing.T) {
		pool, statedb, config := newTestEnv()

		sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
		factory := common.HexToAddress("0x2222222222222222222222222222222222222222")
		payer := common.HexToAddress("0x3333333333333333333333333333333333333333")
		statedb.CreateAccount(sender)
		statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
		statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
		statedb.CreateAccount(factory)
		statedb.SetCode(factory, returnCode, tracing.CodeChangeUnspecified)
		statedb.CreateAccount(payer)
		statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)
		statedb.SetBalance(payer, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

		ftx := baseFTX(sender, 0, config)
		ftx.Frames = []types.Frame{
			{Mode: types.FrameModeDefault, Target: &factory, GasLimit: 10000, Data: []byte{0x01}},
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 40000, Data: []byte{0x02}},
			{Mode: types.FrameModeVerify, Flags: 1, Target: &payer, GasLimit: 40000, Data: []byte{0x03}},
		}
		errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
		if errs[0] != nil {
			t.Fatalf("expected deploy+exec VERIFY+pay VERIFY prefix to be accepted, got: %v", errs[0])
		}
	})
}

func TestFramePoolSelfVerifyStopsValidationPrefix(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
		{Mode: types.FrameModeVerify, Flags: 1, Target: &payer, GasLimit: maxVerifyGas, Data: []byte{0x02}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] != nil {
		t.Fatalf("expected self VERIFY to stop prefix before paymaster candidate, got: %v", errs[0])
	}
}

func TestFramePoolSenderLimit(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Add maxFrameTxsPerAccount txs — all should succeed.
	for i := uint64(0); i < maxFrameTxsPerAccount; i++ {
		ftx := baseFTX(sender, i, config)
		ftx.Frames = []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{byte(i)}},
		}
		errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
		if errs[0] != nil {
			t.Fatalf("tx %d: unexpected error: %v", i, errs[0])
		}
	}

	// The next one should be rejected.
	ftx := baseFTX(sender, maxFrameTxsPerAccount, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0xff}},
	}
	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection when exceeding per-sender limit")
	}
	t.Logf("correctly rejected: %v", errs[0])

	if pending, _ := pool.Stats(); pending != maxFrameTxsPerAccount {
		t.Fatalf("expected %d pending, got %d", maxFrameTxsPerAccount, pending)
	}
}

func TestFramePoolSameNonceReplacementRequiresFeeBump(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}
	oldTx := makeFrameTx(ftx)
	errs := pool.Add([]*types.Transaction{oldTx}, false)
	if errs[0] != nil {
		t.Fatalf("initial tx rejected: %v", errs[0])
	}

	underpriced := baseFTX(sender, 0, config)
	underpriced.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x02}},
	}
	errs = pool.Add([]*types.Transaction{makeFrameTx(underpriced)}, false)
	if errs[0] == nil {
		t.Fatal("expected same-nonce replacement without fee bump to be rejected")
	}

	bumped := baseFTX(sender, 0, config)
	bumped.GasTipCap = uint256.NewInt(2)
	bumped.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) * 11 / 10)
	bumped.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x03}},
	}
	newTx := makeFrameTx(bumped)
	errs = pool.Add([]*types.Transaction{newTx}, false)
	if errs[0] != nil {
		t.Fatalf("expected bumped same-nonce replacement to be accepted, got: %v", errs[0])
	}
	if pool.Has(oldTx.Hash()) {
		t.Fatal("old transaction remained after replacement")
	}
	if !pool.Has(newTx.Hash()) {
		t.Fatal("replacement transaction missing from pool")
	}
	if pending, _ := pool.Stats(); pending != 1 {
		t.Fatalf("expected one pending tx after replacement, got %d", pending)
	}
}

func TestFramePoolNonceCheck(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.SetNonce(sender, 5, tracing.NonceChangeUnspecified)

	// Nonce too low.
	ftx := baseFTX(sender, 4, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}
	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for nonce too low")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestFramePoolDefaultFrameSkipsValidation(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Target uses TIMESTAMP — would trigger OP-011 ban if run through VERIFY validation,
	// but DEFAULT frames are pre-executed without the ERC-7562 validation tracer attached.
	// DEFAULT frames must still succeed execution; they just aren't subject to opcode rules.
	statedb.CreateAccount(target)
	statedb.SetCode(target, timestampThenReturnCode, tracing.CodeChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}}, // VERIFY on sender (valid)
		{Mode: types.FrameModeDefault, Target: &target, GasLimit: 50000, Data: []byte{0x01}},      // DEFAULT on target (no opcode restrictions)
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] != nil {
		t.Fatalf("expected acceptance (DEFAULT frames exempt from ERC-7562 opcode rules), got: %v", errs[0])
	}
}

func TestFramePoolClear(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0x01}},
	}
	pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)

	pool.Clear()

	if pending, _ := pool.Stats(); pending != 0 {
		t.Fatalf("expected 0 pending after Clear, got %d", pending)
	}
}

// --- Frame ordering tests (pre-simulation) ---

func TestFrameOrderingEmptyFrames(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	if err := validateFrameOrdering(nil, sender); err == nil {
		t.Fatal("expected rejection for empty frames")
	}
}

func TestFrameOrderingInvalidMode(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	frames := []types.Frame{{Mode: 3, GasLimit: 50000}}
	if err := validateFrameOrdering(frames, sender); err == nil {
		t.Fatal("expected rejection for invalid mode")
	}
}

func TestFrameOrderingNoVerify(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	frames := []types.Frame{
		{Mode: types.FrameModeDefault, Target: &target, GasLimit: 50000},
		{Mode: types.FrameModeSender, Target: &target, GasLimit: 50000},
	}
	if err := validateFrameOrdering(frames, sender); err == nil {
		t.Fatal("expected rejection for no VERIFY frame")
	}
}

func TestFrameOrderingSenderBeforeVerify(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	frames := []types.Frame{
		{Mode: types.FrameModeSender, Target: &target, GasLimit: 50000},
		{Mode: types.FrameModeVerify, Target: nil, GasLimit: 50000}, // targets sender
	}
	if err := validateFrameOrdering(frames, sender); err == nil {
		t.Fatal("expected rejection for SENDER before VERIFY(sender)")
	}
}

func TestFrameOrderingSenderAfterVerify(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Target: nil, GasLimit: 50000}, // targets sender
		{Mode: types.FrameModeSender, Target: &target, GasLimit: 50000},
	}
	if err := validateFrameOrdering(frames, sender); err != nil {
		t.Fatalf("expected acceptance, got: %v", err)
	}
}

func TestFrameOrderingSenderAfterNonSenderVerify(t *testing.T) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	other := common.HexToAddress("0x2222222222222222222222222222222222222222")
	target := common.HexToAddress("0x3333333333333333333333333333333333333333")
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Target: &other, GasLimit: 50000}, // targets other, not sender
		{Mode: types.FrameModeSender, Target: &target, GasLimit: 50000},
	}
	if err := validateFrameOrdering(frames, sender); err == nil {
		t.Fatal("expected rejection for SENDER after VERIFY(other) without VERIFY(sender)")
	}
}

// --- Scope ordering tests (post-simulation, integration) ---

func TestScopeOrderingExecThenPay(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	target := common.HexToAddress("0x3333333333333333333333333333333333333333")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(payer, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: []byte{0x01}},    // sender → exec
		{Mode: types.FrameModeVerify, Flags: 1, Target: &payer, GasLimit: 50000, Data: []byte{0x01}}, // payer → pay
		{Mode: types.FrameModeDefault, Target: &target, GasLimit: 50000, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] != nil {
		t.Fatalf("expected acceptance for exec→pay ordering, got: %v", errs[0])
	}
}

func TestFramePoolNonCanonicalPaymasterPendingLimit(t *testing.T) {
	pool, statedb, config := newTestEnv()

	senderA := common.HexToAddress("0x1111111111111111111111111111111111111111")
	senderB := common.HexToAddress("0x2222222222222222222222222222222222222222")
	payer := common.HexToAddress("0x3333333333333333333333333333333333333333")
	for _, sender := range []common.Address{senderA, senderB} {
		statedb.CreateAccount(sender)
		statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
		statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	}
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(payer, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	makeTx := func(sender common.Address, data byte) *types.Transaction {
		ftx := baseFTX(sender, 0, config)
		ftx.Frames = []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 40000, Data: []byte{data}},
			{Mode: types.FrameModeVerify, Flags: 1, Target: &payer, GasLimit: 40000, Data: []byte{data + 1}},
		}
		return makeFrameTx(ftx)
	}
	errs := pool.Add([]*types.Transaction{makeTx(senderA, 0x01)}, false)
	if errs[0] != nil {
		t.Fatalf("first non-canonical paymaster tx rejected: %v", errs[0])
	}
	errs = pool.Add([]*types.Transaction{makeTx(senderB, 0x03)}, false)
	if errs[0] == nil {
		t.Fatal("expected second pending tx using same non-canonical paymaster to be rejected")
	}
}

func TestFramePoolCanonicalPaymasterAllowsMultiplePending(t *testing.T) {
	pool, statedb, config := newTestEnv()

	senderA := common.HexToAddress("0x1111111111111111111111111111111111111111")
	senderB := common.HexToAddress("0x2222222222222222222222222222222222222222")
	payer := common.HexToAddress("0x3333333333333333333333333333333333333333")
	for _, sender := range []common.Address{senderA, senderB} {
		statedb.CreateAccount(sender)
		statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
		statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	}
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(payer, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	originalHash := canonicalPaymasterCodeHash
	canonicalPaymasterCodeHash = crypto.Keccak256Hash(approvePayCode)
	t.Cleanup(func() { canonicalPaymasterCodeHash = originalHash })

	makeTx := func(sender common.Address, data byte) *types.Transaction {
		ftx := baseFTX(sender, 0, config)
		ftx.Frames = []types.Frame{
			{Mode: types.FrameModeVerify, Flags: 2, GasLimit: 40000, Data: []byte{data}},
			{Mode: types.FrameModeVerify, Flags: 1, Target: &payer, GasLimit: 40000, Data: []byte{data + 1}},
		}
		return makeFrameTx(ftx)
	}
	for _, tx := range []*types.Transaction{makeTx(senderA, 0x01), makeTx(senderB, 0x03)} {
		if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
			t.Fatalf("canonical paymaster transaction rejected: %v", err)
		}
	}
}

func TestFramePoolCanonicalPaymasterBypassesVerifyOpcodeRules(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	canonicalCode := []byte{0x42, 0x50, 0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0xaa}

	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, canonicalCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(payer, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	originalHash := canonicalPaymasterCodeHash
	canonicalPaymasterCodeHash = crypto.Keccak256Hash(canonicalCode)
	t.Cleanup(func() { canonicalPaymasterCodeHash = originalHash })

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 2, GasLimit: 40000, Data: []byte{0x01}},
		{Mode: types.FrameModeVerify, Flags: 1, Target: &payer, GasLimit: 40000, Data: []byte{0x02}},
	}
	if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err != nil {
		t.Fatalf("canonical paymaster with TIMESTAMP rejected: %v", err)
	}
}

func TestFramePoolCanonicalPaymasterReservesPendingWithdrawal(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)

	originalHash := canonicalPaymasterCodeHash
	canonicalPaymasterCodeHash = crypto.Keccak256Hash(approvePayCode)
	t.Cleanup(func() { canonicalPaymasterCodeHash = originalHash })

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 2, GasLimit: 40000, Data: []byte{0x01}},
		{Mode: types.FrameModeVerify, Flags: 1, Target: &payer, GasLimit: 40000, Data: []byte{0x02}},
	}
	tx := makeFrameTx(ftx)
	maxCost := tx.Cost()
	balance := new(big.Int).Add(maxCost, big.NewInt(100))
	statedb.SetBalance(payer, uint256.MustFromBig(balance), tracing.BalanceChangeUnspecified)
	statedb.SetState(payer, canonicalPaymasterPendingWithdrawalSlot, common.BigToHash(big.NewInt(101)))

	err := pool.Add([]*types.Transaction{tx}, false)[0]
	if err == nil || !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("expected pending withdrawal solvency rejection, got %v", err)
	}
}

func TestScopeOrderingPayBeforeExec(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 1, Target: &payer, GasLimit: 50000, Data: []byte{0x01}}, // payer → pay (before exec!)
		{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: []byte{0x01}},    // sender → exec
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for payment before execution approval")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestScopeOrderingDoublePayer(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payerA := common.HexToAddress("0x2222222222222222222222222222222222222222")
	payerB := common.HexToAddress("0x3333333333333333333333333333333333333333")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(payerA)
	statedb.SetCode(payerA, approvePayCode, tracing.CodeChangeUnspecified)
	statedb.CreateAccount(payerB)
	statedb.SetCode(payerB, approvePayCode, tracing.CodeChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: []byte{0x01}},     // sender → exec
		{Mode: types.FrameModeVerify, Flags: 1, Target: &payerA, GasLimit: 50000, Data: []byte{0x01}}, // payerA → pay
		{Mode: types.FrameModeVerify, Flags: 1, Target: &payerB, GasLimit: 50000, Data: []byte{0x01}}, // payerB → pay (duplicate!)
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for duplicate payer")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestScopeOrderingBothAfterExec(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	conditionalApproveCode := []byte{
		0x60, 0x00, 0x35, 0x15, // PUSH1 0, CALLDATALOAD, ISZERO
		0x60, 0x0f, 0x57, // PUSH1 0x0f, JUMPI
		0x60, 0x02, 0x60, 0x00, 0x60, 0x00, 0xaa, 0x00, // non-zero calldata: APPROVE(0x2), STOP
		0x5b,                                     // JUMPDEST @15
		0x60, 0x03, 0x60, 0x00, 0x60, 0x00, 0xaa, // empty calldata: APPROVE(0x3)
	}
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, conditionalApproveCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000,
			Data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, // sender → exec
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: nil}, // sender → both after exec
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for ApproveBoth after separate execution approval")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestScopeOrderingNoPayer(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: []byte{0x01}}, // sender → exec only
		{Mode: types.FrameModeDefault, Target: &target, GasLimit: 50000, Data: []byte{0x01}},
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for no payer approved")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

// TestApproveCallerNonSenderExec tests the new EIP-8141 APPROVE CALLER check:
// a non-sender target calling APPROVE(0x2) should be rejected because
// execution approval requires ADDRESS == tx.sender.
func TestApproveCallerNonSenderExec(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified) // APPROVE(0x2) — valid from sender
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, approveExecCode, tracing.CodeChangeUnspecified) // APPROVE(0x2) — payer tries exec approval

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: []byte{0x01}},    // sender → exec
		{Mode: types.FrameModeVerify, Flags: 2, Target: &payer, GasLimit: 50000, Data: []byte{0x01}}, // payer → exec (ADDRESS != sender)
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection: non-sender target cannot APPROVE(0x2)")
	}
	t.Logf("correctly rejected: %v", errs[0])
}

func TestScopeOrderingExecReApproval(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: []byte{0x01}}, // sender → exec
		{Mode: types.FrameModeVerify, Flags: 2, Target: nil, GasLimit: 50000, Data: []byte{0x02}}, // sender → exec again!
	}

	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for execution re-approval")
	}
	t.Logf("correctly rejected: %v", errs[0])
}
