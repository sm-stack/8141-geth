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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// --- Test helpers ---

// testChain implements BlockChain for tests.
type testChain struct {
	config  *params.ChainConfig
	statedb *state.StateDB
	head    *types.Header
	blocks  map[common.Hash]*types.Block
}

func (c *testChain) Config() *params.ChainConfig                      { return c.config }
func (c *testChain) CurrentBlock() *types.Header                      { return c.head }
func (c *testChain) GetBlock(hash common.Hash, _ uint64) *types.Block { return c.blocks[hash] }
func (c *testChain) StateAt(*types.Header) (*state.StateDB, error)    { return c.statedb, nil }

// reserver implements txpool.Reserver for tests.
type reserver struct {
	lock     sync.Mutex
	accounts map[common.Address]struct{}
}

func newReserver() *reserver {
	return &reserver{accounts: make(map[common.Address]struct{})}
}

func TestSlotProviderUsesHeaderSlotNumber(t *testing.T) {
	pool, _, _ := newTestEnv()
	slot := uint64(8272)
	head := &types.Header{Time: 120, SlotNumber: &slot}
	if got := pool.slotProvider(head).CurrentSlot(); got != slot {
		t.Fatalf("current slot = %d, want %d", got, slot)
	}
}

func (r *reserver) Hold(addr common.Address) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, exists := r.accounts[addr]; exists {
		return errors.New("address already reserved")
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
	configCopy := *params.MergedTestChainConfig
	zero := uint64(0)
	configCopy.AmsterdamTime = &zero
	configCopy.BogotaTime = &zero
	config := &configCopy
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
		blocks:  make(map[common.Hash]*types.Block),
	}

	pool := New(chain)
	pool.canonicalPaymasters[benchmarkPaymasterAuthShimCodeHash] = benchmarkPaymasterPendingWithdrawalSlot
	pool.Init(0, head, newReserver())
	return pool, statedb, config
}

// makeFrameTx creates a wrapped *types.Transaction from a FrameTx.
func makeFrameTx(ftx *types.FrameTx) *types.Transaction {
	return types.NewTx(ftx)
}

func TestBlobFrameNetworkEncoding(t *testing.T) {
	pool, _, config := newTestEnv()
	defer pool.Close()

	var (
		blob       kzg4844.Blob
		commitment kzg4844.Commitment
		proofs     = make([]kzg4844.Proof, kzg4844.CellProofsPerBlob)
	)
	ftx := baseFTX(common.Address{0x01}, 0, config)
	ftx.BlobFeeCap = uint256.NewInt(1)
	ftx.BlobHashes = []common.Hash{kzg4844.CalcBlobHashV1(sha256.New(), &commitment)}
	ftx.Frames = []types.Frame{{Value: new(uint256.Int)}}
	tx := makeFrameTx(ftx).WithBlobTxSidecar(types.NewBlobTxSidecar(
		types.BlobSidecarVersion1,
		[]kzg4844.Blob{blob},
		[]kzg4844.Commitment{commitment},
		proofs,
	))
	pool.all[tx.Hash()] = tx

	meta := pool.GetMetadata(tx.Hash())
	if meta == nil || meta.SizeWithoutBlob == 0 || meta.SizeWithoutBlob >= meta.Size {
		t.Fatalf("invalid blob frame metadata: %#v", meta)
	}
	for _, test := range []struct {
		version   uint
		wantBlobs int
		wantSize  uint64
	}{
		{version: 71, wantBlobs: 1, wantSize: meta.Size},
		{version: 72, wantBlobs: 0, wantSize: meta.SizeWithoutBlob},
	} {
		var got types.Transaction
		encoded := pool.GetRLP(tx.Hash(), test.version)
		if err := rlp.DecodeBytes(encoded, &got); err != nil {
			t.Fatalf("decode ETH/%d transaction: %v", test.version, err)
		}
		if got.Hash() != tx.Hash() {
			t.Fatalf("ETH/%d transaction hash changed: have %s want %s", test.version, got.Hash(), tx.Hash())
		}
		if blobs := len(got.BlobTxSidecar().Blobs); blobs != test.wantBlobs {
			t.Fatalf("ETH/%d blob count %d, want %d", test.version, blobs, test.wantBlobs)
		}
		if size := uint64(len(encoded)); size != test.wantSize {
			t.Fatalf("ETH/%d encoded size %d, want %d", test.version, size, test.wantSize)
		}
	}
}

func TestFramePoolRejectsInvalidBlobProofs(t *testing.T) {
	pool, statedb, config := newTestEnv()
	var zero uint64
	pool.currentHead.ExcessBlobGas = &zero
	pool.currentHead.BlobGasUsed = &zero
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	var (
		blob       kzg4844.Blob
		commitment kzg4844.Commitment
		proofs     = make([]kzg4844.Proof, kzg4844.CellProofsPerBlob)
	)
	ftx := baseFTX(sender, 0, config)
	ftx.BlobFeeCap = uint256.NewInt(1)
	ftx.BlobHashes = []common.Hash{kzg4844.CalcBlobHashV1(sha256.New(), &commitment)}
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}
	tx := makeFrameTx(ftx).WithBlobTxSidecar(types.NewBlobTxSidecar(
		types.BlobSidecarVersion1,
		[]kzg4844.Blob{blob},
		[]kzg4844.Commitment{commitment},
		proofs,
	))
	signatureBefore := signatureRunMeter.Snapshot().Count()
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; !errors.Is(err, txpool.ErrKZGVerificationError) {
		t.Fatalf("invalid blob proof error: have %v want %v", err, txpool.ErrKZGVerificationError)
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("signature validations before KZG rejection: have %d want 0", delta)
	}
}

func TestFramePoolValidatesSignaturesOutsideValidationLock(t *testing.T) {
	pool, statedb, config := newTestEnv()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}
	addFramePoolEOASignature(ftx, config.ChainID, key)
	tx := makeFrameTx(ftx)

	pool.validationMu.Lock()
	validationLocked := true
	defer func() {
		if validationLocked {
			pool.validationMu.Unlock()
		}
	}()

	signatureBefore := signatureRunMeter.Snapshot().Count()
	result := make(chan error, 1)
	go func() {
		result <- pool.Add([]*types.Transaction{tx}, false)[0]
	}()

	deadline := time.NewTimer(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for signatureRunMeter.Snapshot().Count() == signatureBefore {
		select {
		case err := <-result:
			t.Fatalf("admission returned before acquiring validation lock: %v", err)
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("signature validation did not run outside validation lock")
		}
	}

	// Change a cheap state dependency after the advisory preflight. Admission
	// must repeat the check after acquiring validationMu and reject stale work.
	pool.mu.Lock()
	statedb.SetNonce(sender, 1, tracing.NonceChangeUnspecified)
	pool.mu.Unlock()
	pool.validationMu.Unlock()
	validationLocked = false

	select {
	case err := <-result:
		if !errors.Is(err, core.ErrNonceTooLow) {
			t.Fatalf("post-signature state recheck error: have %v want %v", err, core.ErrNonceTooLow)
		}
	case <-time.After(time.Second):
		t.Fatal("admission did not resume after validation lock release")
	}
}

func TestFramePoolBoundsConcurrentSignatureValidation(t *testing.T) {
	pool, statedb, config := newTestEnv()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}
	addFramePoolEOASignature(ftx, config.ChainID, key)
	tx := makeFrameTx(ftx)

	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	pool.signatureValidationSlots = slots
	slotHeld := true
	defer func() {
		if slotHeld {
			<-slots
		}
	}()

	signatureBefore := signatureRunMeter.Snapshot().Count()
	result := make(chan error, 1)
	go func() {
		result <- pool.Add([]*types.Transaction{tx}, false)[0]
	}()

	select {
	case err := <-result:
		t.Fatalf("admission bypassed occupied signature slot: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("signature validations with no available slot: have %d want 0", delta)
	}

	<-slots
	slotHeld = false
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("admission after signature slot release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("admission did not resume after signature slot release")
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 1 {
		t.Fatalf("signature validations after slot release: have %d want 1", delta)
	}
}

func TestFramePoolRejectsMalformedBlobBeforeKZG(t *testing.T) {
	pool, _, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	var (
		blob       kzg4844.Blob
		commitment kzg4844.Commitment
		proofs     = make([]kzg4844.Proof, kzg4844.CellProofsPerBlob)
	)
	ftx := baseFTX(sender, 0, config)
	ftx.BlobFeeCap = uint256.NewInt(1)
	ftx.BlobHashes = []common.Hash{kzg4844.CalcBlobHashV1(sha256.New(), &commitment)}
	ftx.Frames = []types.Frame{{Mode: types.FrameModeSender, GasLimit: 50_000}}
	tx := makeFrameTx(ftx).WithBlobTxSidecar(types.NewBlobTxSidecar(
		types.BlobSidecarVersion1,
		[]kzg4844.Blob{blob},
		[]kzg4844.Commitment{commitment},
		proofs,
	))
	err := pool.Add([]*types.Transaction{tx}, false)[0]
	if err == nil || !strings.Contains(err.Error(), "SENDER frame before any VERIFY") {
		t.Fatalf("malformed blob frame error: have %v", err)
	}
	if errors.Is(err, txpool.ErrKZGVerificationError) {
		t.Fatalf("malformed blob frame reached KZG verification: %v", err)
	}
}

func TestFramePoolCachesBlobCells(t *testing.T) {
	pool, statedb, config := newTestEnv()
	var zero uint64
	pool.currentHead.ExcessBlobGas = &zero
	pool.currentHead.BlobGasUsed = &zero
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	var blob kzg4844.Blob
	commitment, err := kzg4844.BlobToCommitment(&blob)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := kzg4844.ComputeCellProofs(&blob)
	if err != nil {
		t.Fatal(err)
	}
	ftx := baseFTX(sender, 0, config)
	ftx.BlobFeeCap = uint256.NewInt(1)
	ftx.BlobHashes = []common.Hash{kzg4844.CalcBlobHashV1(sha256.New(), &commitment)}
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}
	tx := makeFrameTx(ftx).WithBlobTxSidecar(types.NewBlobTxSidecar(
		types.BlobSidecarVersion1,
		[]kzg4844.Blob{blob},
		[]kzg4844.Commitment{commitment},
		proofs,
	))
	preflightBefore := preflightRunMeter.Snapshot().Count()
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("add blob frame transaction: %v", err)
	}
	if delta := preflightRunMeter.Snapshot().Count() - preflightBefore; delta != 1 {
		t.Fatalf("metered payer preflight runs: have %d want 1", delta)
	}
	mask := types.NewCustodyBitmap([]uint64{1})
	indices := mask.Indices()
	cells := pool.GetCells(tx.Hash(), mask)
	if len(cells) != len(indices) {
		t.Fatalf("cached cell count = %d, want %d", len(cells), len(indices))
	}
	knownWithInvalidProofs := tx.WithBlobTxSidecar(types.NewBlobTxSidecar(
		types.BlobSidecarVersion1,
		[]kzg4844.Blob{blob},
		[]kzg4844.Commitment{commitment},
		make([]kzg4844.Proof, kzg4844.CellProofsPerBlob),
	))
	if err := pool.Add([]*types.Transaction{knownWithInvalidProofs}, false)[0]; !errors.Is(err, txpool.ErrAlreadyKnown) {
		t.Fatalf("known blob frame error: have %v want %v", err, txpool.ErrAlreadyKnown)
	}
}

func TestFramePoolFullSelectsLowestPricedEviction(t *testing.T) {
	pool, statedb, config := newTestEnv()
	for i := 0; i < maxFramePoolSize; i++ {
		sender := common.BigToAddress(big.NewInt(int64(i + 1)))
		ftx := baseFTX(sender, 0, config)
		ftx.GasTipCap = uint256.NewInt(uint64(i + 1))
		ftx.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) + uint64(i+1))
		pool.all[makeFrameTx(ftx).Hash()] = makeFrameTx(ftx)
	}

	sender := common.HexToAddress("0xffff")
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	candidate := baseFTX(sender, 0, config)
	candidate.GasTipCap = uint256.NewInt(2)
	candidate.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) * 2)
	candidate.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}

	pool.mu.Lock()
	check, err := pool.checkAdmissionCheap(makeFrameTx(candidate), false)
	pool.mu.Unlock()
	if err != nil {
		t.Fatalf("higher-priced transaction rejected from full pool: %v", err)
	}
	if check.eviction == nil || check.eviction.GasTipCap().Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("eviction = %v, want lowest tip transaction", check.eviction)
	}
	evictedHash := check.eviction.Hash()

	candidate.GasTipCap = uint256.NewInt(1)
	candidate.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) + 1)
	pool.mu.Lock()
	_, err = pool.checkAdmissionCheap(makeFrameTx(candidate), false)
	pool.mu.Unlock()
	if !errors.Is(err, txpool.ErrUnderpriced) {
		t.Fatalf("underpriced full-pool admission error = %v", err)
	}

	candidate.GasTipCap = uint256.NewInt(2)
	candidate.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) * 2)
	candidateTx := makeFrameTx(candidate)
	if err := pool.Add([]*types.Transaction{candidateTx}, false)[0]; err != nil {
		t.Fatalf("add replacement for lowest-priced pool entry: %v", err)
	}
	if pool.Has(evictedHash) || !pool.Has(candidateTx.Hash()) {
		t.Fatal("full-pool admission did not atomically replace the lowest-priced entry")
	}
	if pending, _ := pool.Stats(); pending != 1 || len(pool.all) != maxFramePoolSize {
		t.Fatalf("pool sizes after eviction: pending=%d all=%d", pending, len(pool.all))
	}
}

// baseFTX returns a valid FrameTx skeleton for the given sender.
func baseFTX(sender common.Address, nonce uint64, config *params.ChainConfig) *types.FrameTx {
	return &types.FrameTx{
		ChainID:    uint256.NewInt(config.ChainID.Uint64()),
		NonceKeys:  []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:   nonce,
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

func createFactoryCode(runtime []byte) []byte {
	if len(runtime) == 0 || len(runtime) > 32 {
		panic("test runtime must contain 1..32 bytes")
	}
	initCode := append([]byte{byte(vm.PUSH1) + byte(len(runtime)) - 1}, runtime...)
	initCode = append(initCode,
		byte(vm.PUSH1), 0x00, byte(vm.MSTORE),
		byte(vm.PUSH1), byte(len(runtime)), byte(vm.PUSH1), byte(32-len(runtime)), byte(vm.RETURN),
	)
	prefix := []byte{
		byte(vm.PUSH1), byte(len(initCode)), byte(vm.PUSH1), 0x10, byte(vm.PUSH1), 0x00, byte(vm.CODECOPY),
		byte(vm.PUSH1), byte(len(initCode)), byte(vm.PUSH1), 0x00, byte(vm.PUSH1), 0x00, byte(vm.CREATE), byte(vm.POP), byte(vm.STOP),
	}
	return append(prefix, initCode...)
}

type fixedFramePoolSlotProvider uint64

func (p fixedFramePoolSlotProvider) CurrentSlot() uint64 { return uint64(p) }

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

// addFramePoolDefaultCodeSponsorSignatures installs the two protocol signatures
// expected by a contract sender with an EOA payment target. The payment default
// code reads signature index 1; both descriptors must be present before SigHash
// is computed because the signature list itself is hash-committed.
func addFramePoolDefaultCodeSponsorSignatures(ftx *types.FrameTx, chainID *big.Int, key *ecdsa.PrivateKey) {
	if len(ftx.Signatures) != 0 {
		panic("default-code sponsor test helper requires an empty signature list")
	}
	signer := crypto.PubkeyToAddress(key.PublicKey)
	ftx.Signatures = []types.TxSignature{
		{Scheme: types.SignatureSchemeSecp256k1, Signer: signer},
		{Scheme: types.SignatureSchemeSecp256k1, Signer: signer},
	}
	sigHash := ftx.SigHash(chainID)
	sig, err := crypto.Sign(sigHash[:], key)
	if err != nil {
		panic(err)
	}
	vrs := make([]byte, 65)
	vrs[0] = sig[64]
	copy(vrs[1:33], sig[0:32])
	copy(vrs[33:65], sig[32:64])
	for i := range ftx.Signatures {
		ftx.Signatures[i].Signature = common.CopyBytes(vrs)
	}
}

func addFramePoolSplitDefaultCodeSignatures(ftx *types.FrameTx, chainID *big.Int, senderKey, payerKey *ecdsa.PrivateKey) {
	if len(ftx.Signatures) != 0 {
		panic("split default-code test helper requires an empty signature list")
	}
	keys := []*ecdsa.PrivateKey{senderKey, payerKey}
	ftx.Signatures = make([]types.TxSignature, len(keys))
	for i, key := range keys {
		ftx.Signatures[i] = types.TxSignature{
			Scheme: types.SignatureSchemeSecp256k1,
			Signer: crypto.PubkeyToAddress(key.PublicKey),
		}
	}
	sigHash := ftx.SigHash(chainID)
	for i, key := range keys {
		sig, err := crypto.Sign(sigHash[:], key)
		if err != nil {
			panic(err)
		}
		vrs := make([]byte, 65)
		vrs[0] = sig[64]
		copy(vrs[1:33], sig[0:32])
		copy(vrs[33:65], sig[32:64])
		ftx.Signatures[i].Signature = vrs
	}
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

	directBefore := directVerifyRunMeter.Snapshot().Count()
	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] != nil {
		t.Fatalf("expected EOA default VERIFY with tx-level signature to be accepted, got: %v", errs[0])
	}
	if delta := directVerifyRunMeter.Snapshot().Count() - directBefore; delta != 1 {
		t.Fatalf("direct default-code evaluations: have %d want 1", delta)
	}
}

func TestFramePoolDirectEvaluatesSplitDefaultCodePrefix(t *testing.T) {
	pool, statedb, config := newTestEnv()
	senderKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	payerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)
	payer := crypto.PubkeyToAddress(payerKey.PublicKey)
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetBalance(payer, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000},
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &payer, GasLimit: 40_000},
	}
	addFramePoolSplitDefaultCodeSignatures(ftx, config.ChainID, senderKey, payerKey)
	tx := makeFrameTx(ftx)
	directBefore := directVerifyRunMeter.Snapshot().Count()
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("split default-code prefix rejected: %v", err)
	}
	if delta := directVerifyRunMeter.Snapshot().Count() - directBefore; delta != 1 {
		t.Fatalf("direct default-code evaluations: have %d want 1", delta)
	}
	meta := pool.meta[tx.Hash()]
	if meta.payer != payer || !meta.usesPaymaster || meta.nonCanonicalPaymaster {
		t.Fatalf("split default-code payer metadata: %+v", meta)
	}
	if meta.validationDeps == nil || meta.validationDeps.legacyNonce == nil || meta.validationDeps.senderBalance == nil {
		t.Fatalf("split default-code sender-existence dependencies: %+v", meta.validationDeps)
	}
	wantBalance := common.Hash(statedb.GetBalance(sender).Bytes32())
	if *meta.validationDeps.legacyNonce != statedb.GetNonce(sender) || *meta.validationDeps.senderBalance != wantBalance {
		t.Fatalf("split default-code sender-existence dependency values: %+v", meta.validationDeps)
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

	signatureBefore := signatureRunMeter.Snapshot().Count()
	verifyBefore := verifyRunMeter.Snapshot().Count()
	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection for explicit-msg tx-level signature")
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("signature validations before default-code descriptor rejection: have %d want 0", delta)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("VERIFY evaluations before default-code descriptor rejection: have %d want 0", delta)
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
		{Mode: types.FrameModeVerify, Target: &expiry, GasLimit: 40_000, Data: expiryFrameData(pool.currentHead.Time + 12)},
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

func TestFramePoolRejectsExpiryVerifierOutsideFirstFrame(t *testing.T) {
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
		{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 40_000},
		{Mode: types.FrameModeVerify, Target: &expiry, GasLimit: 40_000, Data: expiryFrameData(pool.currentHead.Time + 12)},
	}
	if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err == nil {
		t.Fatal("expiry verifier outside first frame accepted")
	}
}

func TestFramePoolCountsExpiryGasAgainstVerifyBudget(t *testing.T) {
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
		{Mode: types.FrameModeVerify, Target: &expiry, GasLimit: 50_001, Data: expiryFrameData(pool.currentHead.Time + 12)},
		{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000},
	}
	if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err == nil {
		t.Fatal("expiry gas was excluded from validation budget")
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
		{Mode: types.FrameModeVerify, Target: &expiry, GasLimit: 40_000, Data: expiryFrameData(pool.currentHead.Time + 12)},
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

func TestFramePoolResetDoesNotHoldPoolLockDuringValidation(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}
	tx := makeFrameTx(ftx)
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("add frame transaction: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	pool.slotProvider = func(head *types.Header) vm.SlotProvider {
		once.Do(func() {
			close(entered)
			<-release
		})
		return vm.TimestampSlotProvider{Timestamp: head.Time}
	}
	newHead := types.CopyHeader(pool.currentHead)
	newHead.Time++
	done := make(chan struct{})
	go func() {
		pool.Reset(pool.currentHead, newHead)
		close(done)
	}()
	<-entered

	read := make(chan *types.Transaction, 1)
	go func() { read <- pool.Get(tx.Hash()) }()
	select {
	case got := <-read:
		close(release)
		<-done
		if got == nil {
			t.Fatal("transaction disappeared while reset validation was in progress")
		}
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("pool read blocked on reset validation")
	}
}

func TestFramePoolResetReinjectsTransactionFromDiscardedBranch(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}
	tx := makeFrameTx(ftx)
	parent := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), Extra: []byte("parent")})
	oldBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("old"),
		GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee), Difficulty: big.NewInt(0),
	}).WithBody(types.Body{Transactions: types.Transactions{tx}})
	newBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("new"),
		GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee), Difficulty: big.NewInt(0),
	})
	chain := pool.chain.(*testChain)
	for _, block := range []*types.Block{parent, oldBlock, newBlock} {
		chain.blocks[block.Hash()] = block
	}

	pool.Reset(oldBlock.Header(), newBlock.Header())
	if !pool.Has(tx.Hash()) {
		t.Fatal("transaction from discarded branch was not reinjected")
	}
}

func TestFramePoolReorgSubscription(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}
	tx := makeFrameTx(ftx)
	parent := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), Extra: []byte("parent")})
	oldBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("old"),
		GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee), Difficulty: big.NewInt(0),
	}).WithBody(types.Body{Transactions: types.Transactions{tx}})
	newBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("new"),
		GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee), Difficulty: big.NewInt(0),
	})
	chain := pool.chain.(*testChain)
	for _, block := range []*types.Block{parent, oldBlock, newBlock} {
		chain.blocks[block.Hash()] = block
	}

	newTxs := make(chan core.NewTxsEvent, 1)
	allTxs := make(chan core.NewTxsEvent, 1)
	newSub := pool.SubscribeTransactions(newTxs, false)
	defer newSub.Unsubscribe()
	allSub := pool.SubscribeTransactions(allTxs, true)
	defer allSub.Unsubscribe()

	pool.Reset(oldBlock.Header(), newBlock.Header())
	select {
	case event := <-allTxs:
		if len(event.Txs) != 1 || event.Txs[0].Hash() != tx.Hash() {
			t.Fatalf("unexpected reorg event: %v", event.Txs)
		}
	case <-time.After(time.Second):
		t.Fatal("reorg subscriber did not receive reinjected transaction")
	}
	select {
	case event := <-newTxs:
		t.Fatalf("new-only subscriber received reorg event: %v", event.Txs)
	default:
	}
}

func TestFramePoolResetReinjectsBlobTransactionFromDiscardedBranch(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	var (
		blob kzg4844.Blob
		zero uint64
	)
	commitment, err := kzg4844.BlobToCommitment(&blob)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := kzg4844.ComputeCellProofs(&blob)
	if err != nil {
		t.Fatal(err)
	}
	pool.currentHead.ExcessBlobGas = &zero
	pool.currentHead.BlobGasUsed = &zero
	ftx := baseFTX(sender, 0, config)
	ftx.BlobFeeCap = uint256.NewInt(1)
	ftx.BlobHashes = []common.Hash{kzg4844.CalcBlobHashV1(sha256.New(), &commitment)}
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}
	tx := makeFrameTx(ftx).WithBlobTxSidecar(types.NewBlobTxSidecar(
		types.BlobSidecarVersion1,
		[]kzg4844.Blob{blob},
		[]kzg4844.Commitment{commitment},
		proofs,
	))
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("add blob frame transaction: %v", err)
	}

	parent := types.NewBlockWithHeader(pool.currentHead)
	oldBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("old"),
		GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee), Difficulty: big.NewInt(0),
		ExcessBlobGas: &zero, BlobGasUsed: &zero,
	}).WithBody(types.Body{Transactions: types.Transactions{tx.WithoutBlobTxSidecar()}})
	newBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("new"),
		GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee), Difficulty: big.NewInt(0),
		ExcessBlobGas: &zero, BlobGasUsed: &zero,
	})
	chain := pool.chain.(*testChain)
	for _, block := range []*types.Block{parent, oldBlock, newBlock} {
		chain.blocks[block.Hash()] = block
	}

	statedb.SetNonce(sender, 1, tracing.NonceChangeUnspecified)
	pool.Reset(parent.Header(), oldBlock.Header())
	if pool.Has(tx.Hash()) {
		t.Fatal("mined blob frame transaction remained pending")
	}
	statedb.SetNonce(sender, 0, tracing.NonceChangeUnspecified)
	pool.Reset(oldBlock.Header(), newBlock.Header())
	reinjected := pool.Get(tx.Hash())
	if reinjected == nil || reinjected.BlobTxSidecar() == nil || len(reinjected.BlobTxSidecar().Blobs) != 1 {
		t.Fatal("blob frame transaction from discarded branch was not reinjected with its sidecar")
	}
}

func TestFramePoolAcceptsKeyedNonceDomain(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.NonceKeys = []*uint256.Int{uint256.NewInt(101)}
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50000}}
	if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err != nil {
		t.Fatalf("keyed nonce rejected: %v", err)
	}
}

func setupRecentRootFrameTx(t *testing.T, currentSlot, refSlot uint64) (*FramePool, *state.StateDB, *types.FrameTx, types.RecentRootRef) {
	t.Helper()
	pool, statedb, config := newTestEnv()
	pool.currentHead.Time = currentSlot * params.SecondsPerSlot
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	ref := types.RecentRootRef{SourceID: common.HexToHash("0x1234"), Slot: refSlot, Root: common.HexToHash("0x5678")}
	key := types.RecentRootStorageKey(ref.SourceID, ref.Slot)
	statedb.SetState(params.RecentRootAddress, key, types.RecentRootEntryHash(ref.SourceID, ref.Slot, ref.Root))
	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50_000}}
	ftx.RecentRootRefs = []types.RecentRootRef{ref}
	return pool, statedb, ftx, ref
}

func TestFramePoolRecentRootAdmission(t *testing.T) {
	t.Skip("recent-root references were removed from the latest EIP-8141 draft")
	const currentSlot = uint64(9000)
	tests := []struct {
		name   string
		slot   uint64
		mutate func(*types.RecentRootRef)
		valid  bool
	}{
		{name: "previous slot", slot: currentSlot - 1, valid: true},
		{name: "oldest usable", slot: currentSlot - 8191, valid: true},
		{name: "same slot", slot: currentSlot},
		{name: "future slot", slot: currentSlot + 1},
		{name: "expired", slot: currentSlot - 8192},
		{name: "wrong root", slot: currentSlot - 1, mutate: func(ref *types.RecentRootRef) { ref.Root[0] ^= 0xff }},
		{name: "wrong source", slot: currentSlot - 1, mutate: func(ref *types.RecentRootRef) { ref.SourceID[0] ^= 0xff }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, statedb, ftx, ref := setupRecentRootFrameTx(t, currentSlot, tt.slot)
			if tt.mutate != nil {
				tt.mutate(&ftx.RecentRootRefs[0])
			}
			err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]
			if tt.valid && err != nil {
				t.Fatalf("valid reference rejected: %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("invalid reference accepted")
			}
			key := types.RecentRootStorageKey(ref.SourceID, ref.Slot)
			if addressWarm, slotWarm := statedb.SlotInAccessList(params.RecentRootAddress, key); addressWarm || slotWarm {
				t.Fatal("framepool validation polluted current state access list")
			}
		})
	}
}

func TestFramePoolRecentRootAdmissionUsesSlotProvider(t *testing.T) {
	t.Skip("recent-root references were removed from the latest EIP-8141 draft")
	pool, _, ftx, _ := setupRecentRootFrameTx(t, 1, 8999)
	pool.slotProvider = func(*types.Header) vm.SlotProvider { return fixedFramePoolSlotProvider(9000) }
	if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err != nil {
		t.Fatalf("reference valid under injected slot provider rejected: %v", err)
	}
}

func TestWarmRecentRootReferences(t *testing.T) {
	t.Skip("recent-root references were removed from the latest EIP-8141 draft")
	_, statedb, _, ref := setupRecentRootFrameTx(t, 9000, 8999)
	copyState := statedb.Copy()
	warmRecentRootReferences(copyState, []types.RecentRootRef{ref})
	key := types.RecentRootStorageKey(ref.SourceID, ref.Slot)
	if addressWarm, slotWarm := copyState.SlotInAccessList(params.RecentRootAddress, key); !addressWarm || !slotWarm {
		t.Fatalf("recent-root access not warmed: address=%v slot=%v", addressWarm, slotWarm)
	}
	if addressWarm, slotWarm := statedb.SlotInAccessList(params.RecentRootAddress, key); addressWarm || slotWarm {
		t.Fatal("warming simulation copy affected original state")
	}
}

func TestFramePoolRecentRootResetRevalidation(t *testing.T) {
	t.Skip("recent-root references were removed from the latest EIP-8141 draft")
	const currentSlot = uint64(9000)
	t.Run("expiry", func(t *testing.T) {
		pool, _, ftx, ref := setupRecentRootFrameTx(t, currentSlot, currentSlot-1)
		if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err != nil {
			t.Fatal(err)
		}
		newHead := *pool.currentHead
		newHead.Time = (ref.Slot + params.RecentRootWindow) * params.SecondsPerSlot
		pool.Reset(pool.currentHead, &newHead)
		if pending, _ := pool.Stats(); pending != 0 {
			t.Fatalf("expired tx retained: %d", pending)
		}
	})
	t.Run("reorg mismatch", func(t *testing.T) {
		pool, statedb, ftx, ref := setupRecentRootFrameTx(t, currentSlot, currentSlot-1)
		if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err != nil {
			t.Fatal(err)
		}
		statedb.SetState(params.RecentRootAddress, types.RecentRootStorageKey(ref.SourceID, ref.Slot), common.Hash{})
		newHead := *pool.currentHead
		pool.Reset(pool.currentHead, &newHead)
		if pending, _ := pool.Stats(); pending != 0 {
			t.Fatalf("mismatched tx retained: %d", pending)
		}
	})
}

func TestFramePoolInvalidRecentRootReplacementKeepsOriginal(t *testing.T) {
	t.Skip("recent-root references were removed from the latest EIP-8141 draft")
	const currentSlot = uint64(9000)
	pool, _, ftx, _ := setupRecentRootFrameTx(t, currentSlot, currentSlot-1)
	original := makeFrameTx(ftx)
	if err := pool.Add([]*types.Transaction{original}, false)[0]; err != nil {
		t.Fatal(err)
	}
	replacement := types.NewTx(ftx).GetFrameTx()
	replacement.GasTipCap = uint256.NewInt(2)
	replacement.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) * 2)
	replacement.RecentRootRefs[0].Root[0] ^= 0xff
	if err := pool.Add([]*types.Transaction{makeFrameTx(replacement)}, false)[0]; err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if !pool.Has(original.Hash()) {
		t.Fatal("valid original was removed")
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

func TestFramePoolPrivacyProofVerifyGasBudget(t *testing.T) {
	pool, statedb, config := newTestEnv()
	pool.verifyGasCap = 500_000

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 400_000, Data: []byte{0x01}},
	}

	if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err != nil {
		t.Fatalf("expected 400k privacy-proof VERIFY budget to be accepted, got: %v", err)
	}
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

	signatureBefore := signatureRunMeter.Snapshot().Count()
	verifyBefore := verifyRunMeter.Snapshot().Count()
	errs := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)
	if errs[0] == nil {
		t.Fatal("expected rejection when signature gas pushes validation prefix above MAX_VERIFY_GAS")
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("protocol signature validations before prefix gas rejection: have %d want 0", delta)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("VERIFY runs before prefix gas rejection: have %d want 0", delta)
	}
}

func TestFramePoolRejectsVerifyStateGasBeforeCryptographicValidation(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Signatures = []types.TxSignature{{
		Scheme:    types.SignatureSchemeSecp256k1,
		Signer:    sender,
		Signature: make([]byte, 65),
	}}
	ftx.Frames = []types.Frame{{
		Mode:          types.FrameModeVerify,
		Flags:         types.FrameFlagApproveExecution | types.FrameFlagApprovePayment,
		GasLimit:      40_000,
		StateGasLimit: params.FrameTxMaxVerifyStateGas + 1,
	}}

	signatureBefore := signatureRunMeter.Snapshot().Count()
	verifyBefore := verifyRunMeter.Snapshot().Count()
	err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]
	if err == nil || !strings.Contains(err.Error(), "validation prefix state gas") {
		t.Fatalf("validation prefix state-gas error: have %v", err)
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("protocol signature validations before state-gas rejection: have %d want 0", delta)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("VERIFY runs before state-gas rejection: have %d want 0", delta)
	}
}

func TestFramePoolCountsPayFrameInUpfrontVerifyBudget(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000},
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &payer, GasLimit: PublicMaxVerifyGas - 40_000 + 1},
	}

	verifyBefore := verifyRunMeter.Snapshot().Count()
	err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]
	if err == nil || !strings.Contains(err.Error(), "validation prefix gas") {
		t.Fatalf("split validation prefix gas error: have %v", err)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("VERIFY runs before complete prefix gas rejection: have %d want 0", delta)
	}
}

func TestFramePoolRejectsSignatureGasBeforeCryptographicValidation(t *testing.T) {
	pool, _, config := newTestEnv()
	ftx := baseFTX(common.HexToAddress("0x1111111111111111111111111111111111111111"), 0, config)
	for range 15 {
		ftx.Signatures = append(ftx.Signatures, types.TxSignature{
			Scheme:    types.SignatureSchemeP256,
			Signature: make([]byte, 64), // Invalid, but the aggregate gas cap must win first.
		})
	}
	_, err := pool.validateFrameSignatures(ftx)
	if err == nil || !strings.Contains(err.Error(), "signature validation gas") {
		t.Fatalf("expected signature gas cap error before cryptographic validation, got %v", err)
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
	t.Run("reject_noop_deploy_for_existing_sender", func(t *testing.T) {
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
		if errs[0] == nil || !strings.Contains(errs[0].Error(), "code-less sender") {
			t.Fatalf("expected noop deploy for existing sender to be rejected, got: %v", errs[0])
		}
	})

	t.Run("reject_noop_deploy_for_existing_sender_with_paymaster", func(t *testing.T) {
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
		if errs[0] == nil || !strings.Contains(errs[0].Error(), "code-less sender") {
			t.Fatalf("expected noop deploy for existing sender to be rejected, got: %v", errs[0])
		}
	})

	t.Run("deploy_sender_then_verify", func(t *testing.T) {
		pool, statedb, config := newTestEnv()
		factory := common.HexToAddress("0x2222222222222222222222222222222222222222")
		sender := crypto.CreateAddress(factory, 0)
		statedb.CreateAccount(sender)
		statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
		statedb.CreateAccount(factory)
		statedb.SetCode(factory, createFactoryCode(approveBothCode), tracing.CodeChangeUnspecified)

		ftx := baseFTX(sender, 0, config)
		ftx.Frames = []types.Frame{
			{Mode: types.FrameModeDefault, Target: &factory, GasLimit: 60_000},
			{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 30_000},
		}
		if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err != nil {
			t.Fatalf("expected sender deployment followed by VERIFY to pass: %v", err)
		}
	})
}

func TestFramePoolReusableValidationStateRevertsDeploy(t *testing.T) {
	pool, statedb, config := newTestEnv()
	factory := common.HexToAddress("0x2222222222222222222222222222222222222222")
	sender := crypto.CreateAddress(factory, 0)
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(factory)
	statedb.SetCode(factory, createFactoryCode(approveBothCode), tracing.CodeChangeUnspecified)

	frameTx := baseFTX(sender, 0, config)
	frameTx.Frames = []types.Frame{
		{Mode: types.FrameModeDefault, Target: &factory, GasLimit: 60_000},
		{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 30_000},
	}
	view := pool.validationViewLocked()
	factoryNonce := view.currentState.GetNonce(factory)
	assertReverted := func(phase string) {
		t.Helper()
		if code := view.currentState.GetCode(sender); len(code) != 0 {
			t.Fatalf("%s left sender code in reusable state: %x", phase, code)
		}
		if nonce := view.currentState.GetNonce(factory); nonce != factoryNonce {
			t.Fatalf("%s left factory nonce in reusable state: have %d want %d", phase, nonce, factoryNonce)
		}
	}

	failed := *frameTx
	failed.Frames = append([]types.Frame(nil), frameTx.Frames...)
	failed.Frames[0].GasLimit = 1
	if _, _, err := view.simulateVerifyFramesWithSignatureGasOutcome(makeFrameTx(&failed), 0); err == nil {
		t.Fatal("expected underfunded deploy validation to fail")
	}
	assertReverted("failed validation")

	transaction := makeFrameTx(frameTx)
	for attempt := range 2 {
		if _, _, err := view.simulateVerifyFramesWithSignatureGasOutcome(transaction, 0); err != nil {
			t.Fatalf("validation attempt %d failed: %v", attempt, err)
		}
		assertReverted(fmt.Sprintf("validation attempt %d", attempt))
	}
}

func TestFramePoolAdmissionReusesValidationState(t *testing.T) {
	pool, statedb, config := newTestEnv()
	factory := common.HexToAddress("0x2222222222222222222222222222222222222222")
	sender := crypto.CreateAddress(factory, 0)
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(factory)
	statedb.SetCode(factory, createFactoryCode(approveBothCode), tracing.CodeChangeUnspecified)
	secondSender := common.HexToAddress("0x3333333333333333333333333333333333333333")
	statedb.CreateAccount(secondSender)
	statedb.SetCode(secondSender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(secondSender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	frameTx := baseFTX(sender, 0, config)
	frameTx.Frames = []types.Frame{
		{Mode: types.FrameModeDefault, Target: &factory, GasLimit: 60_000},
		{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 30_000},
	}
	failed := *frameTx
	failed.Frames = append([]types.Frame(nil), frameTx.Frames...)
	failed.Frames[0].GasLimit = 1
	if err := pool.Add([]*types.Transaction{makeFrameTx(&failed)}, false)[0]; err == nil {
		t.Fatal("expected underfunded deploy admission to fail")
	}
	validationState := pool.admissionValidationState
	if validationState == nil {
		t.Fatal("failed admission did not initialize reusable validation state")
	}
	factoryNonce := validationState.GetNonce(factory)
	assertReverted := func(phase string) {
		t.Helper()
		if code := validationState.GetCode(sender); len(code) != 0 {
			t.Fatalf("%s left sender code in reusable admission state: %x", phase, code)
		}
		if nonce := validationState.GetNonce(factory); nonce != factoryNonce {
			t.Fatalf("%s left factory nonce in reusable admission state: have %d want %d", phase, nonce, factoryNonce)
		}
	}
	assertReverted("failed validation")

	if err := pool.Add([]*types.Transaction{makeFrameTx(frameTx)}, false)[0]; err != nil {
		t.Fatalf("valid deploy admission failed: %v", err)
	}
	if pool.admissionValidationState != validationState {
		t.Fatal("valid admission replaced reusable validation state")
	}
	assertReverted("successful validation")

	second := baseFTX(secondSender, 0, config)
	second.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 30_000}}
	if err := pool.Add([]*types.Transaction{makeFrameTx(second)}, false)[0]; err != nil {
		t.Fatalf("second admission failed: %v", err)
	}
	if pool.admissionValidationState != validationState {
		t.Fatal("second admission replaced reusable validation state")
	}
}

func TestFramePoolResetInvalidatesAdmissionValidationState(t *testing.T) {
	pool, statedb, config := newTestEnv()
	firstSender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(firstSender)
	statedb.SetCode(firstSender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(firstSender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	first := baseFTX(firstSender, 0, config)
	first.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 30_000}}
	if err := pool.Add([]*types.Transaction{makeFrameTx(first)}, false)[0]; err != nil {
		t.Fatalf("first admission failed: %v", err)
	}
	oldValidationState := pool.admissionValidationState
	if oldValidationState == nil {
		t.Fatal("first admission did not initialize reusable validation state")
	}

	secondSender := common.HexToAddress("0x2222222222222222222222222222222222222222")
	nextState := pool.currentState.Copy()
	nextState.CreateAccount(secondSender)
	nextState.SetCode(secondSender, approveBothCode, tracing.CodeChangeUnspecified)
	nextState.SetBalance(secondSender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	chain := pool.chain.(*testChain)
	oldHead := chain.head
	newHead := types.CopyHeader(oldHead)
	newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHead.Time = oldHead.Time + params.SecondsPerSlot
	chain.statedb = nextState
	chain.head = newHead
	pool.Reset(oldHead, newHead)
	if pool.admissionValidationState != nil {
		t.Fatal("reset retained the previous head's admission validation state")
	}

	second := baseFTX(secondSender, 0, config)
	second.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 30_000}}
	if err := pool.Add([]*types.Transaction{makeFrameTx(second)}, false)[0]; err != nil {
		t.Fatalf("post-reset admission failed: %v", err)
	}
	if pool.admissionValidationState == nil || pool.admissionValidationState == oldValidationState {
		t.Fatal("post-reset admission did not create a new validation state")
	}
}

func TestFramePoolRejectsVerifyAfterValidationPrefix(t *testing.T) {
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
	if errs[0] == nil {
		t.Fatal("expected VERIFY after self-validation prefix to be rejected")
	}
}

func TestFramePoolSenderLimit(t *testing.T) {
	pool, statedb, config := newTestEnv()

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000},
	}
	if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err != nil {
		t.Fatalf("first tx: unexpected error: %v", err)
	}

	// The next one should be rejected.
	second := baseFTX(sender, 1, config)
	second.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 3, Target: nil, GasLimit: 50000, Data: []byte{0xff}},
	}
	errs := pool.Add([]*types.Transaction{makeFrameTx(second)}, false)
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

	differentDomain := baseFTX(sender, 0, config)
	differentDomain.NonceKeys = []*uint256.Int{uint256.NewInt(1)}
	differentDomain.GasTipCap = uint256.NewInt(2)
	differentDomain.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) * 2)
	differentDomain.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 50000, Data: []byte{0x04}}}
	differentDomainTx := makeFrameTx(differentDomain)
	if err := pool.Add([]*types.Transaction{differentDomainTx}, false)[0]; err == nil {
		t.Fatal("different nonce domain accepted despite one-per-sender limit")
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
	if pool.Has(differentDomainTx.Hash()) {
		t.Fatal("rejected different nonce domain transaction entered pool")
	}
	if pending, _ := pool.Stats(); pending != 1 {
		t.Fatalf("expected one pending sender transaction after replacement, got %d", pending)
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

func TestValidateFrameKeyedNonce(t *testing.T) {
	_, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	key := uint256.NewInt(9)
	slot := types.NonceManagerSlot(sender, key)
	statedb.SetState(params.NonceManagerAddress, slot, common.BigToHash(big.NewInt(5)))

	ftx := baseFTX(sender, 5, config)
	ftx.NonceKeys = []*uint256.Int{key}
	if err := validateFrameNonce(ftx, statedb); err != nil {
		t.Fatalf("matching keyed nonce rejected: %v", err)
	}
	ftx.NonceSeq = 4
	if err := validateFrameNonce(ftx, statedb); !errors.Is(err, core.ErrNonceTooLow) {
		t.Fatalf("old keyed nonce error = %v, want nonce too low", err)
	}
	ftx.NonceSeq = 6
	if err := validateFrameNonce(ftx, statedb); !errors.Is(err, core.ErrNonceTooHigh) {
		t.Fatalf("future keyed nonce error = %v, want nonce too high", err)
	}
}

func TestFramePoolRejectsInsufficientKeyedNonceSurchargeGas(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.NonceKeys = []*uint256.Int{uint256.NewInt(1), uint256.NewInt(2)}
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 30_000}}
	verifyBefore := verifyRunMeter.Snapshot().Count()
	err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]
	if err == nil || !strings.Contains(err.Error(), "need at least 40000") {
		t.Fatalf("keyed nonce surcharge error = %v", err)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("VERIFY runs before keyed nonce gas-limit rejection: have %d want 0", delta)
	}
}

func TestFramePoolChecksKeyedNonceSurchargeAgainstPayFrame(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(payer, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.NonceKeys = []*uint256.Int{uint256.NewInt(1)}
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000},
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &payer, GasLimit: 10_000},
	}
	verifyBefore := verifyRunMeter.Snapshot().Count()
	err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]
	if err == nil || !strings.Contains(err.Error(), "payment VERIFY frame 1") {
		t.Fatalf("keyed nonce pay-frame surcharge error = %v", err)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("VERIFY runs before pay-frame surcharge rejection: have %d want 0", delta)
	}
}

func TestFramePoolSkipsFirstUseSurchargeForInitializedKey(t *testing.T) {
	pool, statedb, config := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	key := uint256.NewInt(1)
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.SetState(params.NonceManagerAddress, types.NonceManagerSlot(sender, key), common.BigToHash(big.NewInt(1)))

	ftx := baseFTX(sender, 1, config)
	ftx.NonceKeys = []*uint256.Int{key}
	ftx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: 3, GasLimit: 10_000}}
	if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err != nil {
		t.Fatalf("initialized keyed nonce rejected: %v", err)
	}
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
	for _, test := range []struct {
		name      string
		delegated bool
	}{
		{name: "contract"},
		{name: "eip7702-delegation", delegated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			if test.delegated {
				delegate := common.HexToAddress("0x4444444444444444444444444444444444444444")
				statedb.CreateAccount(delegate)
				statedb.SetCode(delegate, approvePayCode, tracing.CodeChangeUnspecified)
				statedb.SetCode(payer, types.AddressToDelegation(delegate), tracing.CodeChangeUnspecified)
			} else {
				statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)
			}
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
			if pending := pool.paymasterPending[payer]; pending != 1 {
				t.Fatalf("non-canonical payer pending accounting: have %d want 1", pending)
			}
		})
	}
}

func TestFramePoolDefaultCodeDoesNotFollowEmptyPayerDelegation(t *testing.T) {
	pool, statedb, config := newTestEnv()
	payerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := crypto.PubkeyToAddress(payerKey.PublicKey)
	delegate := common.HexToAddress("0x3333333333333333333333333333333333333333")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, types.AddressToDelegation(delegate), tracing.CodeChangeUnspecified)
	statedb.SetBalance(payer, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(delegate)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000},
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &payer, GasLimit: 40_000},
	}
	addFramePoolDefaultCodeSponsorSignatures(ftx, config.ChainID, payerKey)
	if err := pool.Add([]*types.Transaction{makeFrameTx(ftx)}, false)[0]; err == nil {
		t.Fatal("frame pool accepted default-code payment through an empty delegation target")
	}
	if pending, _ := pool.Stats(); pending != 0 {
		t.Fatalf("pending transactions after rejected delegated payer: have %d want 0", pending)
	}
}

func TestFramePoolDefaultCodeSponsorAllowsMultiplePending(t *testing.T) {
	pool, statedb, config := newTestEnv()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	payer := crypto.PubkeyToAddress(key.PublicKey)
	senders := []common.Address{
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
	}
	for _, sender := range senders {
		statedb.CreateAccount(sender)
		statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	}
	statedb.CreateAccount(payer)
	statedb.SetBalance(payer, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	for index, sender := range senders {
		ftx := baseFTX(sender, 0, config)
		ftx.Frames = []types.Frame{
			{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000, Data: []byte{byte(index + 1)}},
			{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &payer, GasLimit: 40_000},
		}
		addFramePoolDefaultCodeSponsorSignatures(ftx, config.ChainID, key)
		tx := makeFrameTx(ftx)
		if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
			t.Fatalf("default-code sponsor transaction %d rejected: %v", index, err)
		}
		meta := pool.meta[tx.Hash()]
		if !meta.usesPaymaster || meta.canonicalPaymaster || meta.nonCanonicalPaymaster {
			t.Fatalf("default-code sponsor metadata %d: %+v", index, meta)
		}
	}
	if pending, _ := pool.Stats(); pending != len(senders) {
		t.Fatalf("default-code sponsor pending transactions: have %d want %d", pending, len(senders))
	}
	if pending := pool.paymasterPending[payer]; pending != 0 {
		t.Fatalf("default-code sponsor non-canonical accounting: have %d want 0", pending)
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
