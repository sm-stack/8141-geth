// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func newNonceKeyTestEnv(t *testing.T, senderLimit, poolLimit int) (*FramePool, common.Address, *params.ChainConfig) {
	t.Helper()
	config := DefaultConfig
	config.MaxPendingPerSender = senderLimit
	config.MaxPoolSize = poolLimit
	pool, statedb, chainConfig := newTestEnvWithConfig(config)
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	return pool, sender, chainConfig
}

func nonceKeyTestTx(sender common.Address, keys []uint64, seq uint64, price uint64, data byte, config *params.ChainConfig) *types.Transaction {
	frameTx := baseFTX(sender, seq, config)
	frameTx.NonceKeys = make([]*uint256.Int, len(keys))
	for i, key := range keys {
		frameTx.NonceKeys[i] = uint256.NewInt(key)
	}
	frameTx.GasTipCap = uint256.NewInt(price)
	frameTx.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) * price)
	frameTx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment | types.FrameFlagApproveExecution, GasLimit: 60_000, Data: []byte{data}}}
	return makeFrameTx(frameTx)
}

func TestFramePoolAcceptsDisjointNonceKeysThroughSenderLimit(t *testing.T) {
	pool, sender, config := newNonceKeyTestEnv(t, 2, 16)
	first := nonceKeyTestTx(sender, []uint64{1}, 0, 1, 0x01, config)
	second := nonceKeyTestTx(sender, []uint64{2}, 0, 1, 0x02, config)
	if errs := pool.Add([]*types.Transaction{first, second}, false); errs[0] != nil || errs[1] != nil {
		t.Fatalf("disjoint admissions failed: %v", errs)
	}

	signatureBefore := signatureRunMeter.Snapshot().Count()
	verifyBefore := verifyRunMeter.Snapshot().Count()
	third := nonceKeyTestTx(sender, []uint64{3}, 0, 1, 0x03, config)
	if err := pool.Add([]*types.Transaction{third}, false)[0]; !errors.Is(err, txpool.ErrAccountLimitExceeded) {
		t.Fatalf("sender-limit error = %v, want %v", err, txpool.ErrAccountLimitExceeded)
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("signature runs before sender-limit rejection = %d, want 0", delta)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("VERIFY runs before sender-limit rejection = %d, want 0", delta)
	}
	if pending, _ := pool.Stats(); pending != 2 {
		t.Fatalf("pending transactions = %d, want 2", pending)
	}
	assertNonceKeyOwner(t, pool, first, true)
	assertNonceKeyOwner(t, pool, second, true)
}

func TestFramePoolRejectsOverlappingNonceKeysBeforeValidation(t *testing.T) {
	pool, sender, config := newNonceKeyTestEnv(t, 4, 16)
	first := nonceKeyTestTx(sender, []uint64{1, 2}, 0, 1, 0x01, config)
	if err := pool.Add([]*types.Transaction{first}, false)[0]; err != nil {
		t.Fatalf("initial admission failed: %v", err)
	}

	signatureBefore := signatureRunMeter.Snapshot().Count()
	verifyBefore := verifyRunMeter.Snapshot().Count()
	overlap := nonceKeyTestTx(sender, []uint64{2, 3}, 0, 1, 0x02, config)
	if err := pool.Add([]*types.Transaction{overlap}, false)[0]; !errors.Is(err, txpool.ErrAccountLimitExceeded) {
		t.Fatalf("overlap error = %v, want %v", err, txpool.ErrAccountLimitExceeded)
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("signature runs before overlap rejection = %d, want 0", delta)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("VERIFY runs before overlap rejection = %d, want 0", delta)
	}
	assertNonceKeyOwner(t, pool, first, true)
}

func TestFramePoolReplacesExactNonceKeySet(t *testing.T) {
	pool, sender, config := newNonceKeyTestEnv(t, 4, 16)
	original := nonceKeyTestTx(sender, []uint64{1, 2}, 0, 1, 0x01, config)
	if err := pool.Add([]*types.Transaction{original}, false)[0]; err != nil {
		t.Fatalf("initial admission failed: %v", err)
	}
	underpriced := nonceKeyTestTx(sender, []uint64{1, 2}, 0, 1, 0x02, config)
	if err := pool.Add([]*types.Transaction{underpriced}, false)[0]; !errors.Is(err, txpool.ErrReplaceUnderpriced) {
		t.Fatalf("underpriced replacement error = %v, want %v", err, txpool.ErrReplaceUnderpriced)
	}
	assertNonceKeyOwner(t, pool, original, true)

	replacement := nonceKeyTestTx(sender, []uint64{1, 2}, 0, 2, 0x03, config)
	if err := pool.Add([]*types.Transaction{replacement}, false)[0]; err != nil {
		t.Fatalf("replacement failed: %v", err)
	}
	if pool.Has(original.Hash()) || !pool.Has(replacement.Hash()) {
		t.Fatal("exact nonce-key replacement was not atomic")
	}
	if pending, _ := pool.Stats(); pending != 1 {
		t.Fatalf("pending transactions = %d, want 1", pending)
	}
	assertNonceKeyOwner(t, pool, original, false)
	assertNonceKeyOwner(t, pool, replacement, true)

	differentSequence := nonceKeyTestTx(sender, []uint64{1, 2}, 1, 3, 0x04, config)
	pool.mu.Lock()
	_, _, err := pool.checkNonceKeyAdmission(differentSequence.GetFrameTx())
	pool.mu.Unlock()
	if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
		t.Fatalf("different-sequence overlap error = %v, want %v", err, txpool.ErrAccountLimitExceeded)
	}
}

func TestFramePoolLegacyNonceDomainRemainsExclusive(t *testing.T) {
	for _, test := range []struct {
		name       string
		firstKeys  []uint64
		secondKeys []uint64
	}{
		{name: "legacy then keyed", firstKeys: []uint64{0}, secondKeys: []uint64{1}},
		{name: "keyed then legacy", firstKeys: []uint64{1}, secondKeys: []uint64{0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, sender, config := newNonceKeyTestEnv(t, 4, 16)
			first := nonceKeyTestTx(sender, test.firstKeys, 0, 1, 0x01, config)
			if err := pool.Add([]*types.Transaction{first}, false)[0]; err != nil {
				t.Fatalf("initial admission failed: %v", err)
			}
			second := nonceKeyTestTx(sender, test.secondKeys, 0, 1, 0x02, config)
			if err := pool.Add([]*types.Transaction{second}, false)[0]; !errors.Is(err, txpool.ErrAccountLimitExceeded) {
				t.Fatalf("legacy exclusivity error = %v, want %v", err, txpool.ErrAccountLimitExceeded)
			}
			assertNonceKeyOwner(t, pool, first, true)
		})
	}
}

func TestFramePoolNonceKeyIndexFollowsRemovalAndClear(t *testing.T) {
	pool, sender, config := newNonceKeyTestEnv(t, 2, 16)
	first := nonceKeyTestTx(sender, []uint64{1}, 0, 1, 0x01, config)
	second := nonceKeyTestTx(sender, []uint64{2}, 0, 2, 0x02, config)
	if errs := pool.Add([]*types.Transaction{first, second}, false); errs[0] != nil || errs[1] != nil {
		t.Fatalf("initial admissions failed: %v", errs)
	}

	pool.SetGasTip(big.NewInt(2))
	assertNonceKeyOwner(t, pool, first, false)
	assertNonceKeyOwner(t, pool, second, true)
	reused := nonceKeyTestTx(sender, []uint64{1}, 0, 2, 0x03, config)
	if err := pool.Add([]*types.Transaction{reused}, false)[0]; err != nil {
		t.Fatalf("released nonce key could not be reused: %v", err)
	}

	pool.Clear()
	if len(pool.nonceKeyOwner) != 0 {
		t.Fatalf("nonce-key owners remain after clear: %v", pool.nonceKeyOwner)
	}
}

func TestFramePoolEvictionReleasesNonceKeys(t *testing.T) {
	pool, sender, config := newNonceKeyTestEnv(t, 2, 2)
	secondSender := common.HexToAddress("0x2222222222222222222222222222222222222222")
	pool.currentState.CreateAccount(secondSender)
	pool.currentState.SetCode(secondSender, approveBothCode, tracing.CodeChangeUnspecified)
	pool.currentState.SetBalance(secondSender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	thirdSender := common.HexToAddress("0x3333333333333333333333333333333333333333")
	pool.currentState.CreateAccount(thirdSender)
	pool.currentState.SetCode(thirdSender, approveBothCode, tracing.CodeChangeUnspecified)
	pool.currentState.SetBalance(thirdSender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	lowest := nonceKeyTestTx(sender, []uint64{1}, 0, 1, 0x01, config)
	if err := pool.Add([]*types.Transaction{lowest}, false)[0]; err != nil {
		t.Fatalf("lowest-priced admission failed: %v", err)
	}
	second := nonceKeyTestTx(secondSender, []uint64{1}, 0, 3, 0x02, config)
	if err := pool.Add([]*types.Transaction{second}, false)[0]; err != nil {
		t.Fatalf("second admission failed: %v", err)
	}
	third := nonceKeyTestTx(thirdSender, []uint64{1}, 0, 2, 0x03, config)
	if err := pool.Add([]*types.Transaction{third}, false)[0]; err != nil {
		t.Fatalf("evicting admission failed: %v", err)
	}
	if pool.Has(lowest.Hash()) {
		t.Fatal("lowest-priced transaction was not evicted")
	}
	assertNonceKeyOwner(t, pool, lowest, false)
}

func TestFramePoolResetEvictsOnlyConsumedNonceKey(t *testing.T) {
	pool, sender, config := newNonceKeyTestEnv(t, 2, 16)
	first := nonceKeyTestTx(sender, []uint64{1}, 0, 1, 0x01, config)
	second := nonceKeyTestTx(sender, []uint64{2}, 0, 1, 0x02, config)
	if errs := pool.Add([]*types.Transaction{first, second}, false); errs[0] != nil || errs[1] != nil {
		t.Fatalf("initial admissions failed: %v", errs)
	}

	chain := pool.chain.(*testChain)
	oldHead := chain.head
	newHead := types.CopyHeader(oldHead)
	newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHead.Time = oldHead.Time + params.SecondsPerSlot
	nextState := pool.currentState.Copy()
	key := uint256.NewInt(1)
	nextState.SetState(params.NonceManagerAddress, types.NonceManagerSlot(sender, key), common.BigToHash(big.NewInt(1)))
	chain.statedb = nextState
	chain.head = newHead
	pool.Reset(oldHead, newHead)

	if pool.Has(first.Hash()) || !pool.Has(second.Hash()) {
		t.Fatal("reset did not evict only the consumed nonce-key transaction")
	}
	assertNonceKeyOwner(t, pool, first, false)
	assertNonceKeyOwner(t, pool, second, true)
}

func TestFramePoolReorgRebuildsNonceKeyIndex(t *testing.T) {
	pool, sender, config := newNonceKeyTestEnv(t, 2, 16)
	tx := nonceKeyTestTx(sender, []uint64{9}, 0, 1, 0x01, config)
	parent := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), Extra: []byte("parent")})
	oldBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("old"),
		GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee), Difficulty: new(big.Int),
	}).WithBody(types.Body{Transactions: types.Transactions{tx}})
	newBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("new"),
		GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee), Difficulty: new(big.Int),
	})
	chain := pool.chain.(*testChain)
	for _, block := range []*types.Block{parent, oldBlock, newBlock} {
		chain.blocks[block.Hash()] = block
	}

	pool.Reset(oldBlock.Header(), newBlock.Header())
	if !pool.Has(tx.Hash()) {
		t.Fatal("discarded keyed transaction was not reinjected")
	}
	assertNonceKeyOwner(t, pool, tx, true)
}

func TestFramePoolReorgRejectsOverlappingNonceKeys(t *testing.T) {
	pool, sender, config := newNonceKeyTestEnv(t, 2, 16)
	pooled := nonceKeyTestTx(sender, []uint64{1, 2}, 0, 1, 0x01, config)
	if err := pool.Add([]*types.Transaction{pooled}, false)[0]; err != nil {
		t.Fatalf("pooled transaction rejected: %v", err)
	}
	overlap := nonceKeyTestTx(sender, []uint64{2, 3}, 0, 2, 0x02, config)
	parent := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), Extra: []byte("parent")})
	oldBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("old"),
		GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee), Difficulty: new(big.Int),
	}).WithBody(types.Body{Transactions: types.Transactions{overlap}})
	newBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("new"),
		GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee), Difficulty: new(big.Int),
	})
	chain := pool.chain.(*testChain)
	for _, block := range []*types.Block{parent, oldBlock, newBlock} {
		chain.blocks[block.Hash()] = block
	}

	pool.Reset(oldBlock.Header(), newBlock.Header())
	if !pool.Has(pooled.Hash()) || pool.Has(overlap.Hash()) {
		t.Fatal("reorg admitted a transaction overlapping an existing nonce key")
	}
	assertNonceKeyOwner(t, pool, pooled, true)
}

func TestFramePoolConcurrentNonceKeyAdmissionsRespectSenderLimit(t *testing.T) {
	const senderLimit = 4
	pool, sender, config := newNonceKeyTestEnv(t, senderLimit, 16)
	txs := make([]*types.Transaction, senderLimit*2)
	for i := range txs {
		txs[i] = nonceKeyTestTx(sender, []uint64{uint64(i + 1)}, 0, 1, byte(i+1), config)
	}

	start := make(chan struct{})
	errs := make([]error, len(txs))
	var wg sync.WaitGroup
	for i, tx := range txs {
		wg.Add(1)
		go func(index int, tx *types.Transaction) {
			defer wg.Done()
			<-start
			errs[index] = pool.Add([]*types.Transaction{tx}, false)[0]
		}(i, tx)
	}
	close(start)
	wg.Wait()

	accepted := 0
	for _, err := range errs {
		if err == nil {
			accepted++
		} else if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
			t.Fatalf("concurrent admission error = %v, want sender limit", err)
		}
	}
	if accepted != senderLimit {
		t.Fatalf("accepted transactions = %d, want %d", accepted, senderLimit)
	}
	pending := pool.pending[sender]
	owners := pool.nonceKeyOwner[sender]
	if len(pending) != senderLimit || len(owners) != senderLimit {
		t.Fatalf("final sender state: pending=%d owners=%d want=%d", len(pending), len(owners), senderLimit)
	}
	for _, tx := range pending {
		assertNonceKeyOwner(t, pool, tx, true)
	}
}

func TestFramePoolConcurrentOverlappingNonceKeyAdmissions(t *testing.T) {
	pool, sender, config := newNonceKeyTestEnv(t, 4, 16)
	txs := []*types.Transaction{
		nonceKeyTestTx(sender, []uint64{1, 2}, 0, 1, 0x01, config),
		nonceKeyTestTx(sender, []uint64{2, 3}, 0, 1, 0x02, config),
	}
	start := make(chan struct{})
	errs := make([]error, len(txs))
	var wg sync.WaitGroup
	for i, tx := range txs {
		wg.Add(1)
		go func(index int, tx *types.Transaction) {
			defer wg.Done()
			<-start
			errs[index] = pool.Add([]*types.Transaction{tx}, false)[0]
		}(i, tx)
	}
	close(start)
	wg.Wait()

	accepted, rejected := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, txpool.ErrAccountLimitExceeded):
			rejected++
		default:
			t.Fatalf("concurrent overlap admission error = %v", err)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("concurrent overlap results: accepted=%d rejected=%d, want 1 each", accepted, rejected)
	}
	if pending, _ := pool.Stats(); pending != 1 {
		t.Fatalf("pending transactions = %d, want 1", pending)
	}
	if owners := pool.nonceKeyOwner[sender]; len(owners) != 2 {
		t.Fatalf("nonce-key owner count = %d, want 2", len(owners))
	}
}

func assertNonceKeyOwner(t *testing.T, pool *FramePool, tx *types.Transaction, want bool) {
	t.Helper()
	frameTx := tx.GetFrameTx()
	for _, key := range frameTx.NonceKeys {
		owner, ok := pool.nonceKeyOwner[frameTx.Sender][nonceKeyID(key)]
		if want && (!ok || owner != tx.Hash()) {
			t.Fatalf("nonce key %x owner = %s, want %s", key.Bytes32(), owner, tx.Hash())
		}
		if !want && ok && owner == tx.Hash() {
			t.Fatalf("nonce key %x is still owned by %s", key.Bytes32(), owner)
		}
	}
}
