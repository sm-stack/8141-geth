// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

func TestValidationDependencyIndexDeduplicatesSharedCode(t *testing.T) {
	pool, statedb, _ := newTestEnv()
	helper := common.HexToAddress("0x7777777777777777777777777777777777777777")
	statedb.CreateAccount(helper)
	statedb.SetCode(helper, []byte{0x00}, tracing.CodeChangeUnspecified)
	helperCodeHash := statedb.GetCodeHash(helper)
	rules := pool.chainconfig.Rules(pool.currentHead.Number, pool.currentHead.Difficulty.Sign() == 0, pool.currentHead.Time)

	index := newValidationDependencyIndex()
	var hashes [2]common.Hash
	for i := range hashes {
		sender := massInvalidationSender(i)
		statedb.CreateAccount(sender)
		statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
		hashes[i] = common.BigToHash(big.NewInt(int64(i + 1)))
		index.add(hashes[i], sender, frameTxMeta{
			payer:         sender,
			payerCodeHash: statedb.GetCodeHash(sender),
			validationDeps: &validationDependencySnapshot{
				senderCodeHash: statedb.GetCodeHash(sender),
				rules:          rules,
				storageValues:  make(map[storageDependency]common.Hash),
				codeHashes:     map[common.Address]common.Hash{helper: helperCodeHash},
			},
		})
	}
	helperKey := validationDependencyKey{kind: validationCodeDependency, address: helper}
	entry := index.byKey[helperKey]
	if entry == nil || len(entry.dependents) != len(hashes) {
		t.Fatalf("shared helper posting: have %v want %d dependents", entry, len(hashes))
	}
	changes := index.changes(statedb)
	if len(changes.affected) != 0 || len(changes.indexed) != len(hashes) {
		t.Fatalf("unchanged index result: affected=%d indexed=%d", len(changes.affected), len(changes.indexed))
	}

	nextState := statedb.Copy()
	nextState.SetCode(helper, []byte{0x5b, 0x00}, tracing.CodeChangeUnspecified)
	changes = index.changes(nextState)
	for _, hash := range hashes {
		if _, ok := changes.affected[hash]; !ok {
			t.Fatalf("shared helper change did not affect %s", hash)
		}
	}

	index.remove(hashes[0])
	if entry := index.byKey[helperKey]; entry == nil || len(entry.dependents) != 1 {
		t.Fatalf("shared helper posting after removal: have %v want 1 dependent", entry)
	}
}

func TestValidationDependencyIndexFallsBackToSnapshot(t *testing.T) {
	fixture := newPayerCodeToggleFixture(t, 1, false)
	sender := massInvalidationSender(0)
	storageReadApproveCode := append([]byte{0x5f, 0x54, 0x50}, approveExecCode...)
	fixture.state.SetCode(sender, storageReadApproveCode, tracing.CodeChangeUnspecified)
	fixture.fill(t)
	tx := fixture.txs[0]

	// Simulate an incomplete acceleration index. The authoritative metadata is
	// intact, so reset must compare the transaction-local snapshot instead.
	delete(fixture.pool.dependencyIndex.byTx, tx.Hash())
	revalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
	resetWithStateChange(fixture.pool, fixture.chain, func(nextState *state.StateDB) {
		nextState.SetState(sender, common.Hash{}, common.HexToHash("0x01"))
	})
	if pending, _ := fixture.pool.Stats(); pending != 1 {
		t.Fatalf("pending after fallback revalidation: have %d want 1", pending)
	}
	if delta := resetRevalidatedMeter.Snapshot().Count() - revalidatedBefore; delta != 1 {
		t.Fatalf("fallback revalidations: have %d want 1", delta)
	}
	if _, ok := fixture.pool.dependencyIndex.byTx[tx.Hash()]; !ok {
		t.Fatal("retained transaction dependency index was not rebuilt")
	}
}

func TestValidationDependencyIndexFollowsPoolLifecycle(t *testing.T) {
	fixture := newPayerCodeToggleFixture(t, 1, false)
	fixture.fill(t)
	tx := fixture.txs[0]
	if _, ok := fixture.pool.dependencyIndex.byTx[tx.Hash()]; !ok {
		t.Fatal("admitted transaction was not indexed")
	}

	fixture.pool.removeTransaction(tx)
	if _, ok := fixture.pool.dependencyIndex.byTx[tx.Hash()]; ok {
		t.Fatal("removed transaction remains in forward dependency index")
	}
	for key, entry := range fixture.pool.dependencyIndex.byKey {
		if _, ok := entry.dependents[tx.Hash()]; ok {
			t.Fatalf("removed transaction remains in reverse dependency posting %v", key)
		}
	}
}

func TestValidationDependencyIndexRulesRemainAuthoritative(t *testing.T) {
	pool, _, _ := newTestEnv()
	frameTx := &types.FrameTx{Sender: common.HexToAddress("0x1111111111111111111111111111111111111111")}
	meta := frameTxMeta{validationDeps: &validationDependencySnapshot{rules: params.Rules{}}}
	changes := &validationDependencyChanges{
		affected: make(map[common.Hash]struct{}),
		indexed:  map[common.Hash]struct{}{common.Hash{}: {}},
	}
	if pool.validationDependenciesUnchangedIndexed(common.Hash{}, frameTx, meta, changes) {
		t.Fatal("reverse index bypassed a rules change")
	}
}
