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
	"github.com/ethereum/go-ethereum/core/types/bal"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func TestValidationDependencyIndexDeduplicatesSharedCode(t *testing.T) {
	pool, statedb, _ := newTestEnv()
	helper := common.HexToAddress("0x7777777777777777777777777777777777777777")
	statedb.CreateAccount(helper)
	statedb.SetCode(helper, []byte{0x00}, tracing.CodeChangeUnspecified)
	helperCodeHash := statedb.GetCodeHash(helper)
	simulationHead := framePoolSimulationHeader(pool.chainconfig, pool.currentHead)
	rules := pool.chainconfig.Rules(simulationHead.Number, simulationHead.Difficulty.Sign() == 0, simulationHead.Time)

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
	changes := index.changes(statedb, nil)
	if len(changes.affected) != 0 || len(changes.indexed) != len(hashes) {
		t.Fatalf("unchanged index result: affected=%d indexed=%d", len(changes.affected), len(changes.indexed))
	}

	nextState := statedb.Copy()
	nextState.SetCode(helper, []byte{0x5b, 0x00}, tracing.CodeChangeUnspecified)
	changes = index.changes(nextState, nil)
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

func TestValidationDependencyTouchesUseBALChanges(t *testing.T) {
	address := common.HexToAddress("0x4444444444444444444444444444444444444444")
	changedSlot := common.HexToHash("0x01")
	readSlot := common.HexToHash("0x02")
	construction := bal.NewConstructionBlockAccessList()
	construction.StorageWrite(1, address, changedSlot, common.HexToHash("0x03"))
	construction.StorageRead(address, readSlot)
	construction.BalanceChange(1, address, uint256.NewInt(1))
	construction.NonceChange(address, 1, 1)
	construction.CodeChange(address, 1, []byte{0x00})

	touches := newValidationDependencyTouches()
	touches.add(construction.ToEncodingObj())
	want := []validationDependencyKey{
		{kind: validationStorageDependency, address: address, slot: changedSlot},
		{kind: validationBalanceDependency, address: address},
		{kind: validationNonceDependency, address: address},
		{kind: validationCodeDependency, address: address},
		{kind: validationAccountExistenceDependency, address: address},
	}
	for _, key := range want {
		if _, ok := touches.keys[key]; !ok {
			t.Fatalf("BAL change missing dependency touch %v", key)
		}
	}
	readKey := validationDependencyKey{kind: validationStorageDependency, address: address, slot: readSlot}
	if _, ok := touches.keys[readKey]; ok {
		t.Fatal("read-only BAL slot incorrectly invalidated a dependency")
	}
}

func TestValidationDependencyIndexTracksDirectSenderBalance(t *testing.T) {
	pool, statedb, _ := newTestEnv()
	sender := common.HexToAddress("0x4444444444444444444444444444444444444444")
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	balance := common.Hash(statedb.GetBalance(sender).Bytes32())
	hash := common.HexToHash("0x01")
	index := newValidationDependencyIndex()
	simulationHead := framePoolSimulationHeader(pool.chainconfig, pool.currentHead)
	rules := pool.chainconfig.Rules(simulationHead.Number, simulationHead.Difficulty.Sign() == 0, simulationHead.Time)
	index.add(hash, sender, frameTxMeta{
		payer:         common.HexToAddress("0x5555555555555555555555555555555555555555"),
		payerCodeHash: types.EmptyCodeHash,
		validationDeps: &validationDependencySnapshot{
			senderCodeHash: types.EmptyCodeHash,
			senderBalance:  &balance,
			rules:          rules,
			storageValues:  make(map[storageDependency]common.Hash),
			codeHashes:     make(map[common.Address]common.Hash),
		},
	})

	nextState := statedb.Copy()
	nextState.SetBalance(sender, uint256.NewInt(2), tracing.BalanceChangeUnspecified)
	construction := bal.NewConstructionBlockAccessList()
	construction.BalanceChange(1, sender, uint256.NewInt(2))
	touches := newValidationDependencyTouches()
	touches.add(construction.ToEncodingObj())
	changes := index.changes(nextState, touches)
	if _, ok := changes.affected[hash]; !ok {
		t.Fatal("direct-evaluation sender balance change did not invalidate its transaction")
	}
}

func TestValidationDependencyIndexUsesBALTouches(t *testing.T) {
	pool, statedb, _ := newTestEnv()
	firstHelper := common.HexToAddress("0x5555555555555555555555555555555555555555")
	secondHelper := common.HexToAddress("0x6666666666666666666666666666666666666666")
	for _, helper := range []common.Address{firstHelper, secondHelper} {
		statedb.CreateAccount(helper)
		statedb.SetCode(helper, []byte{0x00}, tracing.CodeChangeUnspecified)
	}
	index := newValidationDependencyIndex()
	simulationHead := framePoolSimulationHeader(pool.chainconfig, pool.currentHead)
	rules := pool.chainconfig.Rules(simulationHead.Number, simulationHead.Difficulty.Sign() == 0, simulationHead.Time)
	var hashes [2]common.Hash
	for i, helper := range []common.Address{firstHelper, secondHelper} {
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
				codeHashes:     map[common.Address]common.Hash{helper: statedb.GetCodeHash(helper)},
			},
		}, validationDependencyKey{kind: validationBalanceDependency, address: sender})
	}

	nextState := statedb.Copy()
	nextState.SetCode(firstHelper, []byte{0x5b, 0x00}, tracing.CodeChangeUnspecified)
	nextState.SetCode(secondHelper, []byte{0x5b, 0x00}, tracing.CodeChangeUnspecified)
	construction := bal.NewConstructionBlockAccessList()
	construction.CodeChange(firstHelper, 1, []byte{0x5b, 0x00})
	touches := newValidationDependencyTouches()
	touches.add(construction.ToEncodingObj())
	changes := index.changes(nextState, touches)
	if _, ok := changes.affected[hashes[0]]; !ok {
		t.Fatal("BAL-touched helper did not invalidate its transaction")
	}
	if _, ok := changes.affected[hashes[1]]; ok {
		t.Fatal("dependency absent from complete BAL was scanned")
	}
	if !changes.selectiveAccountingScan {
		t.Fatal("complete BAL did not enable selective accounting")
	}
}

func TestReorgDependencyTouchesUnionBothBranches(t *testing.T) {
	pool, _, _ := newTestEnv()
	chain := pool.chain.(*testChain)
	parent := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0), Extra: []byte("parent")})
	oldAddress := common.HexToAddress("0x7777777777777777777777777777777777777777")
	newAddress := common.HexToAddress("0x8888888888888888888888888888888888888888")
	oldBAL := bal.NewConstructionBlockAccessList()
	oldBAL.CodeChange(oldAddress, 1, []byte{0x00})
	newBAL := bal.NewConstructionBlockAccessList()
	newBAL.CodeChange(newAddress, 1, []byte{0x00})
	oldBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("old"),
	}).WithAccessListUnsafe(oldBAL.ToEncodingObj())
	newBlock := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), ParentHash: parent.Hash(), Extra: []byte("new"),
	}).WithAccessListUnsafe(newBAL.ToEncodingObj())
	for _, block := range []*types.Block{parent, oldBlock, newBlock} {
		chain.blocks[block.Hash()] = block
	}

	_, _, touches := pool.reorgTransactions(oldBlock.Header(), newBlock.Header())
	if touches == nil {
		t.Fatal("complete branch BALs unexpectedly fell back to dependency scan")
	}
	for _, address := range []common.Address{oldAddress, newAddress} {
		key := validationDependencyKey{kind: validationCodeDependency, address: address}
		if _, ok := touches.keys[key]; !ok {
			t.Fatalf("reorg BAL union missing code change for %s", address)
		}
	}
}

func TestResetUsesBALForPayerAccounting(t *testing.T) {
	fixture := newPayerCodeToggleFixture(t, 1, false)
	tx := fixture.txs[0]
	initialBalance := new(big.Int).Add(tx.Cost(), big.NewInt(100))
	fixture.state.SetBalance(fixture.payer, uint256.MustFromBig(initialBalance), tracing.BalanceChangeUnspecified)
	fixture.fill(t)

	nextBalance := new(big.Int).Add(tx.Cost(), big.NewInt(50))
	nextState := fixture.pool.currentState.Copy()
	nextState.SetBalance(fixture.payer, uint256.MustFromBig(nextBalance), tracing.BalanceChangeUnspecified)
	oldHead := fixture.chain.head
	newHeader := types.CopyHeader(oldHead)
	newHeader.ParentHash = oldHead.Hash()
	newHeader.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHeader.Time = oldHead.Time + params.SecondsPerSlot
	construction := bal.NewConstructionBlockAccessList()
	construction.BalanceChange(1, fixture.payer, uint256.MustFromBig(nextBalance))
	newBlock := types.NewBlockWithHeader(newHeader).WithAccessListUnsafe(construction.ToEncodingObj())
	fixture.chain.blocks[newBlock.Hash()] = newBlock
	fixture.chain.statedb = nextState
	fixture.chain.head = newBlock.Header()

	verifyBefore := verifyRunMeter.Snapshot().Count()
	fixture.pool.Reset(oldHead, newBlock.Header())
	if pending, _ := fixture.pool.Stats(); pending != 1 {
		t.Fatalf("pending after BAL payer change: have %d want 1", pending)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("BAL payer-only change triggered %d VERIFY runs", delta)
	}
	meta := fixture.pool.meta[tx.Hash()]
	if meta.payerAvailableBalance == nil || meta.payerAvailableBalance.Cmp(nextBalance) != 0 {
		t.Fatalf("payer balance metadata: have %v want %v", meta.payerAvailableBalance, nextBalance)
	}
}
