// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
	"bytes"
	"fmt"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func resetWithStateChange(pool *FramePool, chain *testChain, mutate func(*state.StateDB)) *state.StateDB {
	nextState := pool.currentState.Copy()
	mutate(nextState)
	oldHead := chain.head
	newHead := types.CopyHeader(oldHead)
	newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHead.Time = oldHead.Time + params.SecondsPerSlot
	chain.statedb = nextState
	chain.head = newHead
	pool.Reset(oldHead, newHead)
	return nextState
}

func TestSelectiveRevalidationSkipsUnrelatedHeads(t *testing.T) {
	const count = 16
	fixture := newPayerCodeToggleFixture(t, count, false)
	fixture.fill(t)

	for head := 0; head < 3; head++ {
		reusedBefore := resetReusedMeter.Snapshot().Count()
		revalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
		signatureBefore := signatureRunMeter.Snapshot().Count()
		verifyBefore := verifyRunMeter.Snapshot().Count()
		senderBefore := senderVerifyRunMeter.Snapshot().Count()
		fixture.unrelatedReset()

		if pending, _ := fixture.pool.Stats(); pending != count {
			t.Fatalf("head %d pending: have %d want %d", head, pending, count)
		}
		if delta := resetReusedMeter.Snapshot().Count() - reusedBefore; delta != count {
			t.Fatalf("head %d reused: have %d want %d", head, delta, count)
		}
		if delta := resetRevalidatedMeter.Snapshot().Count() - revalidatedBefore; delta != 0 {
			t.Fatalf("head %d revalidated: have %d want 0", head, delta)
		}
		if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
			t.Fatalf("head %d signature runs: have %d want 0", head, delta)
		}
		if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
			t.Fatalf("head %d validation-prefix runs: have %d want 0", head, delta)
		}
		if delta := senderVerifyRunMeter.Snapshot().Count() - senderBefore; delta != 0 {
			t.Fatalf("head %d sender VERIFY runs: have %d want 0", head, delta)
		}
		for name, value := range map[string]int64{
			"sum":     resetLastVerifySumGauge.Snapshot().Value(),
			"mean":    resetLastVerifyMeanGauge.Snapshot().Value(),
			"max":     resetLastVerifyMaxGauge.Snapshot().Value(),
			"count":   resetLastVerifyCountGauge.Snapshot().Value(),
			"workers": resetLastVerifyWorkersGauge.Snapshot().Value(),
		} {
			if value != 0 {
				t.Fatalf("head %d reset VERIFY %s: have %d want 0", head, name, value)
			}
		}
	}
}

func TestSelectiveRevalidationBalanceChangesOnlyRebuildSolvency(t *testing.T) {
	for _, test := range []struct {
		name         string
		initialExtra int64
		nextDelta    int64
		wantPending  int
		wantReused   int64
	}{
		{name: "increase", nextDelta: 100, wantPending: 1, wantReused: 1},
		{name: "decrease-solvent", initialExtra: 100, wantPending: 1, wantReused: 1},
		{name: "decrease-insolvent", initialExtra: 100, nextDelta: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPayerPreflightFixture(t, true, true)
			fixture.pool.selectiveRevalidation = true
			tx := fixture.tx(0x09)
			initialBalance := new(big.Int).Add(tx.Cost(), big.NewInt(test.initialExtra))
			fixture.state.SetBalance(fixture.payer, uint256.MustFromBig(initialBalance), tracing.BalanceChangeUnspecified)
			if err := fixture.pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
				t.Fatalf("initial transaction rejected: %v", err)
			}

			signatureBefore := signatureRunMeter.Snapshot().Count()
			verifyBefore := verifyRunMeter.Snapshot().Count()
			reusedBefore := resetReusedMeter.Snapshot().Count()
			resetWithStateChange(fixture.pool, fixture.chain, func(nextState *state.StateDB) {
				nextBalance := new(big.Int).Add(tx.Cost(), big.NewInt(test.nextDelta))
				nextState.SetBalance(fixture.payer, uint256.MustFromBig(nextBalance), tracing.BalanceChangeUnspecified)
			})

			if pending, _ := fixture.pool.Stats(); pending != test.wantPending {
				t.Fatalf("pending after balance change: have %d want %d", pending, test.wantPending)
			}
			if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
				t.Fatalf("signature runs after balance-only change: have %d want 0", delta)
			}
			if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
				t.Fatalf("VERIFY runs after balance-only change: have %d want 0", delta)
			}
			if delta := resetReusedMeter.Snapshot().Count() - reusedBefore; delta != test.wantReused {
				t.Fatalf("reused after balance-only change: have %d want %d", delta, test.wantReused)
			}
			if test.wantPending == 1 {
				if reserved := fixture.pool.paymasterReserved[fixture.payer]; reserved == nil || reserved.Cmp(tx.Cost()) != 0 {
					t.Fatalf("rebuilt payer reservation: have %v want %v", reserved, tx.Cost())
				}
			}
		})
	}
}

func TestSortResetTransactionsPrioritizesHigherTipForSharedPayer(t *testing.T) {
	fixture := newPayerPreflightFixture(t, true, true)
	low := fixture.tx(0x0a)
	highFrame := *fixture.tx(0x0b).GetFrameTx()
	highFrame.GasTipCap = uint256.NewInt(2)
	high := makeFrameTx(&highFrame)
	txs := []*types.Transaction{low, high}
	meta := map[common.Hash]frameTxMeta{
		low.Hash():  {payer: fixture.payer},
		high.Hash(): {payer: fixture.payer},
	}

	sortResetTransactions(txs, meta)
	if txs[0].Hash() != high.Hash() {
		t.Fatalf("reset priority: have %s want higher-tip %s", txs[0].Hash(), high.Hash())
	}
}

func TestSelectiveRevalidationDetectsSenderStorageChange(t *testing.T) {
	fixture := newPayerCodeToggleFixture(t, 1, false)
	sender := massInvalidationSender(0)
	storageReadApproveCode := append([]byte{0x5f, 0x54, 0x50}, approveExecCode...)
	fixture.state.SetCode(sender, storageReadApproveCode, tracing.CodeChangeUnspecified)
	fixture.fill(t)

	changedBefore := resetDependencyChangedMeter.Snapshot().Count()
	revalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
	signatureBefore := signatureRunMeter.Snapshot().Count()
	senderBefore := senderVerifyRunMeter.Snapshot().Count()
	fixture.state = resetWithStateChange(fixture.pool, fixture.chain, func(nextState *state.StateDB) {
		nextState.SetState(sender, common.Hash{}, common.HexToHash("0x01"))
	})
	if pending, _ := fixture.pool.Stats(); pending != 1 {
		t.Fatalf("pending after sender storage change: have %d want 1", pending)
	}
	if delta := resetDependencyChangedMeter.Snapshot().Count() - changedBefore; delta != 1 {
		t.Fatalf("dependency changes: have %d want 1", delta)
	}
	if delta := resetRevalidatedMeter.Snapshot().Count() - revalidatedBefore; delta != 1 {
		t.Fatalf("revalidated after sender storage change: have %d want 1", delta)
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("signature runs after sender storage change: have %d want 0", delta)
	}
	if delta := senderVerifyRunMeter.Snapshot().Count() - senderBefore; delta != 1 {
		t.Fatalf("sender VERIFY after storage change: have %d want 1", delta)
	}
}

func TestSelectiveRevalidationDetectsHelperCodeChange(t *testing.T) {
	fixture := newPayerCodeToggleFixture(t, 1, false)
	sender := massInvalidationSender(0)
	helper := common.HexToAddress("0x7777777777777777777777777777777777777777")
	fixture.state.CreateAccount(helper)
	fixture.state.SetCode(helper, []byte{0x00}, tracing.CodeChangeUnspecified)
	senderCode := []byte{0x73}
	senderCode = append(senderCode, helper.Bytes()...)
	senderCode = append(senderCode, 0x3f, 0x50) // EXTCODEHASH, POP
	senderCode = append(senderCode, approveExecCode...)
	fixture.state.SetCode(sender, senderCode, tracing.CodeChangeUnspecified)
	fixture.fill(t)

	changedBefore := resetDependencyChangedMeter.Snapshot().Count()
	revalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
	fixture.state = resetWithStateChange(fixture.pool, fixture.chain, func(nextState *state.StateDB) {
		nextState.SetCode(helper, []byte{0x5b, 0x00}, tracing.CodeChangeUnspecified)
	})
	if pending, _ := fixture.pool.Stats(); pending != 1 {
		t.Fatalf("pending after helper code change: have %d want 1", pending)
	}
	if delta := resetDependencyChangedMeter.Snapshot().Count() - changedBefore; delta != 1 {
		t.Fatalf("helper dependency changes: have %d want 1", delta)
	}
	if delta := resetRevalidatedMeter.Snapshot().Count() - revalidatedBefore; delta != 1 {
		t.Fatalf("revalidated after helper code change: have %d want 1", delta)
	}
}

func TestValidationDependenciesTrackIntrospectedLegacyNonce(t *testing.T) {
	fixture := newPayerCodeToggleFixture(t, 1, false)
	tx := fixture.txs[0]
	frameTx := tx.GetFrameTx()
	meta := frameTxMeta{
		payer:         frameTx.Sender,
		payerCodeHash: fixture.state.GetCodeHash(frameTx.Sender),
	}
	meta.validationDeps = fixture.pool.snapshotValidationDependencies(
		frameTx, validationPrefixPlan{}, meta, nil, nil, true,
	)
	if !fixture.pool.validationDependenciesUnchanged(frameTx, meta) {
		t.Fatal("fresh legacy nonce dependency reported as changed")
	}
	fixture.state.SetNonce(frameTx.Sender, fixture.state.GetNonce(frameTx.Sender)+1, tracing.NonceChangeUnspecified)
	if fixture.pool.validationDependenciesUnchanged(frameTx, meta) {
		t.Fatal("legacy nonce dependency change was reused")
	}
}

func TestSelectiveRevalidationRejectsCanonicalWithdrawalWithoutEVM(t *testing.T) {
	const count = 16
	fixture := newMassInvalidationFixture(t, "bls", count)
	fixture.pool.selectiveRevalidation = true
	fixture.fill(t)

	revalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
	signatureBefore := signatureRunMeter.Snapshot().Count()
	senderBefore := senderVerifyRunMeter.Snapshot().Count()
	oldHead, newHead := fixture.prepareReset(true, 0)
	fixture.reset(oldHead, newHead)
	if pending, _ := fixture.pool.Stats(); pending != 0 {
		t.Fatalf("pending after canonical withdrawal: have %d want 0", pending)
	}
	if delta := resetRevalidatedMeter.Snapshot().Count() - revalidatedBefore; delta != 0 {
		t.Fatalf("canonical withdrawal revalidations: have %d want 0", delta)
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("canonical withdrawal signature runs: have %d want 0", delta)
	}
	if delta := senderVerifyRunMeter.Snapshot().Count() - senderBefore; delta != 0 {
		t.Fatalf("canonical withdrawal sender VERIFY runs: have %d want 0", delta)
	}
}

func TestSelectiveRevalidationDetectsCanonicalSignerChange(t *testing.T) {
	fixture := newMassInvalidationFixture(t, "bls", 1)
	fixture.pool.selectiveRevalidation = true
	fixture.fill(t)

	changedBefore := resetDependencyChangedMeter.Snapshot().Count()
	revalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
	fixture.state = resetWithStateChange(fixture.pool, fixture.chain, func(nextState *state.StateDB) {
		nextSigner := common.HexToAddress("0x8888888888888888888888888888888888888888")
		nextState.SetState(fixture.payer, common.Hash{}, common.BytesToHash(nextSigner.Bytes()))
	})
	if pending, _ := fixture.pool.Stats(); pending != 0 {
		t.Fatalf("pending after canonical signer change: have %d want 0", pending)
	}
	if delta := resetDependencyChangedMeter.Snapshot().Count() - changedBefore; delta != 1 {
		t.Fatalf("canonical signer dependency changes: have %d want 1", delta)
	}
	if delta := resetRevalidatedMeter.Snapshot().Count() - revalidatedBefore; delta != 1 {
		t.Fatalf("revalidated after canonical signer change: have %d want 1", delta)
	}
}

func TestResetPreparesFullValidationInParallel(t *testing.T) {
	const count = 4
	fixture := newPayerCodeToggleFixture(t, count, false)
	fixture.pool.selectiveRevalidation = false
	fixture.pool.resetValidationWorkers = 2
	fixture.fill(t)

	oldHead := fixture.chain.head
	newHead := types.CopyHeader(oldHead)
	newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHead.Time = oldHead.Time + params.SecondsPerSlot
	fixture.chain.statedb = fixture.pool.currentState.Copy()
	fixture.chain.head = newHead

	simulationNumber := new(big.Int).Add(newHead.Number, big.NewInt(1))
	entered := make(chan struct{}, count)
	release := make(chan struct{})
	fixture.pool.slotProvider = func(head *types.Header) vm.SlotProvider {
		if head.Number.Cmp(simulationNumber) == 0 {
			entered <- struct{}{}
			<-release
		}
		return vm.TimestampSlotProvider{Timestamp: head.Time}
	}
	done := make(chan struct{})
	go func() {
		fixture.pool.Reset(oldHead, newHead)
		close(done)
	}()
	for i := 0; i < fixture.pool.resetValidationWorkers; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			<-done
			t.Fatalf("parallel validation entries: have %d want %d", i, fixture.pool.resetValidationWorkers)
		}
	}
	close(release)
	<-done
	if pending, _ := fixture.pool.Stats(); pending != count {
		t.Fatalf("pending after parallel reset: have %d want %d", pending, count)
	}
	verifySum := resetLastVerifySumGauge.Snapshot().Value()
	verifyMean := resetLastVerifyMeanGauge.Snapshot().Value()
	verifyMax := resetLastVerifyMaxGauge.Snapshot().Value()
	if verifySum <= 0 || verifyMean <= 0 || verifyMax <= 0 {
		t.Fatalf("reset VERIFY timing not recorded: sum=%d mean=%d max=%d", verifySum, verifyMean, verifyMax)
	}
	if have := resetLastVerifyCountGauge.Snapshot().Value(); have != count {
		t.Fatalf("reset VERIFY count: have %d want %d", have, count)
	}
	if have := resetLastVerifyWorkersGauge.Snapshot().Value(); have != int64(fixture.pool.resetValidationWorkers) {
		t.Fatalf("reset VERIFY workers: have %d want %d", have, fixture.pool.resetValidationWorkers)
	}
	if want := verifySum / count; verifyMean != want {
		t.Fatalf("reset VERIFY mean: have %d want %d", verifyMean, want)
	}
	if verifyMax > verifySum {
		t.Fatalf("reset VERIFY max %d exceeds sum %d", verifyMax, verifySum)
	}
	if hold := resetLastHoldGauge.Snapshot().Value(); hold <= 0 || hold != resetLastTimeGauge.Snapshot().Value() {
		t.Fatalf("reset hold time mismatch: hold=%d legacy=%d", hold, resetLastTimeGauge.Snapshot().Value())
	}
	if wait := resetLastLockWaitGauge.Snapshot().Value(); wait < 0 {
		t.Fatalf("reset lock wait is negative: %d", wait)
	}
}

func TestResetCommitsSharedPayerInPriorityOrder(t *testing.T) {
	fixture := newPayerCodeToggleFixture(t, 2, false)
	fixture.pool.selectiveRevalidation = false
	fixture.pool.resetValidationWorkers = 2
	fixture.fill(t)

	first, second := fixture.txs[0], fixture.txs[1]
	firstHash, secondHash := first.Hash(), second.Hash()
	if bytes.Compare(firstHash[:], secondHash[:]) > 0 {
		first, second = second, first
	}
	resetWithStateChange(fixture.pool, fixture.chain, func(nextState *state.StateDB) {
		nextState.SetBalance(fixture.payer, uint256.MustFromBig(first.Cost()), tracing.BalanceChangeUnspecified)
	})
	if pending, _ := fixture.pool.Stats(); pending != 1 {
		t.Fatalf("pending after shared-payer reset: have %d want 1", pending)
	}
	if !fixture.pool.Has(first.Hash()) || fixture.pool.Has(second.Hash()) {
		t.Fatalf("retained transaction does not match deterministic priority: first=%t second=%t",
			fixture.pool.Has(first.Hash()), fixture.pool.Has(second.Hash()))
	}
}

func BenchmarkUnrelatedHeadReset(b *testing.B) {
	for _, selective := range []bool{false, true} {
		name := "full-sweep"
		if selective {
			name = "selective"
		}
		b.Run(fmt.Sprintf("%s/N=256", name), func(b *testing.B) {
			b.ReportAllocs()
			var (
				senderRuns  int64
				revalidated int64
				reused      int64
			)
			for b.Loop() {
				b.StopTimer()
				fixture := newPayerCodeToggleFixture(b, 256, false)
				fixture.pool.selectiveRevalidation = selective
				fixture.fill(b)
				runtime.GC()
				senderBefore := senderVerifyRunMeter.Snapshot().Count()
				revalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
				reusedBefore := resetReusedMeter.Snapshot().Count()
				b.StartTimer()
				fixture.unrelatedReset()
				b.StopTimer()
				if pending, _ := fixture.pool.Stats(); pending != 256 {
					b.Fatalf("pending after unrelated head: have %d want 256", pending)
				}
				senderRuns += senderVerifyRunMeter.Snapshot().Count() - senderBefore
				revalidated += resetRevalidatedMeter.Snapshot().Count() - revalidatedBefore
				reused += resetReusedMeter.Snapshot().Count() - reusedBefore
				b.StartTimer()
			}
			b.ReportMetric(256, "tx/op")
			b.ReportMetric(float64(senderRuns)/float64(b.N), "sender-runs/op")
			b.ReportMetric(float64(revalidated)/float64(b.N), "revalidated/op")
			b.ReportMetric(float64(reused)/float64(b.N), "reused/op")
		})
	}
}
