// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/framecorpus"
)

func TestPublicRevalidationGasAdmission(t *testing.T) {
	for _, test := range []struct {
		name        string
		gas         uint64
		proof, memo bool
		memoBytes   uint64
		cap         uint64
		wantCredit  uint64
		wantError   string
	}{
		{name: "ordinary exact cap", gas: 100_000, memo: true},
		{name: "ordinary over cap", gas: 100_001, memo: true, wantError: "revalidation gas G-c"},
		{name: "custom admission view cap", gas: 50_001, cap: 50_000, memo: true, wantError: "revalidation gas G-c"},
		{name: "proof at total cap", gas: 250_000, proof: true, memo: true, wantCredit: 181_000},
		{name: "total cap first", gas: 250_001, proof: true, memo: true, wantError: "validation prefix gas"},
		{name: "memo disabled", gas: 200_000, proof: true, wantError: "revalidation gas G-c"},
		{name: "memo bytes exhausted", gas: 200_000, proof: true, memo: true, memoBytes: 1, wantError: "revalidation gas G-c"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultConfig
			config.CacheValidationPrecompiles = test.memo
			if test.memoBytes != 0 {
				config.ValidationMemoMaxBytes = test.memoBytes
			}
			if test.cap != 0 {
				config.MaxRevalidationGas = test.cap
			}
			code, input := approveBothCode, []byte(nil)
			if test.proof {
				code, input = validationSplitCode(framecorpus.PairingPureOnly), fourPairInput(t)
			}
			pool, _, tx := newValidationSplitTx(t, config, code, input)
			frameTx := tx.GetFrameTx()
			frameTx.Frames[0].GasLimit = test.gas
			tx = makeFrameTx(frameTx)
			err := pool.Add([]*types.Transaction{tx}, false)[0]
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("admission error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			work := pool.meta[tx.Hash()].validationWork
			if work.ValidationGasLimit != test.gas || work.CachedPrecompileGas != test.wantCredit || work.RevalidationGasLimit != test.gas-test.wantCredit {
				t.Fatalf("unexpected G/c/G-c: %+v", work)
			}
		})
	}
}

func TestPublicRevalidationCreditSurvivesReset(t *testing.T) {
	pool, fixture, tx := newValidationSplitTx(t, DefaultConfig, validationSplitCode(framecorpus.PairingPureFirst), fourPairInput(t))
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatal(err)
	}
	before := pool.meta[tx.Hash()].validationWork
	for i := byte(1); i <= 2; i++ {
		resetWithStateChange(pool, pool.chain.(*testChain), func(statedb *state.StateDB) {
			statedb.SetState(fixture.sender, fixture.slot, common.Hash{31: i})
		})
		after := pool.meta[tx.Hash()]
		if !validationWorkEqual(before, after.validationWork) || after.validationWork.CachedPrecompileGas != 181_000 {
			t.Fatalf("reset changed credit: before=%+v after=%+v", before, after.validationWork)
		}
		if stats := after.validationMemo.Stats(); stats.ActualRuns != 1 || stats.Hits != uint64(i) {
			t.Fatalf("reset memo stats: %+v", stats)
		}
	}
}

func TestRevalidationGasGlobalCredit(t *testing.T) {
	var summary validationWorkSummary
	// Add out of order to verify global, rather than insertion-order, accounting.
	profiles := map[int]vm.ValidationWorkProfile{
		0: {FrameGasLimit: 100, CachedPrecompileGas: 60},
		1: {FrameGasLimit: 100, CachedPrecompileGas: 30, HasMutableRead: true, GasUsedBeforeFirstMutable: 40, StateDependentGasLimit: 60},
		2: {FrameGasLimit: 50, CachedPrecompileGas: 40},
	}
	for _, index := range []int{2, 1, 0} {
		if err := summary.addFrame(index, profiles[index]); err != nil {
			t.Fatal(err)
		}
	}
	if summary.ValidationGasLimit != 250 || summary.CachedPrecompileGas != 90 || summary.RevalidationGasLimit != 160 {
		t.Fatalf("global credit: %+v", summary)
	}
	profiles[1] = vm.ValidationWorkProfile{FrameGasLimit: 100, CachedPrecompileGas: 30, GasAccountingConservative: true, StateDependentGasLimit: 100}
	if err := summary.addFrame(1, profiles[1]); err != nil {
		t.Fatal(err)
	}
	if summary.CachedPrecompileGas != 60 || summary.RevalidationGasLimit != 190 {
		t.Fatalf("conservative credit: %+v", summary)
	}
	if err := summary.addFrame(0, vm.ValidationWorkProfile{FrameGasLimit: 1, CachedPrecompileGas: 2}); err == nil {
		t.Fatal("invalid credit accepted")
	}
}
