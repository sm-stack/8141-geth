// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/framecorpus"
	"github.com/holiman/uint256"
)

const (
	pairingInputSize  = framecorpus.PairingInputSize
	pairingVerifyGas  = 200_000
	pairingPrecompile = framecorpus.PairingAddress
)

func fourPairInput(t testing.TB) []byte {
	t.Helper()
	return framecorpus.PairingInput(1)
}

func alternateFourPairInput(_ []byte) []byte {
	return framecorpus.PairingInput(2)
}

func validationSplitCode(shape string) []byte {
	workload, err := framecorpus.WorkloadFor(shape, 1)
	if err != nil {
		panic(err)
	}
	return workload.Code
}

func cheapNowExpensiveLaterCode() []byte {
	return validationSplitCode(framecorpus.CheapNowExpensiveLater)
}

func stateSelectsPairingInputCode() []byte {
	return validationSplitCode(framecorpus.PairingStateSelectsInput)
}

func newValidationSplitTx(t testing.TB, config Config, code, data []byte) (*FramePool, *stateChangeFixture, *types.Transaction) {
	t.Helper()
	pool, statedb, chainConfig := newTestEnvWithConfig(config)
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, code, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: vm.ApproveBoth, GasLimit: pairingVerifyGas, Data: data}}
	return pool, &stateChangeFixture{sender: sender, slot: common.Hash{}}, makeFrameTx(frameTx)
}

type stateChangeFixture struct {
	sender common.Address
	slot   common.Hash
}

func validationSplitConfig(stateGas uint64, memo bool) Config {
	config := DefaultConfig
	config.MaxVerifyGas = 250_000
	config.MaxStateDependentVerifyGas = stateGas
	config.CacheValidationPrecompiles = memo
	return config
}

func TestPairingCorpusQualification(t *testing.T) {
	input := fourPairInput(t)
	precompile := vm.PrecompiledContractsOsaka[common.BytesToAddress([]byte{pairingPrecompile})]
	if gas := precompile.RequiredGas(input); gas != 181_000 {
		t.Fatalf("four-pair gas = %d, want 181000", gas)
	}
	output, err := precompile.Run(input)
	if err != nil || !bytes.Equal(output, common.LeftPadBytes([]byte{1}, 32)) {
		t.Fatalf("four-pair output = %x, %v", output, err)
	}
}

func TestStateDependentValidationShapes(t *testing.T) {
	input := fourPairInput(t)
	for _, test := range []struct {
		shape string
		data  []byte
		cap   uint64
		pass  bool
	}{
		{framecorpus.PairingPureFirst, input, 20_000, true},
		{framecorpus.PairingStateFirst, input, 20_000, false},
		{framecorpus.PairingStateSelectsInput, append(input, alternateFourPairInput(input)...), 20_000, false},
		{framecorpus.PairingPureOnly, input, 1, true},
	} {
		t.Run(test.shape, func(t *testing.T) {
			pool, _, tx := newValidationSplitTx(t, validationSplitConfig(test.cap, false), validationSplitCode(test.shape), test.data)
			err := pool.Add([]*types.Transaction{tx}, false)[0]
			if test.pass && err != nil {
				t.Fatalf("admission failed: %v", err)
			}
			if !test.pass && err == nil {
				t.Fatal("state-first pairing passed a low state-dependent cap")
			}
			if !test.pass {
				return
			}
			profile := pool.meta[tx.Hash()].validationWork
			if test.shape == framecorpus.PairingPureOnly && profile.StateDependentGasLimit != 0 {
				t.Fatalf("pure-only state-dependent gas = %d, want 0", profile.StateDependentGasLimit)
			}
			if test.shape == framecorpus.PairingPureFirst && (profile.StateDependentGasLimit == 0 || profile.StateDependentGasLimit > test.cap) {
				t.Fatalf("pure-first state-dependent gas = %d, cap %d", profile.StateDependentGasLimit, test.cap)
			}
		})
	}
}

func TestValidationWorkSummaryOverflowFailsClosed(t *testing.T) {
	var summary validationWorkSummary
	if err := summary.addFrame(0, vm.ValidationWorkProfile{StateDependentGasLimit: ^uint64(0)}); err != nil {
		t.Fatal(err)
	}
	if err := summary.addFrame(1, vm.ValidationWorkProfile{StateDependentGasLimit: 1}); err == nil {
		t.Fatal("state-dependent gas overflow was accepted")
	}
	if summary.StateDependentGasLimit != ^uint64(0) {
		t.Fatalf("overflow did not fail closed: %+v", summary)
	}
}

func TestStateDependentCapUsesRemainingBudget(t *testing.T) {
	pool, _, tx := newValidationSplitTx(t, validationSplitConfig(20_000, false), cheapNowExpensiveLaterCode(), fourPairInput(t))
	_, outcome, err := pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0)
	if err == nil || !strings.Contains(err.Error(), "state-dependent validation gas") {
		t.Fatalf("cheap admission branch error = %v", err)
	}
	if outcome.gasUsed() >= 20_000 {
		t.Fatalf("test did not take cheap admission branch: gas used %d", outcome.gasUsed())
	}
	if outcome.workProfile.StateDependentGasLimit <= 20_000 {
		t.Fatalf("profile used actual suffix instead of remaining budget: %+v", outcome.workProfile)
	}
}

func TestValidationMemoReusesPairingAcrossReset(t *testing.T) {
	pool, stateFixture, tx := newValidationSplitTx(t, validationSplitConfig(20_000, true), validationSplitCode("pairing-pure-first"), fourPairInput(t))
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	admission := pool.meta[tx.Hash()]
	stats := admission.validationMemo.Stats()
	if stats.Misses != 1 || stats.ActualRuns != 1 || stats.Stores != 1 || stats.Hits != 0 {
		t.Fatalf("admission memo stats: %+v", stats)
	}
	if stats.BeforeMutableMisses != 1 || stats.BeforeMutableActualRuns != 1 || stats.AfterMutableMisses != 0 {
		t.Fatalf("admission watershed stats: %+v", stats)
	}
	chain := pool.chain.(*testChain)
	resetWithStateChange(pool, chain, func(statedb *state.StateDB) {
		statedb.SetState(stateFixture.sender, stateFixture.slot, common.HexToHash("0x01"))
	})
	retained := pool.meta[tx.Hash()]
	if retained.validationMemo == nil || retained.validationMemo != admission.validationMemo {
		t.Fatal("reset did not preserve the transaction-local memo")
	}
	stats = retained.validationMemo.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.ActualRuns != 1 {
		t.Fatalf("reset memo stats: %+v", stats)
	}
	if stats.BeforeMutableHits != 1 || stats.AfterMutableHits != 0 {
		t.Fatalf("reset watershed stats: %+v", stats)
	}
	if !validationWorkEqual(admission.validationWork, retained.validationWork) {
		t.Fatalf("reset profile changed: admission=%+v reset=%+v", admission.validationWork, retained.validationWork)
	}
}

func TestValidationMemoPreservesChargedGas(t *testing.T) {
	input := fourPairInput(t)
	withoutMemo, _, controlTx := newValidationSplitTx(t, validationSplitConfig(250_000, false), validationSplitCode("pairing-pure-first"), input)
	_, control, err := withoutMemo.simulateVerifyFramesWithSignatureGasOutcome(controlTx, 0)
	if err != nil {
		t.Fatal(err)
	}
	withMemo, _, memoTx := newValidationSplitTx(t, validationSplitConfig(250_000, true), validationSplitCode("pairing-pure-first"), input)
	artifacts := withMemo.newValidationArtifacts()
	_, first, err := withMemo.simulateVerifyFramesWithSignatureGasOutcomeAndArtifacts(memoTx, 0, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := withMemo.simulateVerifyFramesWithSignatureGasOutcomeAndArtifacts(memoTx, 0, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if first.gasRemaining != control.gasRemaining || second.gasRemaining != control.gasRemaining || first.approveScope != control.approveScope || second.approveScope != control.approveScope {
		t.Fatalf("memo changed validation outcome: control=%+v first=%+v second=%+v", control, first, second)
	}
}

func TestValidationMemoMissesForStateSelectedInput(t *testing.T) {
	inputA := fourPairInput(t)
	inputB := alternateFourPairInput(inputA)
	pool, stateFixture, tx := newValidationSplitTx(t, validationSplitConfig(250_000, true), stateSelectsPairingInputCode(), append(inputA, inputB...))
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	memo := pool.meta[tx.Hash()].validationMemo
	chain := pool.chain.(*testChain)
	resetWithStateChange(pool, chain, func(statedb *state.StateDB) {
		statedb.SetState(stateFixture.sender, stateFixture.slot, common.HexToHash("0x01"))
	})
	stats := memo.Stats()
	if stats.Hits != 0 || stats.Misses != 2 || stats.ActualRuns != 2 || stats.Stores != 2 {
		t.Fatalf("state-selected input memo stats: %+v", stats)
	}
	if stats.AfterMutableMisses != 2 || stats.AfterMutableActualRuns != 2 || stats.BeforeMutableMisses != 0 {
		t.Fatalf("state-selected watershed stats: %+v", stats)
	}
}

func TestValidationMemoStateFirstHitsAfterWatershed(t *testing.T) {
	pool, stateFixture, tx := newValidationSplitTx(t, validationSplitConfig(250_000, true), validationSplitCode(framecorpus.PairingStateFirst), fourPairInput(t))
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	memo := pool.meta[tx.Hash()].validationMemo
	stats := memo.Stats()
	if stats.AfterMutableMisses != 1 || stats.AfterMutableActualRuns != 1 || stats.BeforeMutableMisses != 0 {
		t.Fatalf("state-first admission stats: %+v", stats)
	}
	resetWithStateChange(pool, pool.chain.(*testChain), func(statedb *state.StateDB) {
		statedb.SetState(stateFixture.sender, stateFixture.slot, common.HexToHash("0x01"))
	})
	stats = memo.Stats()
	if stats.AfterMutableHits != 1 || stats.BeforeMutableHits != 0 || stats.ActualRuns != 1 {
		t.Fatalf("state-first reset stats: %+v", stats)
	}
}

func TestPairingPureOnlyReusesWholeValidation(t *testing.T) {
	pool, stateFixture, tx := newValidationSplitTx(t, validationSplitConfig(250_000, true), validationSplitCode(framecorpus.PairingPureOnly), fourPairInput(t))
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	memo := pool.meta[tx.Hash()].validationMemo
	statsBefore := memo.Stats()
	verifyBefore := verifyRunMeter.Snapshot().Count()
	resetWithStateChange(pool, pool.chain.(*testChain), func(statedb *state.StateDB) {
		statedb.SetState(stateFixture.sender, stateFixture.slot, common.HexToHash("0x01"))
	})
	if verifyDelta := verifyRunMeter.Snapshot().Count() - verifyBefore; verifyDelta != 0 {
		t.Fatalf("dependency-free validation reran %d times", verifyDelta)
	}
	if statsAfter := memo.Stats(); statsAfter != statsBefore {
		t.Fatalf("dependency-free reset touched memo: before=%+v after=%+v", statsBefore, statsAfter)
	}
}

func TestPureEVMBeforeStateRemainsReplayWork(t *testing.T) {
	workload, err := framecorpus.WorkloadFor(framecorpus.PureEVMBeforeState, 1)
	if err != nil {
		t.Fatal(err)
	}
	pool, stateFixture, tx := newValidationSplitTx(t, validationSplitConfig(250_000, true), workload.Code, workload.Data)
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	meta := pool.meta[tx.Hash()]
	profile := meta.validationWork.FrameProfiles[0]
	if profile.GasUsedBeforeFirstMutable < 80_000 || profile.FirstMutableReadKind != vm.ValidationMutableReadStorage {
		t.Fatalf("pure EVM prefix was not profiled: %+v", profile)
	}
	statsBefore := meta.validationMemo.Stats()
	verifyBefore := verifyRunMeter.Snapshot().Count()
	resetWithStateChange(pool, pool.chain.(*testChain), func(statedb *state.StateDB) {
		statedb.SetState(stateFixture.sender, stateFixture.slot, common.HexToHash("0x01"))
	})
	if verifyDelta := verifyRunMeter.Snapshot().Count() - verifyBefore; verifyDelta != 1 {
		t.Fatalf("pure EVM validation reran %d times, want 1", verifyDelta)
	}
	if statsAfter := meta.validationMemo.Stats(); statsAfter != statsBefore {
		t.Fatalf("pure EVM replay unexpectedly used precompile memo: before=%+v after=%+v", statsBefore, statsAfter)
	}
}

func callThenApproveCode(target common.Address) []byte {
	code := []byte{byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.PUSH20)}
	code = append(code, target.Bytes()...)
	code = append(code, byte(vm.GAS), byte(vm.STATICCALL), byte(vm.POP))
	return append(code, approveBothCode...)
}

func TestValidationProgramChangesDropBeforeResetExecution(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*state.StateDB, common.Address) common.Address
	}{
		{
			name: "sender code",
			setup: func(statedb *state.StateDB, sender common.Address) common.Address {
				statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)
				return sender
			},
		},
		{
			name: "delegation implementation",
			setup: func(statedb *state.StateDB, sender common.Address) common.Address {
				implementation := common.HexToAddress("0x2222222222222222222222222222222222222222")
				statedb.CreateAccount(implementation)
				statedb.SetCode(implementation, approveBothCode, tracing.CodeChangeUnspecified)
				statedb.SetCode(sender, types.AddressToDelegation(implementation), tracing.CodeChangeUnspecified)
				return implementation
			},
		},
		{
			name: "called library",
			setup: func(statedb *state.StateDB, sender common.Address) common.Address {
				library := common.HexToAddress("0x3333333333333333333333333333333333333333")
				statedb.CreateAccount(library)
				statedb.SetCode(library, []byte{byte(vm.STOP)}, tracing.CodeChangeUnspecified)
				statedb.SetCode(sender, callThenApproveCode(library), tracing.CodeChangeUnspecified)
				return library
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, statedb, chainConfig := newTestEnv()
			sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
			statedb.CreateAccount(sender)
			statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
			changedAddress := test.setup(statedb, sender)
			frameTx := baseFTX(sender, 0, chainConfig)
			frameTx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: vm.ApproveBoth, GasLimit: PublicMaxVerifyGas}}
			tx := makeFrameTx(frameTx)
			if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
				t.Fatalf("admission failed: %v", err)
			}
			verifyBefore := verifyRunMeter.Snapshot().Count()
			signatureBefore := signatureRunMeter.Snapshot().Count()
			resetWithStateChange(pool, pool.chain.(*testChain), func(next *state.StateDB) {
				next.SetCode(changedAddress, append(append([]byte{}, next.GetCode(changedAddress)...), byte(vm.STOP)), tracing.CodeChangeUnspecified)
			})
			if pending, _ := pool.Stats(); pending != 0 {
				t.Fatalf("changed program retained %d transactions", pending)
			}
			if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
				t.Fatalf("changed program ran %d VERIFY simulations", delta)
			}
			if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
				t.Fatalf("changed program ran %d signature validations", delta)
			}
			if len(pool.staleValidationPrograms) != 1 {
				t.Fatalf("stale validation programs = %d, want 1", len(pool.staleValidationPrograms))
			}
			if err := pool.Add([]*types.Transaction{tx}, false)[0]; err == nil {
				t.Fatal("same hash replay passed stale program preflight")
			}
			if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
				t.Fatalf("same hash replay ran %d signature validations", delta)
			}
		})
	}
}

func TestDeployFactoryChangeDropsBeforeResetExecution(t *testing.T) {
	pool, statedb, chainConfig := newTestEnv()
	factory := common.HexToAddress("0x2222222222222222222222222222222222222222")
	sender := crypto.CreateAddress(factory, 0)
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(factory)
	statedb.SetCode(factory, createFactoryCode(approveBothCode), tracing.CodeChangeUnspecified)
	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.Frames = []types.Frame{
		{Mode: types.FrameModeDefault, Target: &factory, GasLimit: 60_000},
		{Mode: types.FrameModeVerify, Flags: vm.ApproveBoth, GasLimit: 30_000},
	}
	tx := makeFrameTx(frameTx)
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	verifyBefore := verifyRunMeter.Snapshot().Count()
	resetWithStateChange(pool, pool.chain.(*testChain), func(next *state.StateDB) {
		next.SetCode(factory, append(createFactoryCode(approveBothCode), byte(vm.STOP)), tracing.CodeChangeUnspecified)
	})
	if pending, _ := pool.Stats(); pending != 0 {
		t.Fatalf("changed deploy factory retained %d transactions", pending)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("changed deploy factory ran %d VERIFY simulations", delta)
	}
}

func BenchmarkPairingValidation(b *testing.B) {
	for _, memoEnabled := range []bool{false, true} {
		name := "baseline"
		if memoEnabled {
			name = "memo"
		}
		b.Run(name, func(b *testing.B) {
			pool, _, tx := newValidationSplitTx(b, validationSplitConfig(250_000, memoEnabled), validationSplitCode(framecorpus.PairingPureFirst), fourPairInput(b))
			artifacts := pool.newValidationArtifacts()
			if memoEnabled {
				if _, _, err := pool.simulateVerifyFramesWithSignatureGasOutcomeAndArtifacts(tx, 0, artifacts); err != nil {
					b.Fatal(err)
				}
			}
			before := artifacts.precompileMemo.Stats()
			b.ResetTimer()
			for range b.N {
				if _, _, err := pool.simulateVerifyFramesWithSignatureGasOutcomeAndArtifacts(tx, 0, artifacts); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			stats := artifacts.precompileMemo.Stats()
			b.ReportMetric(float64(stats.AccountedBytes), "memo-bytes")
			if memoEnabled {
				b.ReportMetric(float64(stats.Hits-before.Hits)/float64(b.N), "memo-hits/op")
				b.ReportMetric(float64(stats.ActualRuns-before.ActualRuns)/float64(b.N), "actual-runs/op")
			} else {
				b.ReportMetric(0, "memo-hits/op")
				b.ReportMetric(1, "actual-runs/op")
			}
		})
	}
}

func BenchmarkStateDependentPureEVM(b *testing.B) {
	workload, err := framecorpus.WorkloadFor(framecorpus.PureEVMBeforeState, 1)
	if err != nil {
		b.Fatal(err)
	}
	pool, _, tx := newValidationSplitTx(b, validationSplitConfig(250_000, false), workload.Code, workload.Data)
	b.ResetTimer()
	for range b.N {
		if _, _, err := pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidationMemoPairingMemory(b *testing.B) {
	pool, _, tx := newValidationSplitTx(b, validationSplitConfig(250_000, true), validationSplitCode(framecorpus.PairingPureFirst), fourPairInput(b))
	artifacts := pool.newValidationArtifacts()
	b.ResetTimer()
	for range b.N {
		if _, _, err := pool.simulateVerifyFramesWithSignatureGasOutcomeAndArtifacts(tx, 0, artifacts); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	stats := artifacts.precompileMemo.Stats()
	b.ReportMetric(float64(stats.AccountedBytes), "memo-bytes")
}
