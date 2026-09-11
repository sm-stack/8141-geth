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
	"github.com/ethereum/go-ethereum/params"
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
	// These legacy tests isolate the suffix policy from the independent G-c cap.
	config.MaxRevalidationGas = 250_000
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
	if err := summary.addFrame(0, vm.ValidationWorkProfile{HasMutableRead: true, StateDependentGasLimit: ^uint64(0)}); err != nil {
		t.Fatal(err)
	}
	if err := summary.addFrame(1, vm.ValidationWorkProfile{FrameGasLimit: 1}); err == nil {
		t.Fatal("state-dependent gas overflow was accepted")
	}
	if summary.StateDependentGasLimit != ^uint64(0) {
		t.Fatalf("overflow did not fail closed: %+v", summary)
	}
}

func TestValidationWorkSummaryChargesLaterFramesAfterGlobalWatershed(t *testing.T) {
	var summary validationWorkSummary
	if err := summary.addFrame(0, vm.ValidationWorkProfile{
		HasMutableRead:         true,
		FrameGasLimit:          10,
		StateDependentGasLimit: 5,
	}); err != nil {
		t.Fatal(err)
	}
	if err := summary.addFrame(1, vm.ValidationWorkProfile{FrameGasLimit: 100}); err != nil {
		t.Fatal(err)
	}
	if summary.StateDependentGasLimit != 105 {
		t.Fatalf("transaction-global bound = %d, want 105", summary.StateDependentGasLimit)
	}
}

func TestValidationWorkSummaryFailsClosedForConservativeFrame(t *testing.T) {
	var summary validationWorkSummary
	if err := summary.addFrame(0, vm.ValidationWorkProfile{
		FrameGasLimit:             100,
		StateDependentGasLimit:    100,
		GasAccountingConservative: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := summary.addFrame(1, vm.ValidationWorkProfile{FrameGasLimit: 50}); err != nil {
		t.Fatal(err)
	}
	if summary.StateDependentGasLimit != 150 {
		t.Fatalf("conservative transaction-global bound = %d, want 150", summary.StateDependentGasLimit)
	}
	if !summary.hasEarlierMutableFrame(1) {
		t.Fatal("conservative frame did not propagate the transaction-global watershed")
	}
	if index, _, ok := firstMutableWorkProfile(summary); !ok || index != 0 {
		t.Fatalf("first state-dependent profile = (%d, %v), want frame 0", index, ok)
	}
}

func TestValidationWorkInvariantIgnoresPostWatershedFrameProfiles(t *testing.T) {
	first := vm.ValidationWorkProfile{
		HasMutableRead:         true,
		FirstMutableReadKind:   vm.ValidationMutableReadStorage,
		FirstMutableReadPC:     7,
		FrameGasLimit:          10,
		StateDependentGasLimit: 5,
	}
	left := validationWorkSummary{StateDependentGasLimit: 105, FrameProfiles: map[int]vm.ValidationWorkProfile{
		0: first,
		1: {HasMutableRead: true, FirstMutableReadKind: vm.ValidationMutableReadPriorFrame, FrameGasLimit: 100, StateDependentGasLimit: 100},
	}}
	right := validationWorkSummary{StateDependentGasLimit: 105, FrameProfiles: map[int]vm.ValidationWorkProfile{
		0: first,
		1: {HasMutableRead: true, FirstMutableReadKind: vm.ValidationMutableReadCode, FirstMutableReadPC: 12, FrameGasLimit: 100, StateDependentGasLimit: 100},
	}}
	if validationWorkEqual(left, right) {
		t.Fatal("full profiles unexpectedly equal")
	}
	if !validationWorkInvariantEqual(left, right) {
		t.Fatal("post-watershed frame change broke the global invariant")
	}
	changed := right
	changed.FrameProfiles = map[int]vm.ValidationWorkProfile{0: first, 1: right.FrameProfiles[1]}
	changedFirst := first
	changedFirst.FirstMutableReadPC++
	changed.FrameProfiles[0] = changedFirst
	if validationWorkInvariantEqual(left, changed) {
		t.Fatal("changed transaction-global watershed was accepted")
	}
}

func frameParamPayApprovalCode() []byte {
	// Approve payment only when frame 0 completed successfully and consumed
	// non-zero execution gas. This exercises both prior-frame FRAMEPARAM fields.
	return []byte{
		byte(vm.PUSH1), 0x05, byte(vm.PUSH0), byte(vm.FRAMEPARAM),
		byte(vm.PUSH1), 0x0a, byte(vm.PUSH0), byte(vm.FRAMEPARAM),
		byte(vm.ISZERO), byte(vm.ISZERO), byte(vm.AND),
		byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.APPROVE),
	}
}

func approveScopeCode(scope byte) []byte {
	return []byte{byte(vm.PUSH1), scope, byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.APPROVE)}
}

func callThenApproveScopeCode(target common.Address, scope byte) []byte {
	code := []byte{byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.PUSH20)}
	code = append(code, target.Bytes()...)
	code = append(code, byte(vm.GAS), byte(vm.STATICCALL), byte(vm.POP))
	return append(code, approveScopeCode(scope)...)
}

func TestValidationSimulationCarriesPriorFrameResultsAndGas(t *testing.T) {
	pool, statedb, chainConfig := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	for _, address := range []common.Address{sender, payer} {
		statedb.CreateAccount(address)
		statedb.SetBalance(address, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	}
	statedb.SetCode(sender, approveScopeCode(vm.ApproveExecution), tracing.CodeChangeUnspecified)
	statedb.SetCode(payer, frameParamPayApprovalCode(), tracing.CodeChangeUnspecified)
	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: vm.ApproveExecution, GasLimit: 20_000},
		{Mode: types.FrameModeVerify, Flags: vm.ApprovePayment, Target: &payer, GasLimit: 20_000},
	}
	if _, _, err := pool.simulateVerifyFramesWithSignatureGasOutcome(makeFrameTx(frameTx), 0); err != nil {
		t.Fatalf("prior-frame runtime bridge failed in simulation: %v", err)
	}
}

func TestValidationSimulationSharesWarmSetAcrossFrames(t *testing.T) {
	pool, statedb, chainConfig := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	library := common.HexToAddress("0x3333333333333333333333333333333333333333")
	for _, address := range []common.Address{sender, payer, library} {
		statedb.CreateAccount(address)
		statedb.SetBalance(address, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	}
	statedb.SetCode(library, []byte{byte(vm.STOP)}, tracing.CodeChangeUnspecified)
	statedb.SetCode(sender, callThenApproveScopeCode(library, vm.ApproveExecution), tracing.CodeChangeUnspecified)
	statedb.SetCode(payer, callThenApproveScopeCode(library, vm.ApprovePayment), tracing.CodeChangeUnspecified)
	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: vm.ApproveExecution, GasLimit: 20_000},
		// The cold frame target plus a warm library access fits, but a second
		// cold library access does not. Frame 0 must leave the library warm.
		{Mode: types.FrameModeVerify, Flags: vm.ApprovePayment, Target: &payer, GasLimit: 4_000},
	}
	if _, _, err := pool.simulateVerifyFramesWithSignatureGasOutcome(makeFrameTx(frameTx), 0); err != nil {
		t.Fatalf("cross-frame warm access was not retained: %v", err)
	}
	statedb.SetCode(sender, approveScopeCode(vm.ApproveExecution), tracing.CodeChangeUnspecified)
	if _, _, err := pool.simulateVerifyFramesWithSignatureGasOutcome(makeFrameTx(frameTx), 0); err == nil {
		t.Fatal("cold pay-frame access unexpectedly fit the warm-only gas budget")
	}
}

func TestVerifySimulationChargesFrameTargetAccess(t *testing.T) {
	pool, statedb, chainConfig := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	for address, code := range map[common.Address][]byte{
		sender: approveScopeCode(vm.ApproveExecution),
		payer:  approveScopeCode(vm.ApprovePayment),
	} {
		statedb.CreateAccount(address)
		statedb.SetCode(address, code, tracing.CodeChangeUnspecified)
		statedb.SetBalance(address, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	}
	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: vm.ApproveExecution, GasLimit: 20_000},
		{Mode: types.FrameModeVerify, Flags: vm.ApprovePayment, Target: &payer, GasLimit: 20_000},
	}
	_, outcome, err := pool.simulateVerifyFramesWithSignatureGasOutcome(makeFrameTx(frameTx), 0)
	if err != nil {
		t.Fatal(err)
	}
	approveGas := uint64(7) // PUSH1, two PUSH0 instructions; APPROVE itself is free.
	if got, want := outcome.frameGasUsed(), params.ColdAccountAccessAmsterdam+approveGas; got != want {
		t.Fatalf("cold payer frame gas = %d, want %d", got, want)
	}
	wantPrefix := params.WarmAccountAccessAmsterdam + params.ColdAccountAccessAmsterdam + 2*approveGas
	if got := outcome.gasUsed(); got != wantPrefix {
		t.Fatalf("validation prefix gas = %d, want %d", got, wantPrefix)
	}
}

func TestVerifySimulationChargesDelegatedTargetAccess(t *testing.T) {
	pool, statedb, chainConfig := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	implementation := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, types.AddressToDelegation(implementation), tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(implementation)
	statedb.SetCode(implementation, approveScopeCode(vm.ApproveBoth), tracing.CodeChangeUnspecified)

	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: vm.ApproveBoth, GasLimit: 20_000}}
	_, outcome, err := pool.simulateVerifyFramesWithSignatureGasOutcome(makeFrameTx(frameTx), 0)
	if err != nil {
		t.Fatal(err)
	}
	approveGas := uint64(7) // PUSH1, two PUSH0 instructions; APPROVE itself is free.
	want := params.WarmAccountAccessAmsterdam + params.ColdAccountAccessAmsterdam + approveGas
	if got := outcome.gasUsed(); got != want {
		t.Fatalf("delegated validation frame gas = %d, want %d", got, want)
	}
}

func txMaxCostThenApproveCode() []byte {
	return append([]byte{byte(vm.PUSH1), 0x06, byte(vm.TXPARAM), byte(vm.POP)}, approveBothCode...)
}

func extCodeHashThenApproveCode(target common.Address) []byte {
	code := append([]byte{byte(vm.PUSH20)}, target.Bytes()...)
	code = append(code, byte(vm.EXTCODEHASH), byte(vm.POP))
	return append(code, approveBothCode...)
}

func TestBlobMaxCostIsMutableAndInvalidatesOnBlobBaseFeeChange(t *testing.T) {
	pool, statedb, chainConfig := newTestEnv()
	zero := uint64(0)
	pool.currentHead.ExcessBlobGas = &zero
	pool.currentHead.BlobGasUsed = &zero
	pool.chain.(*testChain).head.ExcessBlobGas = &zero
	pool.chain.(*testChain).head.BlobGasUsed = &zero
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, txMaxCostThenApproveCode(), tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.BlobFeeCap = uint256.NewInt(1)
	frameTx.BlobHashes = []common.Hash{{31: 1}}
	frameTx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: vm.ApproveBoth, GasLimit: 20_000}}
	tx := makeFrameTx(frameTx)
	meta, _, err := pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0)
	if err != nil {
		t.Fatal(err)
	}
	profile := meta.validationWork.FrameProfiles[0]
	if profile.FirstMutableReadKind != vm.ValidationMutableReadEnvironment || meta.validationDeps.blobBaseFee == nil {
		t.Fatalf("blob max-cost dependency missing: profile=%+v deps=%+v", profile, meta.validationDeps)
	}
	nextHead := types.CopyHeader(pool.currentHead)
	excess := uint64(100_000_000)
	nextHead.ExcessBlobGas = &excess
	nextHead.BlobGasUsed = &zero
	pool.currentHead = nextHead
	if pool.validationDependenciesUnchanged(frameTx, meta) {
		t.Fatal("changed blob base fee reused validation")
	}
	indexed := &validationDependencyChanges{
		affected: make(map[common.Hash]struct{}),
		indexed:  map[common.Hash]struct{}{tx.Hash(): {}},
	}
	if pool.validationDependenciesUnchangedIndexed(tx.Hash(), frameTx, meta, indexed) {
		t.Fatal("indexed dependency fast path reused a changed blob base fee")
	}
}

func TestPrecompileExtCodeHashDustDropsBeforeResetExecution(t *testing.T) {
	pool, statedb, chainConfig := newTestEnv()
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	precompile := common.BytesToAddress([]byte{1})
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, extCodeHashThenApproveCode(precompile), tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: vm.ApproveBoth, GasLimit: 20_000}}
	tx := makeFrameTx(frameTx)
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatal(err)
	}
	profile := pool.meta[tx.Hash()].validationWork.FrameProfiles[0]
	if profile.FirstMutableReadKind != vm.ValidationMutableReadCode {
		t.Fatalf("precompile EXTCODEHASH profile = %+v", profile)
	}
	verifyBefore := verifyRunMeter.Snapshot().Count()
	resetWithStateChange(pool, pool.chain.(*testChain), func(next *state.StateDB) {
		next.CreateAccount(precompile)
		next.SetBalance(precompile, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	})
	if pending, _ := pool.Stats(); pending != 0 {
		t.Fatalf("dusted precompile identity retained %d transactions", pending)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("dusted precompile ran %d validation simulations", delta)
	}
}

func TestPrecompileExtCodeHashExistenceChangeUsesDependencyIndex(t *testing.T) {
	config := DefaultConfig
	config.PayerCodeIdentityPreflight = false
	pool, statedb, chainConfig := newTestEnvWithConfig(config)
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	precompile := common.BytesToAddress([]byte{1})
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, extCodeHashThenApproveCode(precompile), tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: vm.ApproveBoth, GasLimit: 20_000}}
	tx := makeFrameTx(frameTx)
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatal(err)
	}
	key := validationDependencyKey{kind: validationAccountExistenceDependency, address: precompile}
	if entry := pool.dependencyIndex.byKey[key]; entry == nil {
		t.Fatal("EXTCODEHASH account-existence dependency was not indexed")
	}
	verifyBefore := verifyRunMeter.Snapshot().Count()
	resetWithStateChange(pool, pool.chain.(*testChain), func(next *state.StateDB) {
		next.CreateAccount(precompile)
		next.SetBalance(precompile, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	})
	if pending, _ := pool.Stats(); pending != 1 {
		t.Fatalf("revalidated precompile identity retained %d transactions, want 1", pending)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 1 {
		t.Fatalf("precompile existence change ran %d validation simulations, want 1", delta)
	}
}

func TestStrictMemoRequiresCompleteReusablePrefix(t *testing.T) {
	config := validationSplitConfig(250_000, true)
	config.RejectIncompleteValidationMemo = true
	pool, _, _ := newTestEnvWithConfig(config)
	rules := params.Rules{IsBerlin: true}
	address := common.BytesToAddress([]byte{2})
	precompile := vm.PrecompiledContractsBerlin[address]

	stateDependentWork := validationWorkSummary{FrameProfiles: map[int]vm.ValidationWorkProfile{
		0: {HasMutableRead: true, FrameGasLimit: 1_000, StateDependentGasLimit: 500},
	}}
	if err := stateDependentWork.recompute(); err != nil {
		t.Fatal(err)
	}
	testMemo := func(afterMutable bool, work validationWorkSummary) error {
		memo := vm.NewValidationPrecompileMemo(vm.ValidationPrecompileMemoLimits{MaxEntries: 1, MaxBytes: 4096})
		view := memo.ValidationFrameView()
		if afterMutable {
			view.MarkValidationMutable()
		}
		for _, input := range [][]byte{{1}, {2}} {
			if _, _, err := vm.RunPrecompiledContract(nil, precompile, address, input, vm.NewGasBudget(1_000, 0), nil, rules, view); err != nil {
				t.Fatal(err)
			}
		}
		return pool.finalizeValidationArtifacts(&frameTxMeta{}, work, validationArtifacts{precompileMemo: memo})
	}
	if err := testMemo(false, stateDependentWork); err == nil || !strings.Contains(err.Error(), "memo incomplete") {
		t.Fatalf("incomplete reusable prefix error = %v", err)
	}
	if err := testMemo(true, stateDependentWork); err != nil {
		t.Fatalf("after-watershed saturation rejected: %v", err)
	}
	if err := testMemo(false, validationWorkSummary{}); err != nil {
		t.Fatalf("pure-only incomplete memo rejected: %v", err)
	}
	if err := pool.finalizeValidationArtifacts(&frameTxMeta{}, validationWorkSummary{}, validationArtifacts{}); err != nil {
		t.Fatalf("pure-only missing memo rejected: %v", err)
	}
	if err := pool.finalizeValidationArtifacts(&frameTxMeta{}, stateDependentWork, validationArtifacts{}); err == nil {
		t.Fatal("strict policy accepted a missing reusable-prefix memo")
	}
	pool.selectiveRevalidation = false
	if err := pool.finalizeValidationArtifacts(&frameTxMeta{}, validationWorkSummary{}, validationArtifacts{}); err == nil {
		t.Fatal("strict full-revalidation policy accepted a missing pure-only memo")
	}
}

func TestStrictMemoConfigurationReachesAdmissionView(t *testing.T) {
	config := validationSplitConfig(250_000, true)
	config.RejectIncompleteValidationMemo = true
	config.ValidationMemoMaxEntries = 1
	pool, statedb, chainConfig := newTestEnvWithConfig(config)
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	firstCall := fixedPrecompileNoApproveCode(1, 2, 1)
	secondCall := fixedPrecompileNoApproveCode(1, 3, 1)
	code := append([]byte{}, firstCall[:len(firstCall)-1]...)
	code = append(code, secondCall[:len(secondCall)-1]...)
	pureCode := append([]byte{}, code...)
	pureCode = append(pureCode, approveBothCode...)
	code = append(code, byte(vm.PUSH0), byte(vm.SLOAD), byte(vm.POP))
	code = append(code, approveBothCode...)
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, code, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: vm.ApproveBoth, GasLimit: 20_000, Data: []byte{1}}}
	if err := pool.Add([]*types.Transaction{makeFrameTx(frameTx)}, false)[0]; err == nil || !strings.Contains(err.Error(), "memo incomplete") {
		t.Fatalf("strict admission error = %v", err)
	}
	purePool, pureState, pureChainConfig := newTestEnvWithConfig(config)
	pureState.CreateAccount(sender)
	pureState.SetCode(sender, pureCode, tracing.CodeChangeUnspecified)
	pureState.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	pureFrameTx := baseFTX(sender, 0, pureChainConfig)
	pureFrameTx.Frames = frameTx.Frames
	if err := purePool.Add([]*types.Transaction{makeFrameTx(pureFrameTx)}, false)[0]; err != nil {
		t.Fatalf("strict policy rejected pure-only incomplete memo: %v", err)
	}
}

func TestCrossFrameMemoSaturationAfterMutableIsBounded(t *testing.T) {
	config := validationSplitConfig(250_000, true)
	config.RejectIncompleteValidationMemo = true
	config.ValidationMemoMaxEntries = 1
	pool, statedb, chainConfig := newTestEnvWithConfig(config)
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	for _, address := range []common.Address{sender, payer} {
		statedb.CreateAccount(address)
		statedb.SetBalance(address, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	}
	senderCode := append([]byte{byte(vm.PUSH0), byte(vm.SLOAD), byte(vm.POP)}, approveScopeCode(vm.ApproveExecution)...)
	firstCall := fixedPrecompileNoApproveCode(1, 2, 1)
	secondCall := fixedPrecompileNoApproveCode(1, 3, 1)
	payerCode := append([]byte{}, firstCall[:len(firstCall)-1]...)
	payerCode = append(payerCode, secondCall[:len(secondCall)-1]...)
	payerCode = append(payerCode, approveScopeCode(vm.ApprovePayment)...)
	statedb.SetCode(sender, senderCode, tracing.CodeChangeUnspecified)
	statedb.SetCode(payer, payerCode, tracing.CodeChangeUnspecified)
	frameTx := baseFTX(sender, 0, chainConfig)
	frameTx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: vm.ApproveExecution, GasLimit: 20_000},
		{Mode: types.FrameModeVerify, Flags: vm.ApprovePayment, Target: &payer, GasLimit: 20_000, Data: []byte{1}},
	}
	tx := makeFrameTx(frameTx)
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatal(err)
	}
	meta := pool.meta[tx.Hash()]
	if meta.validationMemo.Complete() || !meta.validationMemo.CompleteBeforeFirstMutable() {
		t.Fatalf("cross-frame saturation phase: stats=%+v", meta.validationMemo.Stats())
	}
	payProfile := meta.validationWork.FrameProfiles[1]
	if payProfile.FirstMutableReadKind != vm.ValidationMutableReadPriorFrame || payProfile.StateDependentGasLimit != frameTx.Frames[1].GasLimit {
		t.Fatalf("pay frame was not globally bounded: %+v", payProfile)
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
			frameTx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: vm.ApproveBoth, GasLimit: PublicMaxRevalidationGas}}
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
