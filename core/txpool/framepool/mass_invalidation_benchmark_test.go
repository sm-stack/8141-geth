// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// This benchmark models the shared-payer invalidation primitive described by
// the EIP-8141 public-mempool rules. It is research instrumentation, not a
// production-policy recommendation.

package framepool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

var benchmarkPaymasterAuthShimRuntime = common.FromHex("0x361561004f57335f541461001257610082565b6044361461001f57610082565b5f3560e01c63da95ebf71461003357610082565b60043580156100825760015560243560025561a8c04201600355005b60015fb460011461005f57610082565b60025fb41561006d57610082565b5f5fb45f541461007c57610082565b60015f5faa5b5f5ffd")

var (
	benchmarkPaymasterAuthShimCodeHash      = common.HexToHash("0x0eaf76edbfffd6e5f136f53d137faabe417fc9cff28655308d6ed70d5ce9ea0b")
	benchmarkPaymasterPendingWithdrawalSlot = common.Hash{31: 2}
)

const (
	massInvalidationSignerKey  = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
	massInvalidationPayerGas   = uint64(6_000)
	massInvalidationSenderGas  = PublicMaxVerifyGas - params.SigGasSecp256k1 - massInvalidationPayerGas
	massInvalidationApproveGas = uint64(9)
	// Seven BLS calls fit the 92,200-gas sender frame. The authenticated
	// benchmark payer consumes 5,202 gas on its successful payment path,
	// including its cold frame-target access.
	massInvalidationBLSIterations = uint64(7)
	massInvalidationPayerGasUsed  = uint64(5_202)
	massInvalidationSignatureGas  = params.SigGasSecp256k1
)

type massInvalidationFixture struct {
	pool       *FramePool
	state      *state.StateDB
	chain      *testChain
	payer      common.Address
	payerFunds *uint256.Int
	txs        []*types.Transaction
	gasPerTx   uint64
}

func massInvalidationSender(index int) common.Address {
	var sender common.Address
	sender[0] = 0x41
	binary.BigEndian.PutUint64(sender[12:], uint64(index+1))
	return sender
}

func massInvalidationCorpus(tb testing.TB, corpus string) ([]byte, []byte, uint64) {
	tb.Helper()
	var (
		code    []byte
		data    []byte
		gasUsed uint64
	)
	switch corpus {
	case "arithmetic":
		iterations := fullCostNoApproveIterations(massInvalidationSenderGas)
		code = common.CopyBytes(fullCostNoApproveCode[:len(fullCostNoApproveCode)-1])
		data = uint64Word(iterations)
		gasUsed = fullCostNoApproveFixedGas + iterations*fullCostNoApproveLoopGas
	case "bls":
		targetGas := massInvalidationSenderGas * 96 / 100
		iterations := (targetGas - precompileNoApproveFixedGas) / blsG1MSMNoApproveCallGas
		if iterations == 0 {
			iterations = 1
		}
		if iterations != massInvalidationBLSIterations {
			tb.Fatalf("mass-invalidation BLS iterations: have %d want %d", iterations, massInvalidationBLSIterations)
		}
		generated := fixedPrecompileNoApproveCode(uint16(len(blsG1MSMInput)), 0x000c, iterations)
		code = common.CopyBytes(generated[:len(generated)-1])
		data = common.CopyBytes(blsG1MSMInput)
		gasUsed = precompileNoApproveFixedGas + iterations*blsG1MSMNoApproveCallGas
	default:
		tb.Fatalf("unknown mass-invalidation corpus %q", corpus)
	}
	code = append(code, approveExecCode...)
	return code, data, gasUsed + massInvalidationApproveGas + params.WarmAccountAccessAmsterdam + massInvalidationPayerGasUsed
}

func newMassInvalidationFixture(tb testing.TB, corpus string, count int) *massInvalidationFixture {
	tb.Helper()
	if count <= 0 || count > DefaultConfig.MaxPoolSize {
		tb.Fatalf("invalid fixture size %d", count)
	}
	pool, statedb, config := newTestEnv()
	// This legacy benchmark measures the unconditional full-sweep baseline.
	pool.selectiveRevalidation = false
	chain := pool.chain.(*testChain)
	payer := common.HexToAddress("0x9999999999999999999999999999999999999999")
	signerKey, err := crypto.HexToECDSA(massInvalidationSignerKey)
	if err != nil {
		tb.Fatalf("parse benchmark payer signer: %v", err)
	}
	signer := crypto.PubkeyToAddress(signerKey.PublicKey)

	statedb.CreateAccount(payer)
	statedb.SetCode(payer, benchmarkPaymasterAuthShimRuntime, tracing.CodeChangeUnspecified)
	statedb.SetState(payer, common.Hash{}, common.BytesToHash(signer.Bytes()))

	senderCode, senderData, gasPerTx := massInvalidationCorpus(tb, corpus)
	txs := make([]*types.Transaction, 0, count)
	payerFundsBig := new(big.Int)
	for i := 0; i < count; i++ {
		sender := massInvalidationSender(i)
		statedb.CreateAccount(sender)
		statedb.SetCode(sender, senderCode, tracing.CodeChangeUnspecified)

		ftx := baseFTX(sender, 0, config)
		ftx.Frames = []types.Frame{
			{
				Mode:     types.FrameModeVerify,
				Flags:    2,
				GasLimit: massInvalidationSenderGas,
				Data:     senderData,
			},
			{
				Mode:     types.FrameModeVerify,
				Flags:    1,
				Target:   &payer,
				GasLimit: massInvalidationPayerGas,
			},
		}
		addFramePoolEOASignature(ftx, config.ChainID, signerKey)
		tx := makeFrameTx(ftx)
		txs = append(txs, tx)
		payerFundsBig.Add(payerFundsBig, tx.Cost())
	}
	payerFunds := uint256.MustFromBig(payerFundsBig)
	statedb.SetBalance(payer, payerFunds, tracing.BalanceChangeUnspecified)
	return &massInvalidationFixture{
		pool:       pool,
		state:      statedb,
		chain:      chain,
		payer:      payer,
		payerFunds: payerFunds,
		txs:        txs,
		gasPerTx:   gasPerTx,
	}
}

func (f *massInvalidationFixture) fill(tb testing.TB) {
	tb.Helper()
	f.state.SetState(f.payer, benchmarkPaymasterPendingWithdrawalSlot, common.Hash{})
	errs := f.pool.Add(f.txs, false)
	for i, err := range errs {
		if err != nil {
			tb.Fatalf("add tx %d: %v", i, err)
		}
	}
	if pending, _ := f.pool.Stats(); pending != len(f.txs) {
		tb.Fatalf("pending before trigger: have %d want %d", pending, len(f.txs))
	}
}

func (f *massInvalidationFixture) prepareReset(triggerWithdrawal bool, sequence uint64) (*types.Header, *types.Header) {
	nextState := f.pool.currentState.Copy()
	if triggerWithdrawal {
		nextState.SetState(f.payer, benchmarkPaymasterPendingWithdrawalSlot, common.BigToHash(f.payerFunds.ToBig()))
	}
	oldHead := f.chain.head
	newHead := types.CopyHeader(oldHead)
	newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHead.Time = oldHead.Time + params.SecondsPerSlot + sequence
	f.chain.statedb = nextState
	f.chain.head = newHead
	return oldHead, newHead
}

func (f *massInvalidationFixture) reset(oldHead, newHead *types.Header) {
	f.pool.Reset(oldHead, newHead)
	f.state = f.chain.statedb
}

func TestFramePoolCanonicalPaymasterWithdrawalMassInvalidation(t *testing.T) {
	const count = 16
	fixture := newMassInvalidationFixture(t, "bls", count)
	_, outcome, err := fixture.pool.simulateVerifyFramesWithSignatureGasOutcome(fixture.txs[0], params.SigGasSecp256k1)
	if err != nil {
		t.Fatalf("qualify mass-invalidation corpus: %v", err)
	}
	if used := outcome.gasUsed(); used != fixture.gasPerTx {
		t.Fatalf("mass-invalidation corpus gas: have %d want %d", used, fixture.gasPerTx)
	}
	fixture.fill(t)
	verifyBeforeKnownReplay := verifyRunMeter.Snapshot().Count()
	for i, err := range fixture.pool.Add(fixture.txs, false) {
		if !errors.Is(err, txpool.ErrAlreadyKnown) {
			t.Fatalf("known replay tx %d: have %v want %v", i, err, txpool.ErrAlreadyKnown)
		}
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBeforeKnownReplay; delta != 0 {
		t.Fatalf("known replay VERIFY runs: have %d want 0", delta)
	}
	revalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
	evictedBefore := resetEvictedMeter.Snapshot().Count()
	oldHead, newHead := fixture.prepareReset(true, 0)
	fixture.reset(oldHead, newHead)
	if pending, _ := fixture.pool.Stats(); pending != 0 {
		t.Fatalf("pending after withdrawal trigger: have %d want 0", pending)
	}
	if delta := resetRevalidatedMeter.Snapshot().Count() - revalidatedBefore; delta != 0 {
		t.Fatalf("revalidated after withdrawal trigger: have %d want 0", delta)
	}
	if delta := resetEvictedMeter.Snapshot().Count() - evictedBefore; delta != count {
		t.Fatalf("evicted after withdrawal trigger: have %d want %d", delta, count)
	}
	verifyBeforeInvalidReplay := verifyRunMeter.Snapshot().Count()
	rejectBefore := accountingRejectMeter.Snapshot().Count()
	insufficientBefore := accountingInsufficientMeter.Snapshot().Count()
	for i, err := range fixture.pool.Add(fixture.txs, false) {
		if !errors.Is(err, core.ErrInsufficientFunds) {
			t.Fatalf("withdrawal replay tx %d: have %v want %v", i, err, core.ErrInsufficientFunds)
		}
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBeforeInvalidReplay; delta != 0 {
		t.Fatalf("withdrawal replay VERIFY runs: have %d want 0", delta)
	}
	if delta := accountingRejectMeter.Snapshot().Count() - rejectBefore; delta != count {
		t.Fatalf("withdrawal replay accounting rejects: have %d want %d", delta, count)
	}
	if delta := accountingInsufficientMeter.Snapshot().Count() - insufficientBefore; delta != count {
		t.Fatalf("withdrawal replay insufficient-funds rejects: have %d want %d", delta, count)
	}
}

func TestBenchmarkPaymasterAuthShimCodeHash(t *testing.T) {
	if have := crypto.Keccak256Hash(benchmarkPaymasterAuthShimRuntime); have != benchmarkPaymasterAuthShimCodeHash {
		t.Fatalf("benchmark payer auth shim hash: have %s want %s", have, benchmarkPaymasterAuthShimCodeHash)
	}
}

func BenchmarkFramePoolMassInvalidation(b *testing.B) {
	for _, corpus := range []string{"arithmetic", "bls"} {
		for _, count := range []int{1, 16, 64, 128, 256} {
			for _, scenario := range []struct {
				name              string
				triggerWithdrawal bool
				wantPending       int
			}{
				{name: "unchanged", wantPending: count},
				{name: "withdrawal", triggerWithdrawal: true, wantPending: 0},
			} {
				b.Run(fmt.Sprintf("%s/%s/txs=%d", corpus, scenario.name, count), func(b *testing.B) {
					b.StopTimer()
					fixture := newMassInvalidationFixture(b, corpus, count)
					b.ResetTimer()
					b.ReportAllocs()
					b.ReportMetric(float64(count), "candidates/op")
					b.ReportMetric(float64(count-scenario.wantPending), "evicted/op")
					evmGas := uint64(count) * fixture.gasPerTx
					signatureGas := uint64(count) * massInvalidationSignatureGas
					b.ReportMetric(float64(evmGas), "evm-gas/op")
					b.ReportMetric(float64(signatureGas), "signature-gas/op")
					b.ReportMetric(float64(evmGas+signatureGas), "validation-gas/op")
					for i := 0; i < b.N; i++ {
						b.StopTimer()
						fixture.pool.Clear()
						fixture.fill(b)
						oldHead, newHead := fixture.prepareReset(scenario.triggerWithdrawal, uint64(i))
						b.StartTimer()
						fixture.reset(oldHead, newHead)
						b.StopTimer()
						if pending, _ := fixture.pool.Stats(); pending != scenario.wantPending {
							b.Fatalf("pending after reset: have %d want %d", pending, scenario.wantPending)
						}
					}
				})
			}
		}
	}
}
