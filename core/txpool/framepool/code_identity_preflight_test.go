// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
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

const payerCodeToggleSenderGas = PublicMaxRevalidationGas - params.SigGasArbitrary - params.SigGasSecp256k1 - massInvalidationPayerGas

type payerCodeToggleFixture struct {
	pool     *FramePool
	state    *state.StateDB
	chain    *testChain
	payer    common.Address
	delegate common.Address
	txs      []*types.Transaction
}

func newPayerCodeToggleFixture(tb testing.TB, count int, codeIdentityPreflight bool) *payerCodeToggleFixture {
	tb.Helper()
	if count <= 0 || count > DefaultConfig.MaxPoolSize {
		tb.Fatalf("invalid fixture size %d", count)
	}
	pool, statedb, config := newTestEnv()
	pool.payerSolvencyPreflight = true
	pool.payerCodeIdentityPreflight = codeIdentityPreflight
	chain := pool.chain.(*testChain)

	payerKey, err := crypto.HexToECDSA(massInvalidationSignerKey)
	if err != nil {
		tb.Fatalf("parse payer signer: %v", err)
	}
	payer := crypto.PubkeyToAddress(payerKey.PublicKey)
	delegate := common.HexToAddress("0xdedededededededededededededededededededede")
	statedb.CreateAccount(payer)
	statedb.CreateAccount(delegate)
	statedb.SetCode(delegate, []byte{0x00}, tracing.CodeChangeUnspecified)

	iterations := (payerCodeToggleSenderGas*96/100 - precompileNoApproveFixedGas) / blsG1MSMNoApproveCallGas
	if iterations == 0 {
		iterations = 1
	}
	senderCode := fixedPrecompileNoApproveCode(uint16(len(blsG1MSMInput)), 0x000c, iterations)
	senderCode = append(senderCode[:len(senderCode)-1], approveExecCode...)
	senderData := common.CopyBytes(blsG1MSMInput)
	txs := make([]*types.Transaction, 0, count)
	aggregateCost := new(big.Int)
	for i := 0; i < count; i++ {
		sender := massInvalidationSender(i)
		statedb.CreateAccount(sender)
		statedb.SetCode(sender, senderCode, tracing.CodeChangeUnspecified)

		frameTx := baseFTX(sender, 0, config)
		frameTx.Frames = []types.Frame{
			{
				Mode:     types.FrameModeVerify,
				Flags:    types.FrameFlagApproveExecution,
				GasLimit: payerCodeToggleSenderGas,
				Data:     senderData,
			},
			{
				Mode:     types.FrameModeVerify,
				Flags:    types.FrameFlagApprovePayment,
				Target:   &payer,
				GasLimit: massInvalidationPayerGas,
			},
		}
		frameTx.Signatures = []types.TxSignature{
			{Scheme: types.SignatureSchemeArbitrary, Signature: []byte{0x01}},
			{Scheme: types.SignatureSchemeSecp256k1, Signer: payer},
		}
		sigHash := frameTx.SigHash(config.ChainID)
		sig, err := crypto.Sign(sigHash[:], payerKey)
		if err != nil {
			tb.Fatalf("sign payer authorization: %v", err)
		}
		vrs := make([]byte, 65)
		vrs[0] = sig[64]
		copy(vrs[1:33], sig[0:32])
		copy(vrs[33:65], sig[32:64])
		frameTx.Signatures[1].Signature = vrs
		tx := makeFrameTx(frameTx)
		txs = append(txs, tx)
		aggregateCost.Add(aggregateCost, tx.Cost())
	}
	statedb.SetBalance(payer, uint256.MustFromBig(aggregateCost), tracing.BalanceChangeUnspecified)
	return &payerCodeToggleFixture{
		pool:     pool,
		state:    statedb,
		chain:    chain,
		payer:    payer,
		delegate: delegate,
		txs:      txs,
	}
}

func (f *payerCodeToggleFixture) unrelatedReset() {
	nextState := f.pool.currentState.Copy()
	oldHead := f.chain.head
	newHead := types.CopyHeader(oldHead)
	newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHead.Time = oldHead.Time + params.SecondsPerSlot
	f.chain.statedb = nextState
	f.chain.head = newHead
	f.pool.Reset(oldHead, newHead)
	f.state = nextState
}

func (f *payerCodeToggleFixture) fill(tb testing.TB) {
	tb.Helper()
	for i, err := range f.pool.Add(f.txs, false) {
		if err != nil {
			tb.Fatalf("fill tx %d: %v", i, err)
		}
	}
	if pending, _ := f.pool.Stats(); pending != len(f.txs) {
		tb.Fatalf("pending after fill: have %d want %d", pending, len(f.txs))
	}
}

func (f *payerCodeToggleFixture) toggleAndReset() {
	nextState := f.pool.currentState.Copy()
	nextState.SetCode(f.payer, types.AddressToDelegation(f.delegate), tracing.CodeChangeUnspecified)
	oldHead := f.chain.head
	newHead := types.CopyHeader(oldHead)
	newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHead.Time = oldHead.Time + params.SecondsPerSlot
	f.chain.statedb = nextState
	f.chain.head = newHead
	f.pool.Reset(oldHead, newHead)
}

func TestPayerCodeIdentityPreflightConfig(t *testing.T) {
	baseline, _, _ := newTestEnv()
	if !DefaultConfig.PayerCodeIdentityPreflight || !baseline.payerCodeIdentityPreflight {
		t.Fatal("payer code-identity preflight must be enabled by default")
	}
	configured := NewWithConfig(Config{
		MaxVerifyGas: PublicMaxVerifyGas,
	}, baseline.chain)
	if configured.payerCodeIdentityPreflight {
		t.Fatal("disabled payer code-identity preflight was not propagated to the pool")
	}
}

func TestPayerCodeIdentityPreflightBlocksToggleReexecution(t *testing.T) {
	const count = 16
	fixture := newPayerCodeToggleFixture(t, count, true)
	fixture.fill(t)

	checkBefore := payerCodeIdentityCheckMeter.Snapshot().Count()
	rejectBefore := payerCodeIdentityRejectMeter.Snapshot().Count()
	resetRevalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
	signatureBefore := signatureRunMeter.Snapshot().Count()
	verifyBefore := verifyRunMeter.Snapshot().Count()
	senderBefore := senderVerifyRunMeter.Snapshot().Count()
	fixture.toggleAndReset()

	if pending, _ := fixture.pool.Stats(); pending != 0 {
		t.Fatalf("pending after payer code toggle: have %d want 0", pending)
	}
	if delta := payerCodeIdentityCheckMeter.Snapshot().Count() - checkBefore; delta != count {
		t.Fatalf("reset code-identity checks: have %d want %d", delta, count)
	}
	if delta := payerCodeIdentityRejectMeter.Snapshot().Count() - rejectBefore; delta != count {
		t.Fatalf("reset code-identity rejects: have %d want %d", delta, count)
	}
	if delta := resetRevalidatedMeter.Snapshot().Count() - resetRevalidatedBefore; delta != 0 {
		t.Fatalf("reset full revalidations: have %d want 0", delta)
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("reset signature runs: have %d want 0", delta)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("reset validation-prefix runs: have %d want 0", delta)
	}
	if delta := senderVerifyRunMeter.Snapshot().Count() - senderBefore; delta != 0 {
		t.Fatalf("reset sender VERIFY runs: have %d want 0", delta)
	}
	if len(fixture.pool.stalePayerCode) != count {
		t.Fatalf("stale code identities: have %d want %d", len(fixture.pool.stalePayerCode), count)
	}

	replayRejectBefore := payerCodeIdentityReplayRejectMeter.Snapshot().Count()
	signatureBefore = signatureRunMeter.Snapshot().Count()
	verifyBefore = verifyRunMeter.Snapshot().Count()
	senderBefore = senderVerifyRunMeter.Snapshot().Count()
	for i, err := range fixture.pool.Add(fixture.txs, false) {
		if !errors.Is(err, core.ErrFrameTxInvalid) {
			t.Fatalf("exact replay tx %d: have %v want %v", i, err, core.ErrFrameTxInvalid)
		}
	}
	if delta := payerCodeIdentityReplayRejectMeter.Snapshot().Count() - replayRejectBefore; delta != count {
		t.Fatalf("exact-replay code-identity rejects: have %d want %d", delta, count)
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("exact-replay signature runs: have %d want 0", delta)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("exact-replay validation-prefix runs: have %d want 0", delta)
	}
	if delta := senderVerifyRunMeter.Snapshot().Count() - senderBefore; delta != 0 {
		t.Fatalf("exact-replay sender VERIFY runs: have %d want 0", delta)
	}
}

func TestPayerCodeIdentityPreflightDisabledPreservesToggleReexecution(t *testing.T) {
	const count = 4
	fixture := newPayerCodeToggleFixture(t, count, false)
	fixture.fill(t)
	fixture.toggleAndReset()
	if len(fixture.pool.stalePayerCode) != 0 {
		t.Fatalf("disabled preflight recorded %d stale identities", len(fixture.pool.stalePayerCode))
	}

	signatureBefore := signatureRunMeter.Snapshot().Count()
	verifyBefore := verifyRunMeter.Snapshot().Count()
	senderBefore := senderVerifyRunMeter.Snapshot().Count()
	for i, err := range fixture.pool.Add(fixture.txs, false) {
		if err == nil {
			t.Fatalf("baseline replay tx %d unexpectedly accepted", i)
		}
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != count {
		t.Fatalf("baseline exact-replay signature runs: have %d want %d", delta, count)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != count {
		t.Fatalf("baseline exact-replay validation-prefix runs: have %d want %d", delta, count)
	}
	if delta := senderVerifyRunMeter.Snapshot().Count() - senderBefore; delta != count {
		t.Fatalf("baseline exact-replay sender VERIFY runs: have %d want %d", delta, count)
	}
}

func TestPayerCodeIdentityPreflightKeepsUnchangedControlKnown(t *testing.T) {
	const count = 16
	fixture := newPayerCodeToggleFixture(t, count, true)
	fixture.fill(t)

	oldHead := fixture.chain.head
	newHead := types.CopyHeader(oldHead)
	newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHead.Time = oldHead.Time + params.SecondsPerSlot
	fixture.chain.head = newHead
	fixture.pool.Reset(oldHead, newHead)
	if pending, _ := fixture.pool.Stats(); pending != count {
		t.Fatalf("unchanged control pending: have %d want %d", pending, count)
	}
	for i, err := range fixture.pool.Add(fixture.txs, false) {
		if !errors.Is(err, txpool.ErrAlreadyKnown) {
			t.Fatalf("known control tx %d: have %v want %v", i, err, txpool.ErrAlreadyKnown)
		}
	}
}

func TestPayerCodeIdentityPreflightKeepsSelfPayingDeploy(t *testing.T) {
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
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveScopeMask, GasLimit: 30_000},
	}
	tx := makeFrameTx(frameTx)
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("add self-paying deploy transaction: %v", err)
	}
	meta := pool.meta[tx.Hash()]
	if meta.usesPaymaster {
		t.Fatal("self-paying deploy transaction classified as using a paymaster")
	}
	if statedb.GetCodeHash(sender) == meta.payerCodeHash {
		t.Fatal("test requires validation-view payer code to differ from pre-state code")
	}

	chain := pool.chain.(*testChain)
	oldHead := chain.head
	newHead := types.CopyHeader(oldHead)
	newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHead.Time = oldHead.Time + params.SecondsPerSlot
	chain.statedb = pool.currentState.Copy()
	chain.head = newHead
	pool.Reset(oldHead, newHead)

	if pending, _ := pool.Stats(); pending != 1 {
		t.Fatalf("pending self-paying deploy transactions after reset: have %d want 1", pending)
	}
	if len(pool.stalePayerCode) != 0 {
		t.Fatalf("self-paying deploy recorded %d stale payer identities", len(pool.stalePayerCode))
	}
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; !errors.Is(err, txpool.ErrAlreadyKnown) {
		t.Fatalf("known self-paying deploy after reset: have %v want %v", err, txpool.ErrAlreadyKnown)
	}
}

func TestPayerCodeIdentityPreflightAllowsReplayAfterCodeRestoration(t *testing.T) {
	fixture := newPayerCodeToggleFixture(t, 1, true)
	fixture.fill(t)
	fixture.toggleAndReset()
	if len(fixture.pool.stalePayerCode) != 1 {
		t.Fatalf("stale code identities after toggle: have %d want 1", len(fixture.pool.stalePayerCode))
	}

	nextState := fixture.pool.currentState.Copy()
	nextState.SetCode(fixture.payer, nil, tracing.CodeChangeUnspecified)
	oldHead := fixture.chain.head
	newHead := types.CopyHeader(oldHead)
	newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
	newHead.Time = oldHead.Time + params.SecondsPerSlot
	fixture.chain.statedb = nextState
	fixture.chain.head = newHead
	fixture.pool.Reset(oldHead, newHead)

	if err := fixture.pool.Add(fixture.txs, false)[0]; err != nil {
		t.Fatalf("replay after restoring payer code identity: %v", err)
	}
	if len(fixture.pool.stalePayerCode) != 0 {
		t.Fatalf("stale code identities after successful re-admission: have %d want 0", len(fixture.pool.stalePayerCode))
	}
}

func BenchmarkPayerCodeToggleExactReplay(b *testing.B) {
	for _, count := range []int{16, 256} {
		for _, mitigation := range []bool{false, true} {
			name := "baseline"
			if mitigation {
				name = "code-identity-gate"
			}
			b.Run(fmt.Sprintf("%s/N=%d", name, count), func(b *testing.B) {
				b.ReportAllocs()
				var (
					senderRuns    int64
					senderGas     int64
					signatureRuns int64
				)
				for b.Loop() {
					b.StopTimer()
					fixture := newPayerCodeToggleFixture(b, count, mitigation)
					fixture.fill(b)
					fixture.toggleAndReset()
					senderBefore := senderVerifyRunMeter.Snapshot().Count()
					senderGasBefore := senderVerifyGasMeter.Snapshot().Count()
					signatureBefore := signatureRunMeter.Snapshot().Count()
					b.StartTimer()
					errs := fixture.pool.Add(fixture.txs, false)
					b.StopTimer()
					for i, err := range errs {
						if mitigation {
							if !errors.Is(err, core.ErrFrameTxInvalid) {
								b.Fatalf("mitigated replay tx %d: have %v want %v", i, err, core.ErrFrameTxInvalid)
							}
						} else if err == nil {
							b.Fatalf("baseline replay tx %d unexpectedly accepted", i)
						}
					}
					senderRuns += senderVerifyRunMeter.Snapshot().Count() - senderBefore
					senderGas += senderVerifyGasMeter.Snapshot().Count() - senderGasBefore
					signatureRuns += signatureRunMeter.Snapshot().Count() - signatureBefore
					b.StartTimer()
				}
				b.ReportMetric(float64(count), "tx/op")
				b.ReportMetric(float64(senderRuns)/float64(b.N), "sender-runs/op")
				b.ReportMetric(float64(senderGas)/float64(b.N), "sender-gas/op")
				b.ReportMetric(float64(signatureRuns)/float64(b.N), "signature-runs/op")
			})
		}
	}
}
