// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
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

type payerPreflightFixture struct {
	pool   *FramePool
	state  *state.StateDB
	chain  *testChain
	config *params.ChainConfig
	key    *ecdsa.PrivateKey
	sender common.Address
	payer  common.Address
}

const payerPreflightSignerKey = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"

func TestPayerSolvencyPreflightConfig(t *testing.T) {
	standard, _, _ := newTestEnv()
	if !DefaultConfig.PayerSolvencyPreflight || !standard.payerSolvencyPreflight {
		t.Fatal("payer solvency preflight must be enabled by default")
	}
	baseline := NewWithConfig(Config{MaxVerifyGas: PublicMaxVerifyGas}, standard.chain)
	if baseline.payerSolvencyPreflight {
		t.Fatal("explicit A/B baseline unexpectedly enabled payer solvency preflight")
	}
}

func newPayerPreflightFixture(t *testing.T, enabled bool, canonical bool) payerPreflightFixture {
	t.Helper()
	pool, statedb, config := newTestEnv()
	pool.payerSolvencyPreflight = enabled
	// Solvency A/B tests isolate the preflight from dependency-result reuse.
	pool.selectiveRevalidation = false
	key, err := crypto.HexToECDSA(payerPreflightSignerKey)
	if err != nil {
		t.Fatalf("parse preflight test signer: %v", err)
	}
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payer := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, approvePayCode, tracing.CodeChangeUnspecified)
	if canonical {
		originalHash := canonicalPaymasterCodeHash
		canonicalPaymasterCodeHash = crypto.Keccak256Hash(approvePayCode)
		t.Cleanup(func() { canonicalPaymasterCodeHash = originalHash })
	}
	return payerPreflightFixture{
		pool:   pool,
		state:  statedb,
		chain:  pool.chain.(*testChain),
		config: config,
		key:    key,
		sender: sender,
		payer:  payer,
	}
}

func (f payerPreflightFixture) tx(data byte) *types.Transaction {
	frameTx := baseFTX(f.sender, 0, f.config)
	frameTx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000, Data: []byte{data}},
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &f.payer, GasLimit: 40_000},
	}
	addFramePoolEOASignature(frameTx, f.config.ChainID, f.key)
	return makeFrameTx(frameTx)
}

func TestPayerSolvencyPreflightAdmissionAB(t *testing.T) {
	for _, test := range []struct {
		name              string
		enabled           bool
		wantVerify        int64
		wantSignature     int64
		wantPreflightRun  int64
		wantPreflightDrop int64
	}{
		{name: "baseline", wantVerify: 1, wantSignature: 1},
		{name: "preflight", enabled: true, wantPreflightRun: 1, wantPreflightDrop: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPayerPreflightFixture(t, test.enabled, true)
			tx := fixture.tx(0x01)
			balance := new(big.Int).Add(tx.Cost(), big.NewInt(100))
			fixture.state.SetBalance(fixture.payer, uint256.MustFromBig(balance), tracing.BalanceChangeUnspecified)
			fixture.state.SetState(fixture.payer, canonicalPaymasterPendingWithdrawalSlot, common.BigToHash(big.NewInt(101)))

			verifyBefore := verifyRunMeter.Snapshot().Count()
			verifyGasBefore := verifyGasMeter.Snapshot().Count()
			signatureBefore := signatureRunMeter.Snapshot().Count()
			signatureSuccessBefore := signatureSuccessMeter.Snapshot().Count()
			signatureGasBefore := signatureGasMeter.Snapshot().Count()
			runBefore := preflightRunMeter.Snapshot().Count()
			dropBefore := preflightRejectMeter.Snapshot().Count()
			err := fixture.pool.Add([]*types.Transaction{tx}, false)[0]
			if !errors.Is(err, core.ErrInsufficientFunds) {
				t.Fatalf("admission error: have %v want %v", err, core.ErrInsufficientFunds)
			}
			if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != test.wantVerify {
				t.Fatalf("VERIFY runs: have %d want %d", delta, test.wantVerify)
			}
			verifyGasDelta := verifyGasMeter.Snapshot().Count() - verifyGasBefore
			if test.wantVerify == 0 && verifyGasDelta != 0 {
				t.Fatalf("VERIFY gas: have %d want 0", verifyGasDelta)
			}
			if test.wantVerify > 0 && verifyGasDelta <= 0 {
				t.Fatalf("VERIFY gas: have %d want positive", verifyGasDelta)
			}
			if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != test.wantSignature {
				t.Fatalf("signature validation runs: have %d want %d", delta, test.wantSignature)
			}
			if delta := signatureSuccessMeter.Snapshot().Count() - signatureSuccessBefore; delta != test.wantSignature {
				t.Fatalf("successful signature validations: have %d want %d", delta, test.wantSignature)
			}
			if delta := signatureGasMeter.Snapshot().Count() - signatureGasBefore; delta != test.wantSignature*int64(params.SigGasSecp256k1) {
				t.Fatalf("signature validation gas: have %d want %d", delta, test.wantSignature*int64(params.SigGasSecp256k1))
			}
			if delta := preflightRunMeter.Snapshot().Count() - runBefore; delta != test.wantPreflightRun {
				t.Fatalf("preflight runs: have %d want %d", delta, test.wantPreflightRun)
			}
			if delta := preflightRejectMeter.Snapshot().Count() - dropBefore; delta != test.wantPreflightDrop {
				t.Fatalf("preflight rejects: have %d want %d", delta, test.wantPreflightDrop)
			}
		})
	}
}

func TestFrameSignatureValidationFailureMetrics(t *testing.T) {
	pool, _, config := newTestEnv()
	sender := common.HexToAddress("0x4444444444444444444444444444444444444444")
	frameTx := baseFTX(sender, 0, config)
	frameTx.Signatures = []types.TxSignature{{
		Scheme:    types.SignatureSchemeSecp256k1,
		Signer:    sender,
		Signature: make([]byte, 65),
	}}

	runBefore := signatureRunMeter.Snapshot().Count()
	failureBefore := signatureFailureMeter.Snapshot().Count()
	gasBefore := signatureGasMeter.Snapshot().Count()
	if _, err := pool.validateFrameSignatures(frameTx); err == nil {
		t.Fatal("invalid signature unexpectedly passed")
	}
	if delta := signatureRunMeter.Snapshot().Count() - runBefore; delta != 1 {
		t.Fatalf("signature runs: have %d want 1", delta)
	}
	if delta := signatureFailureMeter.Snapshot().Count() - failureBefore; delta != 1 {
		t.Fatalf("signature failures: have %d want 1", delta)
	}
	if delta := signatureGasMeter.Snapshot().Count() - gasBefore; delta != int64(params.SigGasSecp256k1) {
		t.Fatalf("failed signature validation gas: have %d want %d", delta, params.SigGasSecp256k1)
	}
}

func TestPayerSolvencyPreflightPassStillRunsVerify(t *testing.T) {
	fixture := newPayerPreflightFixture(t, true, true)
	tx := fixture.tx(0x02)
	fixture.state.SetBalance(fixture.payer, uint256.MustFromBig(tx.Cost()), tracing.BalanceChangeUnspecified)

	verifyBefore := verifyRunMeter.Snapshot().Count()
	verifyGasBefore := verifyGasMeter.Snapshot().Count()
	runBefore := preflightRunMeter.Snapshot().Count()
	passBefore := preflightPassMeter.Snapshot().Count()
	if err := fixture.pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("solvent canonical payer rejected: %v", err)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 1 {
		t.Fatalf("VERIFY runs after passing preflight: have %d want 1", delta)
	}
	if delta := verifyGasMeter.Snapshot().Count() - verifyGasBefore; delta <= 0 {
		t.Fatalf("VERIFY gas after passing preflight: have %d want positive", delta)
	}
	if delta := preflightRunMeter.Snapshot().Count() - runBefore; delta != 1 {
		t.Fatalf("preflight runs: have %d want 1", delta)
	}
	if delta := preflightPassMeter.Snapshot().Count() - passBefore; delta != 1 {
		t.Fatalf("preflight passes: have %d want 1", delta)
	}
}

func TestPayerSolvencyPreflightSelfPayerAdmissionAB(t *testing.T) {
	for _, test := range []struct {
		name              string
		enabled           bool
		wantVerify        int64
		wantPreflightRun  int64
		wantPreflightDrop int64
	}{
		{name: "baseline", wantVerify: 1},
		{name: "preflight", enabled: true, wantPreflightRun: 1, wantPreflightDrop: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, statedb, config := newTestEnv()
			pool.payerSolvencyPreflight = test.enabled
			sender := common.HexToAddress("0x6666666666666666666666666666666666666666")
			statedb.CreateAccount(sender)
			statedb.SetCode(sender, approveBothCode, tracing.CodeChangeUnspecified)

			frameTx := baseFTX(sender, 0, config)
			frameTx.Frames = []types.Frame{{
				Mode:     types.FrameModeVerify,
				Flags:    types.FrameFlagApproveExecution | types.FrameFlagApprovePayment,
				GasLimit: 40_000,
			}}
			tx := makeFrameTx(frameTx)
			statedb.SetBalance(sender, uint256.MustFromBig(new(big.Int).Sub(tx.Cost(), big.NewInt(1))), tracing.BalanceChangeUnspecified)

			verifyBefore := verifyRunMeter.Snapshot().Count()
			senderVerifyBefore := senderVerifyRunMeter.Snapshot().Count()
			runBefore := preflightRunMeter.Snapshot().Count()
			rejectBefore := preflightRejectMeter.Snapshot().Count()
			err := pool.Add([]*types.Transaction{tx}, false)[0]
			if !errors.Is(err, core.ErrInsufficientFunds) {
				t.Fatalf("self-payer admission error: have %v want %v", err, core.ErrInsufficientFunds)
			}
			if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != test.wantVerify {
				t.Fatalf("self-payer VERIFY runs: have %d want %d", delta, test.wantVerify)
			}
			if delta := senderVerifyRunMeter.Snapshot().Count() - senderVerifyBefore; delta != test.wantVerify {
				t.Fatalf("self-payer sender VERIFY runs: have %d want %d", delta, test.wantVerify)
			}
			if delta := preflightRunMeter.Snapshot().Count() - runBefore; delta != test.wantPreflightRun {
				t.Fatalf("self-payer preflight runs: have %d want %d", delta, test.wantPreflightRun)
			}
			if delta := preflightRejectMeter.Snapshot().Count() - rejectBefore; delta != test.wantPreflightDrop {
				t.Fatalf("self-payer preflight rejects: have %d want %d", delta, test.wantPreflightDrop)
			}
		})
	}
}

func TestAdmissionRejectsMalformedPrefixBeforeStateChecks(t *testing.T) {
	pool, statedb, config := newTestEnv()
	pool.payerSolvencyPreflight = true
	sender := common.HexToAddress("0x7777777777777777777777777777777777777777")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.SetNonce(sender, 1, tracing.NonceChangeUnspecified)

	frameTx := baseFTX(sender, 0, config)
	frameTx.Frames = []types.Frame{{
		Mode:     types.FrameModeVerify,
		Flags:    types.FrameFlagApproveExecution,
		GasLimit: 40_000,
	}}
	tx := makeFrameTx(frameTx)

	verifyBefore := verifyRunMeter.Snapshot().Count()
	signatureBefore := signatureRunMeter.Snapshot().Count()
	senderVerifyBefore := senderVerifyRunMeter.Snapshot().Count()
	runBefore := preflightRunMeter.Snapshot().Count()
	err := pool.Add([]*types.Transaction{tx}, false)[0]
	if err == nil || !strings.Contains(err.Error(), "execution-only validation prefix missing payment VERIFY frame") {
		t.Fatalf("malformed no-pay prefix error: have %v", err)
	}
	if errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("malformed no-pay prefix was incorrectly rejected by solvency preflight: %v", err)
	}
	if errors.Is(err, core.ErrNonceTooLow) {
		t.Fatalf("malformed no-pay prefix reached sender state validation: %v", err)
	}
	if delta := preflightRunMeter.Snapshot().Count() - runBefore; delta != 0 {
		t.Fatalf("malformed no-pay preflight runs: have %d want 0", delta)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("malformed no-pay normal validation attempts: have %d want 0", delta)
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("malformed no-pay signature validations: have %d want 0", delta)
	}
	if delta := senderVerifyRunMeter.Snapshot().Count() - senderVerifyBefore; delta != 0 {
		t.Fatalf("malformed no-pay sender VERIFY runs: have %d want 0", delta)
	}
}

func TestSenderVerifyMetricsCountFailureAndSurvivePayFrameOutcome(t *testing.T) {
	t.Run("sender failure", func(t *testing.T) {
		pool, tx := newValidationOutcomeCase(t, 100_000, fullCostNoApproveCode, uint64Word(fullCostNoApproveIterations(100_000)))
		runBefore := senderVerifyRunMeter.Snapshot().Count()
		gasBefore := senderVerifyGasMeter.Snapshot().Count()

		_, outcome, err := pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0)
		if err == nil || outcome.failureClass != verifyFailureDidNotApprove {
			t.Fatalf("sender outcome: error=%v failure=%q, want did-not-approve", err, outcome.failureClass)
		}
		if delta := senderVerifyRunMeter.Snapshot().Count() - runBefore; delta != 1 {
			t.Fatalf("sender VERIFY runs: have %d want 1", delta)
		}
		if delta := senderVerifyGasMeter.Snapshot().Count() - gasBefore; delta != int64(outcome.frameGasUsed()) || delta <= 0 {
			t.Fatalf("sender VERIFY gas: have %d want positive outcome gas %d", delta, outcome.frameGasUsed())
		}
	})

	t.Run("payer failure", func(t *testing.T) {
		fixture := newPayerPreflightFixture(t, true, false)
		fixture.state.SetCode(fixture.payer, []byte{0x00}, tracing.CodeChangeUnspecified)
		tx := fixture.tx(0x07)
		runBefore := senderVerifyRunMeter.Snapshot().Count()
		gasBefore := senderVerifyGasMeter.Snapshot().Count()

		_, outcome, err := fixture.pool.simulateVerifyFramesWithSignatureGasOutcome(tx, params.SigGasSecp256k1)
		if err == nil || outcome.failureClass != verifyFailureDidNotApprove || outcome.frameIndex != 1 {
			t.Fatalf("payer outcome: error=%v outcome=%+v, want payer did-not-approve", err, outcome)
		}
		if delta := senderVerifyRunMeter.Snapshot().Count() - runBefore; delta != 1 {
			t.Fatalf("sender VERIFY runs after payer failure: have %d want 1", delta)
		}
		if delta := senderVerifyGasMeter.Snapshot().Count() - gasBefore; delta <= 0 {
			t.Fatalf("sender VERIFY gas after payer failure: have %d want positive", delta)
		}
	})
}

func TestPayerSolvencyPreflightRejectsInsolventNonCanonicalPayer(t *testing.T) {
	fixture := newPayerPreflightFixture(t, true, false)
	tx := fixture.tx(0x03)
	fixture.state.SetBalance(fixture.payer, uint256.MustFromBig(new(big.Int).Sub(tx.Cost(), big.NewInt(1))), tracing.BalanceChangeUnspecified)

	verifyBefore := verifyRunMeter.Snapshot().Count()
	runBefore := preflightRunMeter.Snapshot().Count()
	rejectBefore := preflightRejectMeter.Snapshot().Count()
	err := fixture.pool.Add([]*types.Transaction{tx}, false)[0]
	if !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("admission error: have %v want %v", err, core.ErrInsufficientFunds)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("non-canonical VERIFY runs: have %d want 0", delta)
	}
	if delta := preflightRunMeter.Snapshot().Count() - runBefore; delta != 1 {
		t.Fatalf("non-canonical preflight runs: have %d want 1", delta)
	}
	if delta := preflightRejectMeter.Snapshot().Count() - rejectBefore; delta != 1 {
		t.Fatalf("non-canonical preflight rejects: have %d want 1", delta)
	}
}

func TestNonCanonicalPendingCapRunsBeforeValidation(t *testing.T) {
	for _, solvencyPreflight := range []bool{false, true} {
		t.Run(fmt.Sprintf("solvency-preflight-%t", solvencyPreflight), func(t *testing.T) {
			fixture := newPayerPreflightFixture(t, solvencyPreflight, false)
			secondSender := common.HexToAddress("0x3333333333333333333333333333333333333333")
			fixture.state.CreateAccount(secondSender)
			fixture.state.SetCode(secondSender, approveExecCode, tracing.CodeChangeUnspecified)

			firstTx := fixture.tx(0x04)
			secondFrameTx := baseFTX(secondSender, 0, fixture.config)
			secondFrameTx.Frames = []types.Frame{
				{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000, Data: []byte{0x05}},
				{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &fixture.payer, GasLimit: 40_000},
			}
			addFramePoolEOASignature(secondFrameTx, fixture.config.ChainID, fixture.key)
			secondTx := makeFrameTx(secondFrameTx)
			balance := new(big.Int).Add(firstTx.Cost(), secondTx.Cost())
			fixture.state.SetBalance(fixture.payer, uint256.MustFromBig(balance), tracing.BalanceChangeUnspecified)

			if err := fixture.pool.Add([]*types.Transaction{firstTx}, false)[0]; err != nil {
				t.Fatalf("initial non-canonical payer transaction rejected: %v", err)
			}
			verifyBefore := verifyRunMeter.Snapshot().Count()
			signatureBefore := signatureRunMeter.Snapshot().Count()
			runBefore := preflightRunMeter.Snapshot().Count()
			err := fixture.pool.Add([]*types.Transaction{secondTx}, false)[0]
			if !errors.Is(err, txpool.ErrAccountLimitExceeded) {
				t.Fatalf("second admission error: have %v want %v", err, txpool.ErrAccountLimitExceeded)
			}
			if delta := preflightRunMeter.Snapshot().Count() - runBefore; delta != 0 {
				t.Fatalf("solvency preflight runs before cap rejection: have %d want 0", delta)
			}
			if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
				t.Fatalf("signature validations before cap rejection: have %d want 0", delta)
			}
			if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
				t.Fatalf("VERIFY runs before cap rejection: have %d want 0", delta)
			}
		})
	}
}

func TestPayerSolvencyPreflightPassesDefaultCodeSponsor(t *testing.T) {
	pool, statedb, config := newTestEnv()
	pool.payerSolvencyPreflight = true
	key, err := crypto.HexToECDSA(payerPreflightSignerKey)
	if err != nil {
		t.Fatalf("parse preflight test signer: %v", err)
	}
	sender := common.HexToAddress("0x5555555555555555555555555555555555555555")
	payer := crypto.PubkeyToAddress(key.PublicKey)
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, approveExecCode, tracing.CodeChangeUnspecified)
	statedb.CreateAccount(payer)

	frameTx := baseFTX(sender, 0, config)
	frameTx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000},
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &payer, GasLimit: 40_000},
	}
	addFramePoolDefaultCodeSponsorSignatures(frameTx, config.ChainID, key)
	tx := makeFrameTx(frameTx)
	statedb.SetBalance(payer, uint256.MustFromBig(tx.Cost()), tracing.BalanceChangeUnspecified)

	verifyBefore := verifyRunMeter.Snapshot().Count()
	directBefore := directVerifyRunMeter.Snapshot().Count()
	runBefore := preflightRunMeter.Snapshot().Count()
	passBefore := preflightPassMeter.Snapshot().Count()
	rejectBefore := preflightRejectMeter.Snapshot().Count()
	if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
		t.Fatalf("solvent default-code sponsor rejected: %v", err)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 1 {
		t.Fatalf("default-code sponsor VERIFY runs: have %d want 1", delta)
	}
	if delta := directVerifyRunMeter.Snapshot().Count() - directBefore; delta != 0 {
		t.Fatalf("mixed validation prefix used %d direct evaluations", delta)
	}
	if delta := preflightRunMeter.Snapshot().Count() - runBefore; delta != 1 {
		t.Fatalf("default-code sponsor preflight runs: have %d want 1", delta)
	}
	if delta := preflightPassMeter.Snapshot().Count() - passBefore; delta != 1 {
		t.Fatalf("default-code sponsor preflight passes: have %d want 1", delta)
	}
	if delta := preflightRejectMeter.Snapshot().Count() - rejectBefore; delta != 0 {
		t.Fatalf("default-code sponsor preflight rejects: have %d want 0", delta)
	}
	meta := pool.meta[tx.Hash()]
	if !meta.usesPaymaster || meta.canonicalPaymaster || meta.nonCanonicalPaymaster {
		t.Fatalf("default-code sponsor metadata: %+v", meta)
	}
}

func TestPayerSolvencyPreflightReplacementExcludesOldReservation(t *testing.T) {
	fixture := newPayerPreflightFixture(t, true, true)
	oldTx := fixture.tx(0x04)
	newFrameTx := baseFTX(fixture.sender, 0, fixture.config)
	newFrameTx.GasTipCap = uint256.NewInt(2)
	newFrameTx.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) * 11 / 10)
	newFrameTx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000, Data: []byte{0x05}},
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &fixture.payer, GasLimit: 40_000},
	}
	addFramePoolEOASignature(newFrameTx, fixture.config.ChainID, fixture.key)
	newTx := makeFrameTx(newFrameTx)
	fixture.state.SetBalance(fixture.payer, uint256.MustFromBig(newTx.Cost()), tracing.BalanceChangeUnspecified)

	if err := fixture.pool.Add([]*types.Transaction{oldTx}, false)[0]; err != nil {
		t.Fatalf("initial transaction rejected: %v", err)
	}
	if err := fixture.pool.Add([]*types.Transaction{newTx}, false)[0]; err != nil {
		t.Fatalf("replacement rejected instead of excluding old reservation: %v", err)
	}
	if fixture.pool.Has(oldTx.Hash()) || !fixture.pool.Has(newTx.Hash()) {
		t.Fatal("replacement did not atomically replace the old transaction")
	}
}

func TestNonCanonicalPendingCapPreflightAllowsReplacement(t *testing.T) {
	fixture := newPayerPreflightFixture(t, true, false)
	oldTx := fixture.tx(0x04)
	replacementFrameTx := baseFTX(fixture.sender, 0, fixture.config)
	replacementFrameTx.GasTipCap = uint256.NewInt(2)
	replacementFrameTx.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) * 11 / 10)
	replacementFrameTx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000, Data: []byte{0x05}},
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &fixture.payer, GasLimit: 40_000},
	}
	addFramePoolEOASignature(replacementFrameTx, fixture.config.ChainID, fixture.key)
	replacement := makeFrameTx(replacementFrameTx)
	fixture.state.SetBalance(fixture.payer, uint256.MustFromBig(replacement.Cost()), tracing.BalanceChangeUnspecified)

	if err := fixture.pool.Add([]*types.Transaction{oldTx}, false)[0]; err != nil {
		t.Fatalf("initial non-canonical payer transaction rejected: %v", err)
	}
	if err := fixture.pool.Add([]*types.Transaction{replacement}, false)[0]; err != nil {
		t.Fatalf("non-canonical payer replacement rejected: %v", err)
	}
	if fixture.pool.Has(oldTx.Hash()) || !fixture.pool.Has(replacement.Hash()) {
		t.Fatal("replacement did not atomically replace the old transaction")
	}
}

func TestNonCanonicalPendingCapPreflightExcludesEviction(t *testing.T) {
	fixture := newPayerPreflightFixture(t, true, false)
	firstTx := fixture.tx(0x04)
	secondSender := common.HexToAddress("0x3333333333333333333333333333333333333333")
	fixture.state.CreateAccount(secondSender)
	fixture.state.SetCode(secondSender, approveExecCode, tracing.CodeChangeUnspecified)
	candidateFrameTx := baseFTX(secondSender, 0, fixture.config)
	candidateFrameTx.GasTipCap = uint256.NewInt(2)
	candidateFrameTx.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) * 11 / 10)
	candidateFrameTx.Frames = []types.Frame{
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution, GasLimit: 40_000, Data: []byte{0x05}},
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApprovePayment, Target: &fixture.payer, GasLimit: 40_000},
	}
	addFramePoolEOASignature(candidateFrameTx, fixture.config.ChainID, fixture.key)
	candidate := makeFrameTx(candidateFrameTx)
	balance := new(big.Int).Add(firstTx.Cost(), candidate.Cost())
	fixture.state.SetBalance(fixture.payer, uint256.MustFromBig(balance), tracing.BalanceChangeUnspecified)

	if err := fixture.pool.Add([]*types.Transaction{firstTx}, false)[0]; err != nil {
		t.Fatalf("initial non-canonical payer transaction rejected: %v", err)
	}
	for i := 1; i < maxFramePoolSize; i++ {
		dummyFrameTx := baseFTX(common.BigToAddress(big.NewInt(int64(i+100))), uint64(i), fixture.config)
		dummyFrameTx.GasTipCap = uint256.NewInt(10)
		dummyFrameTx.GasFeeCap = uint256.NewInt(uint64(params.InitialBaseFee) * 10)
		dummyFrameTx.Frames = []types.Frame{{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveExecution | types.FrameFlagApprovePayment, GasLimit: 40_000, Data: []byte{byte(i)}}}
		dummy := makeFrameTx(dummyFrameTx)
		fixture.pool.all[dummy.Hash()] = dummy
	}
	if err := fixture.pool.Add([]*types.Transaction{candidate}, false)[0]; err != nil {
		t.Fatalf("candidate replacing the payer's evicted transaction rejected: %v", err)
	}
	if fixture.pool.Has(firstTx.Hash()) || !fixture.pool.Has(candidate.Hash()) {
		t.Fatal("candidate did not replace the selected eviction")
	}
}

func TestCanonicalPaymasterWithdrawalSlotDependsOnRuntime(t *testing.T) {
	pool, statedb, _ := newTestEnv()
	payer := common.HexToAddress("0x3333333333333333333333333333333333333333")
	statedb.CreateAccount(payer)
	statedb.SetCode(payer, benchmarkPaymasterAuthShimRuntime, tracing.CodeChangeUnspecified)
	statedb.SetState(payer, canonicalPaymasterPendingWithdrawalSlot, common.BigToHash(big.NewInt(111)))
	statedb.SetState(payer, benchmarkPaymasterPendingWithdrawalSlot, common.BigToHash(big.NewInt(222)))
	if got := pool.pendingCanonicalWithdrawal(payer); got.Cmp(big.NewInt(222)) != 0 {
		t.Fatalf("benchmark auth shim pending withdrawal: have %v want 222", got)
	}

	legacyCode := append([]byte{0x5b}, approvePayCode...)
	originalHash := canonicalPaymasterCodeHash
	canonicalPaymasterCodeHash = crypto.Keccak256Hash(legacyCode)
	t.Cleanup(func() { canonicalPaymasterCodeHash = originalHash })
	statedb.SetCode(payer, legacyCode, tracing.CodeChangeUnspecified)
	if got := pool.pendingCanonicalWithdrawal(payer); got.Cmp(big.NewInt(111)) != 0 {
		t.Fatalf("legacy canonical pending withdrawal: have %v want 111", got)
	}
}

func TestPayerSolvencyPreflightResetAB(t *testing.T) {
	for _, test := range []struct {
		name             string
		enabled          bool
		wantVerify       int64
		wantRevalidated  int64
		wantPreflightRun int64
	}{
		{name: "baseline", wantVerify: 1, wantRevalidated: 1},
		{name: "preflight", enabled: true, wantPreflightRun: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPayerPreflightFixture(t, test.enabled, true)
			tx := fixture.tx(0x06)
			fixture.state.SetBalance(fixture.payer, uint256.MustFromBig(tx.Cost()), tracing.BalanceChangeUnspecified)
			if err := fixture.pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
				t.Fatalf("initial transaction rejected: %v", err)
			}

			nextState := fixture.pool.currentState.Copy()
			nextState.SetState(fixture.payer, canonicalPaymasterPendingWithdrawalSlot, common.BigToHash(tx.Cost()))
			oldHead := fixture.chain.head
			newHead := types.CopyHeader(oldHead)
			newHead.Number = new(big.Int).Add(oldHead.Number, big.NewInt(1))
			newHead.Time = oldHead.Time + params.SecondsPerSlot
			fixture.chain.statedb = nextState
			fixture.chain.head = newHead

			verifyBefore := verifyRunMeter.Snapshot().Count()
			verifyGasBefore := verifyGasMeter.Snapshot().Count()
			revalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
			preflightBefore := preflightRunMeter.Snapshot().Count()
			fixture.pool.Reset(oldHead, newHead)
			if pending, _ := fixture.pool.Stats(); pending != 0 {
				t.Fatalf("pending after withdrawal: have %d want 0", pending)
			}
			if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != test.wantVerify {
				t.Fatalf("reset VERIFY runs: have %d want %d", delta, test.wantVerify)
			}
			verifyGasDelta := verifyGasMeter.Snapshot().Count() - verifyGasBefore
			if test.wantVerify == 0 && verifyGasDelta != 0 {
				t.Fatalf("reset VERIFY gas: have %d want 0", verifyGasDelta)
			}
			if test.wantVerify > 0 && verifyGasDelta <= 0 {
				t.Fatalf("reset VERIFY gas: have %d want positive", verifyGasDelta)
			}
			if delta := resetRevalidatedMeter.Snapshot().Count() - revalidatedBefore; delta != test.wantRevalidated {
				t.Fatalf("reset revalidated count: have %d want %d", delta, test.wantRevalidated)
			}
			if delta := preflightRunMeter.Snapshot().Count() - preflightBefore; delta != test.wantPreflightRun {
				t.Fatalf("reset preflight runs: have %d want %d", delta, test.wantPreflightRun)
			}
		})
	}
}
