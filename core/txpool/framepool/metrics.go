// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package framepool

import "github.com/ethereum/go-ethereum/metrics"

var (
	// verifyRunMeter counts validation-prefix evaluation attempts, one per
	// transaction. Signature validation is accounted for separately below.
	verifyRunMeter                = metrics.NewRegisteredMeter("framepool/verify/run", nil)
	verifySuccessMeter            = metrics.NewRegisteredMeter("framepool/verify/success", nil)
	verifyGasMeter                = metrics.NewRegisteredMeter("framepool/verify/gastotal", nil)
	verifyGasHistogram            = metrics.NewRegisteredHistogram("framepool/verify/gas", nil, metrics.NewExpDecaySample(1028, 0.015))
	verifyTimeTimer               = metrics.NewRegisteredTimer("framepool/verify/time", nil)
	directVerifyRunMeter          = metrics.NewRegisteredMeter("framepool/verify/direct", nil)
	stateDependentGasMeter        = metrics.NewRegisteredMeter("framepool/verify/statedependent/gastotal", nil)
	stateDependentGasHistogram    = metrics.NewRegisteredHistogram("framepool/verify/statedependent/gas", nil, metrics.NewExpDecaySample(1028, 0.015))
	stateDependentRejectMeter     = metrics.NewRegisteredMeter("framepool/verify/statedependent/reject", nil)
	firstMutableStorageMeter      = metrics.NewRegisteredMeter("framepool/verify/firstmutable/storage", nil)
	firstMutableLegacyNonceMeter  = metrics.NewRegisteredMeter("framepool/verify/firstmutable/legacynonce", nil)
	firstMutableCodeMeter         = metrics.NewRegisteredMeter("framepool/verify/firstmutable/code", nil)
	firstMutableEnvironmentMeter  = metrics.NewRegisteredMeter("framepool/verify/firstmutable/environment", nil)
	firstMutablePriorFrameMeter   = metrics.NewRegisteredMeter("framepool/verify/firstmutable/priorframe", nil)
	firstMutableConservativeMeter = metrics.NewRegisteredMeter("framepool/verify/firstmutable/conservative", nil)

	// senderVerifyRunMeter and senderVerifyGasMeter count sender VERIFY frame
	// evaluations. They are marked immediately after the sender frame
	// returns so a later payer VERIFY outcome cannot overwrite the sender work.
	senderVerifyRunMeter = metrics.NewRegisteredMeter("framepool/verify/sender/run", nil)
	senderVerifyGasMeter = metrics.NewRegisteredMeter("framepool/verify/sender/gastotal", nil)

	verifyDidNotApproveMeter             = metrics.NewRegisteredMeter("framepool/verify/failure/didnotapprove", nil)
	verifyRevertedMeter                  = metrics.NewRegisteredMeter("framepool/verify/failure/reverted", nil)
	verifyOutOfGasMeter                  = metrics.NewRegisteredMeter("framepool/verify/failure/outofgas", nil)
	verifyTracerViolationMeter           = metrics.NewRegisteredMeter("framepool/verify/failure/tracerviolation", nil)
	verifyEVMMeter                       = metrics.NewRegisteredMeter("framepool/verify/failure/evm", nil)
	verifyOtherFailureMeter              = metrics.NewRegisteredMeter("framepool/verify/failure/other", nil)
	signatureRunMeter                    = metrics.NewRegisteredMeter("framepool/signature/run", nil)
	signatureSuccessMeter                = metrics.NewRegisteredMeter("framepool/signature/success", nil)
	signatureFailureMeter                = metrics.NewRegisteredMeter("framepool/signature/failure", nil)
	signatureGasMeter                    = metrics.NewRegisteredMeter("framepool/signature/gastotal", nil)
	signatureGasHistogram                = metrics.NewRegisteredHistogram("framepool/signature/gas", nil, metrics.NewExpDecaySample(1028, 0.015))
	signatureTimeTimer                   = metrics.NewRegisteredTimer("framepool/signature/time", nil)
	accountingRejectMeter                = metrics.NewRegisteredMeter("framepool/accounting/reject", nil)
	revalidationGasHistogram             = metrics.NewRegisteredHistogram("framepool/revalidation/gas", nil, metrics.NewExpDecaySample(1028, 0.015))
	validationCreditGasHistogram         = metrics.NewRegisteredHistogram("framepool/revalidation/creditgas", nil, metrics.NewExpDecaySample(1028, 0.015))
	revalidationRejectMeter              = metrics.NewRegisteredMeter("framepool/revalidation/reject", nil)
	accountingInsufficientMeter          = metrics.NewRegisteredMeter("framepool/accounting/reject/insufficientpayerfunds", nil)
	preflightRunMeter                    = metrics.NewRegisteredMeter("framepool/preflight/run", nil)
	preflightPassMeter                   = metrics.NewRegisteredMeter("framepool/preflight/pass", nil)
	preflightRejectMeter                 = metrics.NewRegisteredMeter("framepool/preflight/reject", nil)
	preflightTimeTimer                   = metrics.NewRegisteredTimer("framepool/preflight/time", nil)
	payerCodeIdentityCheckMeter          = metrics.NewRegisteredMeter("framepool/preflight/codeidentity/check", nil)
	payerCodeIdentityRejectMeter         = metrics.NewRegisteredMeter("framepool/preflight/codeidentity/reject", nil)
	payerCodeIdentityReplayRejectMeter   = metrics.NewRegisteredMeter("framepool/preflight/codeidentity/replayreject", nil)
	validationMemoHitMeter               = metrics.NewRegisteredMeter("framepool/validationmemo/hit", nil)
	validationMemoMissMeter              = metrics.NewRegisteredMeter("framepool/validationmemo/miss", nil)
	validationMemoActualRunMeter         = metrics.NewRegisteredMeter("framepool/validationmemo/actualrun", nil)
	validationMemoStoreMeter             = metrics.NewRegisteredMeter("framepool/validationmemo/store", nil)
	validationMemoUncacheableMeter       = metrics.NewRegisteredMeter("framepool/validationmemo/uncacheable", nil)
	validationMemoSaturatedMeter         = metrics.NewRegisteredMeter("framepool/validationmemo/saturated", nil)
	validationMemoBeforeUncacheableMeter = metrics.NewRegisteredMeter("framepool/validationmemo/beforemutable/uncacheable", nil)
	validationMemoAfterUncacheableMeter  = metrics.NewRegisteredMeter("framepool/validationmemo/aftermutable/uncacheable", nil)
	validationMemoBeforeSaturatedMeter   = metrics.NewRegisteredMeter("framepool/validationmemo/beforemutable/saturated", nil)
	validationMemoAfterSaturatedMeter    = metrics.NewRegisteredMeter("framepool/validationmemo/aftermutable/saturated", nil)
	validationMemoIncompleteRejectMeter  = metrics.NewRegisteredMeter("framepool/validationmemo/incompletereject", nil)

	resetRunMeter                = metrics.NewRegisteredMeter("framepool/reset/run", nil)
	resetCandidateMeter          = metrics.NewRegisteredMeter("framepool/reset/candidate", nil)
	resetRevalidatedMeter        = metrics.NewRegisteredMeter("framepool/reset/revalidated", nil)
	resetReusedMeter             = metrics.NewRegisteredMeter("framepool/reset/reused", nil)
	resetDependencyChangedMeter  = metrics.NewRegisteredMeter("framepool/reset/dependencychanged", nil)
	resetRetainedMeter           = metrics.NewRegisteredMeter("framepool/reset/retained", nil)
	resetEvictedMeter            = metrics.NewRegisteredMeter("framepool/reset/evicted", nil)
	resetTimeTimer               = metrics.NewRegisteredTimer("framepool/reset/time", nil)
	resetLastTimeGauge           = metrics.NewRegisteredGauge("framepool/reset/lasttime", nil)
	resetLastHoldGauge           = metrics.NewRegisteredGauge("framepool/reset/lasthold", nil)
	resetLastLockWaitGauge       = metrics.NewRegisteredGauge("framepool/reset/lastlockwait", nil)
	resetLastVerifySumGauge      = metrics.NewRegisteredGauge("framepool/reset/lastverifysum", nil)
	resetLastVerifyMeanGauge     = metrics.NewRegisteredGauge("framepool/reset/lastverifymean", nil)
	resetLastVerifyMaxGauge      = metrics.NewRegisteredGauge("framepool/reset/lastverifymax", nil)
	resetLastVerifyCountGauge    = metrics.NewRegisteredGauge("framepool/reset/lastverifycount", nil)
	resetLastVerifyWorkersGauge  = metrics.NewRegisteredGauge("framepool/reset/lastverifyworkers", nil)
	resetLastMemoHitsGauge       = metrics.NewRegisteredGauge("framepool/reset/lastmemo/hits", nil)
	resetLastMemoMissesGauge     = metrics.NewRegisteredGauge("framepool/reset/lastmemo/misses", nil)
	resetLastMemoActualRunsGauge = metrics.NewRegisteredGauge("framepool/reset/lastmemo/actualruns", nil)
	// Cached gas was still charged to the frame; only precompile CPU execution was skipped.
	resetLastMemoCachedGasGauge     = metrics.NewRegisteredGauge("framepool/reset/lastmemo/cachedgas", nil)
	resetLastStateDependentGasGauge = metrics.NewRegisteredGauge("framepool/reset/laststatedependentgas", nil)
	resetProgramDropMeter           = metrics.NewRegisteredMeter("framepool/reset/programdrop", nil)
	resetProfileMismatchMeter       = metrics.NewRegisteredMeter("framepool/reset/profilemismatch", nil)
)

func markVerifyOutcome(class verifyFailureClass, failed bool) {
	switch class {
	case verifyFailureNone:
		if failed {
			verifyOtherFailureMeter.Mark(1)
		} else {
			verifySuccessMeter.Mark(1)
		}
	case verifyFailureDidNotApprove:
		verifyDidNotApproveMeter.Mark(1)
	case verifyFailureReverted:
		verifyRevertedMeter.Mark(1)
	case verifyFailureOutOfGas:
		verifyOutOfGasMeter.Mark(1)
	case verifyFailureTracerViolation:
		verifyTracerViolationMeter.Mark(1)
	case verifyFailureEVM:
		verifyEVMMeter.Mark(1)
	default:
		verifyOtherFailureMeter.Mark(1)
	}
}
