// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

const (
	// fullCostNoApproveFixedGas is PUSH0 + CALLDATALOAD.
	fullCostNoApproveFixedGas uint64 = 5
	// fullCostNoApproveLoopGas is JUMPDEST, PUSH1, SWAP1, SUB, DUP1, PUSH1, JUMPI.
	fullCostNoApproveLoopGas uint64 = 26
)

var (
	// fullCostNoApproveCode executes an exact, calldata-selected number of
	// 26-gas loop iterations and stops without calling APPROVE.
	//
	//   calldata[0:32] -> iteration count
	//             +-------+
	//             v       |
	//   PUSH0 CALLDATALOAD JUMPDEST PUSH1(1) SWAP1 SUB DUP1 PUSH1(2) JUMPI STOP
	fullCostNoApproveCode = []byte{byte(vm.PUSH0), byte(vm.CALLDATALOAD), byte(vm.JUMPDEST), byte(vm.PUSH1), 0x01, byte(vm.SWAP1), byte(vm.SUB), byte(vm.DUP1), byte(vm.PUSH1), 0x02, byte(vm.JUMPI), byte(vm.STOP)}
	revertCode            = []byte{byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.REVERT)}
	stackUnderflowCode    = []byte{byte(vm.PUSH0), byte(vm.POP), byte(vm.POP)}
)

func fullCostNoApproveIterations(gasLimit uint64) uint64 {
	if gasLimit <= fullCostNoApproveFixedGas {
		return 1
	}
	// Target 96% instead of exhausting the frame. This clears the corpus's 95%
	// qualification threshold while leaving enough headroom for EVM call setup.
	targetGas := gasLimit * 96 / 100
	return (targetGas - fullCostNoApproveFixedGas) / fullCostNoApproveLoopGas
}

func uint64Word(value uint64) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], value)
	return word
}

func newValidationOutcomeCase(tb testing.TB, gasLimit uint64, code, data []byte) (*FramePool, *types.Transaction) {
	tb.Helper()
	pool, statedb, config := newTestEnv()
	pool.verifyGasCap = gasLimit

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, code, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{{
		Mode:     types.FrameModeVerify,
		Flags:    vm.ApproveBoth,
		GasLimit: gasLimit,
		Data:     data,
	}}
	return pool, makeFrameTx(ftx)
}

func TestVerifyStructuredOutcomes(t *testing.T) {
	tests := []struct {
		name        string
		code        []byte
		data        []byte
		wantFailure verifyFailureClass
		wantError   string
	}{
		{
			name: "success",
			code: approveBothCode,
		},
		{
			name:        "did_not_approve",
			code:        fullCostNoApproveCode,
			data:        uint64Word(fullCostNoApproveIterations(100_000)),
			wantFailure: verifyFailureDidNotApprove,
			wantError:   "did not APPROVE",
		},
		{
			name:        "reverted",
			code:        revertCode,
			wantFailure: verifyFailureReverted,
			wantError:   "execution reverted",
		},
		{
			name:        "out_of_gas",
			code:        fullCostNoApproveCode,
			data:        uint64Word(math.MaxUint64),
			wantFailure: verifyFailureOutOfGas,
			wantError:   "out-of-gas",
		},
		{
			name:        "evm_error",
			code:        stackUnderflowCode,
			wantFailure: verifyFailureEVM,
			wantError:   "stack underflow",
		},
		{
			name:        "tracer_violation",
			code:        timestampThenApproveCode,
			wantFailure: verifyFailureTracerViolation,
			wantError:   "banned opcode",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool, tx := newValidationOutcomeCase(t, 100_000, test.code, test.data)
			_, outcome, err := pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected validation error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
			if outcome.failureClass != test.wantFailure {
				t.Fatalf("failure class = %q, want %q", outcome.failureClass, test.wantFailure)
			}
			if outcome.frameIndex != 0 {
				t.Fatalf("frame index = %d, want 0", outcome.frameIndex)
			}
			if outcome.gasLimit != 100_000 {
				t.Fatalf("gas limit = %d, want 100000", outcome.gasLimit)
			}
			if outcome.gasUsed() == 0 {
				t.Fatal("structured outcome did not retain gas usage")
			}
		})
	}
}

func TestFullCostNoApproveCorpusQualification(t *testing.T) {
	for _, gasLimit := range []uint64{100_000, 300_000, 500_000, 1_000_000} {
		t.Run(fmt.Sprintf("gas_%d", gasLimit), func(t *testing.T) {
			iterations := fullCostNoApproveIterations(gasLimit)
			pool, tx := newValidationOutcomeCase(t, gasLimit, fullCostNoApproveCode, uint64Word(iterations))

			_, outcome, err := pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0)
			if err == nil || !strings.Contains(err.Error(), "did not APPROVE") {
				t.Fatalf("validation error = %v, want did not APPROVE", err)
			}
			if outcome.failureClass != verifyFailureDidNotApprove {
				t.Fatalf("failure class = %q, want %q", outcome.failureClass, verifyFailureDidNotApprove)
			}
			if used := outcome.gasUsed(); used*100 < gasLimit*95 {
				t.Fatalf("gas used = %d/%d (%.2f%%), want at least 95%%", used, gasLimit, 100*float64(used)/float64(gasLimit))
			}

			if addErr := pool.Add([]*types.Transaction{tx}, false)[0]; addErr == nil || !strings.Contains(addErr.Error(), "did not APPROVE") {
				t.Fatalf("admission error = %v, want did not APPROVE", addErr)
			}
			if pending, queued := pool.Stats(); pending != 0 || queued != 0 {
				t.Fatalf("invalid corpus entered pool: pending=%d queued=%d", pending, queued)
			}
		})
	}
}

var (
	benchmarkFrameTxMeta  frameTxMeta
	benchmarkVerifyResult verifyResult
	benchmarkVerifyErr    error
)

func BenchmarkFullCostNoApproveValidation(b *testing.B) {
	for _, gasLimit := range []uint64{100_000, 300_000, 500_000, 1_000_000} {
		b.Run(fmt.Sprintf("gas_%d", gasLimit), func(b *testing.B) {
			iterations := fullCostNoApproveIterations(gasLimit)
			pool, tx := newValidationOutcomeCase(b, gasLimit, fullCostNoApproveCode, uint64Word(iterations))
			raw, err := tx.MarshalBinary()
			if err != nil {
				b.Fatalf("encode corpus: %v", err)
			}
			_, qualification, err := pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0)
			if err == nil || qualification.failureClass != verifyFailureDidNotApprove {
				b.Fatalf("corpus qualification failed: outcome=%+v err=%v", qualification, err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchmarkFrameTxMeta, benchmarkVerifyResult, benchmarkVerifyErr = pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0)
			}
			b.StopTimer()
			b.ReportMetric(float64(len(raw)), "encoded-B/op")
			b.ReportMetric(float64(qualification.gasUsed()), "verify-gas/op")
			b.ReportMetric(100*float64(qualification.gasUsed())/float64(gasLimit), "verify-gas-%")
			if benchmarkVerifyErr == nil || benchmarkVerifyResult.failureClass != verifyFailureDidNotApprove {
				b.Fatalf("benchmark validation changed outcome: outcome=%+v err=%v", benchmarkVerifyResult, benchmarkVerifyErr)
			}
		})
	}
}
