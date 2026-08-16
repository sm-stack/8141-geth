// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
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
	// senderSloadFixedGas is PUSH0 + CALLDATALOAD plus the final POP.
	senderSloadFixedGas uint64 = 7
	// senderSloadLoopGas includes one cold SLOAD of a distinct sender slot.
	// JUMPDEST, DUP1, SLOAD, POP, PUSH1, SWAP1, SUB, DUP1, PUSH1, JUMPI.
	senderSloadLoopGas uint64 = 2_131
	// modexpNoApproveFixedGas includes calldata copy and six words of memory
	// expansion.
	modexpNoApproveFixedGas uint64 = 80
	// modexpNoApproveLoopGas includes an Osaka-priced 32-byte ModExp with a
	// 256-bit exponent, STATICCALL overhead, and stack setup.
	modexpNoApproveCallGas uint64 = 4_196
	// extCodeCopyFirstExtraGas covers the first cold account access and memory
	// expansion to 24 KiB. Each subsequent copy reuses the warm helper and
	// already-expanded memory.
	extCodeCopyFirstExtraGas uint64 = 5_956
	extCodeCopyCallGas       uint64 = 2_414
	extCodeCopySize          uint64 = 24 * 1024
	// Both P256VERIFY and a one-pair BLS12-381 G1 MSM use 160-byte inputs.
	// The fixed gas copies five words into memory. Per-call gas includes
	// stack setup, warm STATICCALL overhead, the precompile, and POP.
	precompileNoApproveFixedGas uint64 = 40
	p256NoApproveCallGas        uint64 = 7_016
	blsG1MSMNoApproveCallGas    uint64 = 12_116
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
	// senderSloadNoApproveCode uses the loop counter as a storage key, so every
	// iteration performs a cold SLOAD from a distinct tx.sender slot.
	//
	//   PUSH0 CALLDATALOAD
	//   loop: JUMPDEST DUP1 SLOAD POP PUSH1(1) SWAP1 SUB
	//         DUP1 PUSH1(loop) JUMPI
	//   POP STOP
	senderSloadNoApproveCode = []byte{
		byte(vm.PUSH0), byte(vm.CALLDATALOAD),
		byte(vm.JUMPDEST), byte(vm.DUP1), byte(vm.SLOAD), byte(vm.POP),
		byte(vm.PUSH1), 0x01, byte(vm.SWAP1), byte(vm.SUB),
		byte(vm.DUP1), byte(vm.PUSH1), 0x02, byte(vm.JUMPI),
		byte(vm.POP), byte(vm.STOP),
	}
	revertCode         = []byte{byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.REVERT)}
	stackUnderflowCode = []byte{byte(vm.PUSH0), byte(vm.POP), byte(vm.POP)}
	extCodeCopyHelper  = common.HexToAddress("0x2222222222222222222222222222222222222222")
	p256VerifyInput    = common.FromHex("0x4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e")
	blsG1MSMInput      = common.FromHex("0x0000000000000000000000000000000002c7919b322a84cb1e6164043d745a53535edad9ef74533d3155900d4e1d63674b2616d87ca8b3dac6def99441cf196c00000000000000000000000000000000069f2ddefcadf0463b0c40e389837d1079781e04ccd8262623d5df6fb1989973ef6fcb8628b978a088e4f043f54d54391824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffd")
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

func senderSloadNoApproveIterations(gasLimit uint64) uint64 {
	if gasLimit <= senderSloadFixedGas {
		return 1
	}
	targetGas := gasLimit * 96 / 100
	return (targetGas - senderSloadFixedGas) / senderSloadLoopGas
}

func modexpNoApproveIterations(gasLimit uint64) uint64 {
	if gasLimit <= modexpNoApproveFixedGas {
		return 1
	}
	targetGas := gasLimit * 96 / 100
	return (targetGas - modexpNoApproveFixedGas + modexpNoApproveCallGas - 1) / modexpNoApproveCallGas
}

func modexpNoApproveCode(iterations uint64) []byte {
	// Keep the counter out of the EVM stack across calls: this code is
	// generated once per gas cap and statically unrolls the precompile calls.
	code := []byte{byte(vm.PUSH1), 0xc0, byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.CALLDATACOPY)}
	call := []byte{
		byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.PUSH1), 0xc0, byte(vm.PUSH0),
		byte(vm.PUSH1), 0x05, byte(vm.GAS), byte(vm.STATICCALL), byte(vm.POP),
	}
	for i := uint64(0); i < iterations; i++ {
		code = append(code, call...)
	}
	return append(code, byte(vm.STOP))
}

func modexpNoApproveData() []byte {
	// [baseLen=32, expLen=32, modLen=32, base, exponent, modulus]
	data := make([]byte, 6*32)
	data[31] = 32
	data[63] = 32
	data[95] = 32
	data[127] = 2
	for i := 128; i < 160; i++ {
		data[i] = 0xff
	}
	for i := 160; i < 192; i++ {
		data[i] = 0xff
	}
	data[191] = 0x43
	return data
}

func extCodeCopyNoApproveIterations(gasLimit uint64) uint64 {
	targetGas := gasLimit * 96 / 100
	if targetGas <= extCodeCopyFirstExtraGas+extCodeCopyCallGas {
		return 1
	}
	return (targetGas - extCodeCopyFirstExtraGas) / extCodeCopyCallGas
}

func extCodeCopyNoApproveCode(iterations uint64) []byte {
	code := make([]byte, 0, iterations*27+1)
	for i := uint64(0); i < iterations; i++ {
		code = append(code,
			byte(vm.PUSH2), byte(extCodeCopySize>>8), byte(extCodeCopySize&0xff),
			byte(vm.PUSH0),
			byte(vm.PUSH0),
			byte(vm.PUSH20),
		)
		code = append(code, extCodeCopyHelper[:]...)
		code = append(code, byte(vm.EXTCODECOPY))
	}
	return append(code, byte(vm.STOP))
}

func fixedPrecompileIterations(gasLimit, callGas uint64) uint64 {
	if gasLimit <= precompileNoApproveFixedGas {
		return 1
	}
	targetGas := gasLimit * 96 / 100
	return (targetGas - precompileNoApproveFixedGas + callGas - 1) / callGas
}

func fixedPrecompileNoApproveCode(inputSize, address uint16, iterations uint64) []byte {
	code := []byte{
		byte(vm.PUSH2), byte(inputSize >> 8), byte(inputSize),
		byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.CALLDATACOPY),
	}
	call := []byte{
		byte(vm.PUSH0), byte(vm.PUSH0),
		byte(vm.PUSH2), byte(inputSize >> 8), byte(inputSize),
		byte(vm.PUSH0),
		byte(vm.PUSH2), byte(address >> 8), byte(address),
		byte(vm.GAS), byte(vm.STATICCALL), byte(vm.POP),
	}
	for i := uint64(0); i < iterations; i++ {
		code = append(code, call...)
	}
	return append(code, byte(vm.STOP))
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

func newSenderSloadOutcomeCase(tb testing.TB, gasLimit uint64) (*FramePool, *types.Transaction) {
	tb.Helper()
	iterations := senderSloadNoApproveIterations(gasLimit)
	pool, statedb, config := newTestEnv()
	pool.verifyGasCap = gasLimit

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, senderSloadNoApproveCode, tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	for slot := uint64(1); slot <= iterations; slot++ {
		statedb.SetState(sender, common.BigToHash(new(big.Int).SetUint64(slot)), common.BigToHash(new(big.Int).SetUint64(slot)))
	}

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{{
		Mode:     types.FrameModeVerify,
		Flags:    vm.ApproveBoth,
		GasLimit: gasLimit,
		Data:     uint64Word(iterations),
	}}
	return pool, makeFrameTx(ftx)
}

func newModexpOutcomeCase(tb testing.TB, gasLimit uint64) (*FramePool, *types.Transaction) {
	tb.Helper()
	iterations := modexpNoApproveIterations(gasLimit)
	return newValidationOutcomeCase(tb, gasLimit, modexpNoApproveCode(iterations), modexpNoApproveData())
}

func newExtCodeCopyOutcomeCase(tb testing.TB, gasLimit uint64) (*FramePool, *types.Transaction) {
	tb.Helper()
	iterations := extCodeCopyNoApproveIterations(gasLimit)
	pool, statedb, config := newTestEnv()
	pool.verifyGasCap = gasLimit

	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	statedb.CreateAccount(sender)
	statedb.SetCode(sender, extCodeCopyNoApproveCode(iterations), tracing.CodeChangeUnspecified)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(extCodeCopyHelper)
	statedb.SetCode(extCodeCopyHelper, make([]byte, extCodeCopySize), tracing.CodeChangeUnspecified)

	ftx := baseFTX(sender, 0, config)
	ftx.Frames = []types.Frame{{
		Mode:     types.FrameModeVerify,
		Flags:    vm.ApproveBoth,
		GasLimit: gasLimit,
	}}
	return pool, makeFrameTx(ftx)
}

func newP256OutcomeCase(tb testing.TB, gasLimit uint64) (*FramePool, *types.Transaction) {
	tb.Helper()
	iterations := fixedPrecompileIterations(gasLimit, p256NoApproveCallGas)
	code := fixedPrecompileNoApproveCode(uint16(len(p256VerifyInput)), 0x0100, iterations)
	return newValidationOutcomeCase(tb, gasLimit, code, p256VerifyInput)
}

func newBLSG1MSMOutcomeCase(tb testing.TB, gasLimit uint64) (*FramePool, *types.Transaction) {
	tb.Helper()
	iterations := fixedPrecompileIterations(gasLimit, blsG1MSMNoApproveCallGas)
	code := fixedPrecompileNoApproveCode(uint16(len(blsG1MSMInput)), 0x000c, iterations)
	return newValidationOutcomeCase(tb, gasLimit, code, blsG1MSMInput)
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
				t.Fatalf("validation error = %v, outcome=%+v gas_used=%d, want did not APPROVE", err, outcome, outcome.gasUsed())
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

func TestSenderSloadNoApproveCorpusQualification(t *testing.T) {
	for _, gasLimit := range []uint64{100_000, 300_000, 500_000, 1_000_000} {
		t.Run(fmt.Sprintf("gas_%d", gasLimit), func(t *testing.T) {
			pool, tx := newSenderSloadOutcomeCase(t, gasLimit)

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

func TestModexpNoApproveCorpusQualification(t *testing.T) {
	for _, gasLimit := range []uint64{100_000, 300_000, 500_000, 1_000_000} {
		t.Run(fmt.Sprintf("gas_%d", gasLimit), func(t *testing.T) {
			pool, tx := newModexpOutcomeCase(t, gasLimit)

			_, outcome, err := pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0)
			if err == nil || !strings.Contains(err.Error(), "did not APPROVE") {
				t.Fatalf("validation error = %v, outcome=%+v gas_used=%d, want did not APPROVE", err, outcome, outcome.gasUsed())
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

func TestExtCodeCopyNoApproveCorpusQualification(t *testing.T) {
	for _, gasLimit := range []uint64{100_000, 300_000, 500_000, 1_000_000} {
		t.Run(fmt.Sprintf("gas_%d", gasLimit), func(t *testing.T) {
			pool, tx := newExtCodeCopyOutcomeCase(t, gasLimit)

			_, outcome, err := pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0)
			if err == nil || !strings.Contains(err.Error(), "did not APPROVE") {
				t.Fatalf("validation error = %v, outcome=%+v gas_used=%d, want did not APPROVE", err, outcome, outcome.gasUsed())
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

func testPrecompileNoApproveCorpusQualification(t *testing.T, build func(testing.TB, uint64) (*FramePool, *types.Transaction)) {
	t.Helper()
	for _, gasLimit := range []uint64{100_000, 300_000, 500_000, 1_000_000} {
		t.Run(fmt.Sprintf("gas_%d", gasLimit), func(t *testing.T) {
			pool, tx := build(t, gasLimit)

			_, outcome, err := pool.simulateVerifyFramesWithSignatureGasOutcome(tx, 0)
			if err == nil || !strings.Contains(err.Error(), "did not APPROVE") {
				t.Fatalf("validation error = %v, outcome=%+v gas_used=%d, want did not APPROVE", err, outcome, outcome.gasUsed())
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

func TestP256NoApproveCorpusQualification(t *testing.T) {
	testPrecompileNoApproveCorpusQualification(t, newP256OutcomeCase)
}

func TestBLSG1MSMNoApproveCorpusQualification(t *testing.T) {
	testPrecompileNoApproveCorpusQualification(t, newBLSG1MSMOutcomeCase)
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

func BenchmarkSenderSloadNoApproveValidation(b *testing.B) {
	for _, gasLimit := range []uint64{100_000, 300_000, 500_000, 1_000_000} {
		b.Run(fmt.Sprintf("gas_%d", gasLimit), func(b *testing.B) {
			pool, tx := newSenderSloadOutcomeCase(b, gasLimit)
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

func BenchmarkModexpNoApproveValidation(b *testing.B) {
	for _, gasLimit := range []uint64{100_000, 300_000, 500_000, 1_000_000} {
		b.Run(fmt.Sprintf("gas_%d", gasLimit), func(b *testing.B) {
			pool, tx := newModexpOutcomeCase(b, gasLimit)
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

func BenchmarkExtCodeCopyNoApproveValidation(b *testing.B) {
	for _, gasLimit := range []uint64{100_000, 300_000, 500_000, 1_000_000} {
		b.Run(fmt.Sprintf("gas_%d", gasLimit), func(b *testing.B) {
			pool, tx := newExtCodeCopyOutcomeCase(b, gasLimit)
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

func benchmarkPrecompileNoApproveValidation(b *testing.B, build func(testing.TB, uint64) (*FramePool, *types.Transaction)) {
	b.Helper()
	for _, gasLimit := range []uint64{100_000, 300_000, 500_000, 1_000_000} {
		b.Run(fmt.Sprintf("gas_%d", gasLimit), func(b *testing.B) {
			pool, tx := build(b, gasLimit)
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

func BenchmarkP256NoApproveValidation(b *testing.B) {
	benchmarkPrecompileNoApproveValidation(b, newP256OutcomeCase)
}

func BenchmarkBLSG1MSMNoApproveValidation(b *testing.B) {
	benchmarkPrecompileNoApproveValidation(b, newBLSG1MSMOutcomeCase)
}
