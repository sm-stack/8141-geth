// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

func TestReusableValidationGasCountsRetainedInvocations(t *testing.T) {
	memo := NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 1, MaxBytes: 4096})
	call := func(view *PrecompileCache, input []byte) {
		t.Helper()
		_, remaining, err := RunPrecompiledContract(nil, &ecrecover{}, common.HexToAddress("0x01"), input, NewGasBudget(params.EcrecoverGas+17, 0), nil, params.Rules{}, view)
		if err != nil || remaining.ExecutionGas != 17 {
			t.Fatalf("outcome = %v, %v", remaining, err)
		}
	}
	for range 2 { // Admission miss and replay hit must give the same per-run c.
		view := memo.ValidationFrameView()
		call(view, []byte{1})
		call(view, []byte{1}) // Same retained entry, two skipped invocations on replay.
		call(view, []byte{2}) // Entry cap: this invocation earns no credit.
		view.MarkValidationMutable()
		call(view, []byte{1}) // Hit after the watershed earns no credit either.
		if got := view.ReusableValidationGas(); got != 2*params.EcrecoverGas {
			t.Fatalf("credit = %d", got)
		}
	}
	if got := memo.ReusableValidationGas(); got != 0 {
		t.Fatalf("frame credit leaked into shared handle: %d", got)
	}
	if stats := memo.Stats(); stats.Stores != 1 || stats.ActualRuns != 3 || stats.Hits != 5 {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestValidationMemoEligibility(t *testing.T) {
	memo := NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 8, MaxBytes: 16384})
	for _, test := range []struct {
		name  string
		p     PrecompiledContract
		input []byte
		want  bool
	}{
		{"ecrecover", &ecrecover{}, make([]byte, 128), true},
		{"input boundary", &ecrecover{}, make([]byte, 1024), true},
		{"oversized before normalization", &ecrecover{}, make([]byte, 1025), false},
		{"sha", &sha256hash{}, make([]byte, 64), false},
		{"ripemd high gas", &ripemd160hash{}, make([]byte, 1024), false},
		{"add", &bn256AddIstanbul{}, make([]byte, 128), false},
		{"mul", &bn256ScalarMulIstanbul{}, make([]byte, 96), true},
		{"cheap modexp", &bigModExp{eip2565: true}, make([]byte, 96), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, got := memo.invocationKey(test.p, test.input, test.p.RequiredGas(test.input)); got != test.want {
				t.Fatalf("eligible = %v, want %v", got, test.want)
			}
		})
	}
	// This restriction is local policy; block processing retains its existing cache.
	shared := NewPrecompileCache()
	if _, ok := shared.invocationKey(&sha256hash{}, []byte{1}, 72); !ok {
		t.Fatal("validation policy changed the shared cache")
	}
}
