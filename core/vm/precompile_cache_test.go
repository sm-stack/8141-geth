// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

type countingCacheablePrecompile struct {
	runs   atomic.Uint64
	gas    uint64
	output []byte
	err    error
}

func (p *countingCacheablePrecompile) RequiredGas([]byte) uint64 { return p.gas }
func (p *countingCacheablePrecompile) Run([]byte) ([]byte, error) {
	p.runs.Add(1)
	return common.CopyBytes(p.output), p.err
}
func (p *countingCacheablePrecompile) Name() string    { return "COUNTING" }
func (p *countingCacheablePrecompile) Cacheable() bool { return true }

// allPrecompileSets returns every set a node can run with, labelled by a fork
// that selects it. It walks the flags of params.Rules and asks
// activePrecompiledContracts what each one activates, so a set added for a new
// fork is covered here without anyone remembering to list it.
func allPrecompileSets() map[string]PrecompiledContracts {
	var (
		rules = reflect.TypeOf(params.Rules{})
		seen  = make(map[*PrecompiledContracts]bool)
		sets  = make(map[string]PrecompiledContracts)
	)
	// The zero value picks whatever the switch falls through to.
	base := activePrecompiledContracts(params.Rules{})
	seen[base], sets["default"] = true, *base

	for i := range rules.NumField() {
		field := rules.Field(i)
		if field.Type.Kind() != reflect.Bool {
			continue
		}
		// Activate only this field so the fork resolves to the set it gates.
		var forked params.Rules
		reflect.ValueOf(&forked).Elem().Field(i).SetBool(true)

		// Later forks shadow earlier ones, so the first flag reaching a set is
		// the one that names it.
		if set := activePrecompiledContracts(forked); !seen[set] {
			seen[set], sets[strings.TrimPrefix(field.Name, "Is")] = true, *set
		}
	}
	return sets
}

// probeGasLimit is a generous stand-in for the block gas limit, bounding the
// probe corpus to invocations the EVM could actually pay to run.
const probeGasLimit = 1 << 30

// cacheProbeInputs builds inputs that stress normalization: the lengths each
// precompile cares about, either side of them, zero padded and non-zero padded
// variants, and a few random ones.
//
// Random bytes alone are not enough. They fail every signature and curve check,
// so a precompile whose failure path returns one fixed value looks consistent
// no matter how badly its inputs are merged. The corpus therefore also carries
// every input from testdata, which is where the succeeding cases live, and pads
// each of them so a valid call and its padded form can be caught colliding.
func cacheProbeInputs(t *testing.T, rng *rand.Rand) [][]byte {
	lengths := []int{0, 1, 31, 32, 63, 64, 65, 95, 96, 97, 127, 128, 129, 160, 161,
		191, 192, 193, 213, 214, 255, 256, 257, 288, 384, 385, 512, 576, 1920, 4096, 8192, 8193}

	var inputs [][]byte
	for _, n := range lengths {
		inputs = append(inputs, make([]byte, n)) // all zero

		filled := make([]byte, n)
		rng.Read(filled)
		inputs = append(inputs, filled)

		// A short body followed by zeros, which normalization is allowed to
		// drop, and by non-zeros, which it is not unless unread.
		if n >= 64 {
			zeroTail := make([]byte, n)
			copy(zeroTail, filled[:32])
			inputs = append(inputs, zeroTail)

			oneTail := make([]byte, n)
			copy(oneTail, filled[:32])
			for i := 32; i < n; i++ {
				oneTail[i] = 1
			}
			inputs = append(inputs, oneTail)
		}
	}
	for _, fixture := range precompileFixtureInputs(t) {
		inputs = append(inputs, fixture)
		for _, extra := range []int{1, 64, 512} {
			padded := make([]byte, len(fixture)+extra)
			copy(padded, fixture)
			inputs = append(inputs, padded)

			nonzero := make([]byte, len(fixture)+extra)
			copy(nonzero, fixture)
			for i := len(fixture); i < len(nonzero); i++ {
				nonzero[i] = 0xff
			}
			inputs = append(inputs, nonzero)
		}
	}
	return inputs
}

// precompileFixtureInputs reads every precompile test vector on disk. These are
// the inputs that actually exercise success paths.
func precompileFixtureInputs(t *testing.T) [][]byte {
	t.Helper()

	entries, err := os.ReadDir("testdata/precompiles")
	if err != nil {
		t.Fatalf("reading precompile fixtures: %v", err)
	}
	var inputs [][]byte
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		blob, err := os.ReadFile(filepath.Join("testdata/precompiles", entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		var cases []struct{ Input string }
		if err := json.Unmarshal(blob, &cases); err != nil {
			t.Fatalf("parsing %s: %v", entry.Name(), err)
		}
		for _, c := range cases {
			if in, err := hex.DecodeString(c.Input); err == nil && len(in) <= maxCacheablePrecompileInput {
				inputs = append(inputs, in)
			}
		}
	}
	if len(inputs) == 0 {
		t.Fatal("no precompile fixtures found")
	}
	return inputs
}

// TestPrecompileCacheNormalizationSound is the load bearing test of the cache:
// two inputs that normalize to the same key are served the same entry, so they
// must run to the same result. A violation here is a consensus bug, not a
// performance one.
func TestPrecompileCacheNormalizationSound(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	inputs := cacheProbeInputs(t, rng)

	for fork, set := range allPrecompileSets() {
		for addr, p := range set {
			type outcome struct {
				input  []byte
				output []byte
				err    error
			}
			seen := make(map[string]outcome)
			for _, in := range inputs {
				// Skip what the EVM could never reach. A random modexp header
				// declares operands nobody can pay for, and RunPrecompiledContract
				// charges before it runs, so Run never sees them.
				if p.RequiredGas(in) > probeGasLimit {
					continue
				}
				key, ok := precompileCacheKey(p, in)
				if !ok {
					continue
				}
				output, err := p.Run(in)
				prev, dup := seen[string(key)]
				if !dup {
					seen[string(key)] = outcome{in, output, err}
					continue
				}
				if !bytes.Equal(output, prev.output) || !errEqual(err, prev.err) {
					t.Errorf("%s %s (%x): inputs %x and %x share key %x but run differently:\n  %x / %v\n  %x / %v",
						fork, p.Name(), addr, prev.input, in, key, prev.output, prev.err, output, err)
				}
			}
		}
	}
}

// TestPrecompileCacheNormalizationCollapsesPadding checks the other direction
// for the precompiles that read a fixed prefix: padding must land on the entry
// the unpadded call already made, otherwise every padded call mints its own.
func TestPrecompileCacheNormalizationCollapsesPadding(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for _, tc := range []struct {
		name  string
		p     PrecompiledContract
		read  int
		valid int
	}{
		{"ecrecover", &ecrecover{}, ecRecoverInputLength, ecRecoverInputLength},
		{"bn256ScalarMul", &bn256ScalarMulIstanbul{}, bn256ScalarMulInputLength, bn256ScalarMulInputLength},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := make([]byte, tc.valid)
			rng.Read(body)

			want, ok := precompileCacheKey(tc.p, body)
			if !ok {
				t.Fatal("unpadded input is not cacheable")
			}
			for _, n := range []int{tc.read + 1, tc.read * 2, maxCacheablePrecompileInput} {
				padded := make([]byte, n)
				copy(padded, body)
				got, ok := precompileCacheKey(tc.p, padded)
				if !ok {
					t.Errorf("input padded to %d is not cacheable", n)
					continue
				}
				if !bytes.Equal(got, want) {
					t.Errorf("padding to %d changed the key: %x != %x", n, got, want)
				}
			}
		})
	}
	// modexp declares its own operand lengths, so padding past them collapses
	// too even though the read length is not a constant.
	modexp := &bigModExp{eip2565: true}
	header := make([]byte, modExpHeaderLength)
	header[31], header[63], header[95] = 1, 1, 1 // one byte each of base, exp, mod
	body := append(append([]byte{}, header...), 2, 3, 5)

	want, ok := precompileCacheKey(modexp, body)
	if !ok {
		t.Fatal("modexp body is not cacheable")
	}
	padded := make([]byte, 4096)
	copy(padded, body)
	got, ok := precompileCacheKey(modexp, padded)
	if !ok {
		t.Fatal("padded modexp is not cacheable")
	}
	if !bytes.Equal(got, want) {
		t.Errorf("modexp padding changed the key: %x != %x", got, want)
	}
}

// TestPrecompileCacheOptIn asserts that caching is opt in, so a new precompile
// cannot be enrolled by accident before anyone has checked that its output is a
// pure function of its input.
func TestPrecompileCacheOptIn(t *testing.T) {
	if _, ok := precompileCacheKey(&undeclaredPrecompile{}, nil); ok {
		t.Fatal("a precompile that does not implement CacheablePrecompile is cacheable")
	}
}

// TestPrecompileCacheHit runs a precompile twice through the cache and asserts
// the served result matches the computed one, gas included.
func TestPrecompileCacheHit(t *testing.T) {
	var (
		cache = NewPrecompileCache()
		addr  = common.BytesToAddress([]byte{8})
		p     = PrecompiledContractsOsaka[addr]
		rules = params.Rules{IsBerlin: true, IsIstanbul: true, IsByzantium: true}
		input = make([]byte, 192)
	)
	gasCost := p.RequiredGas(input)
	key, ok := precompileCacheKey(p, input)
	if !ok {
		t.Fatalf("%s is not cacheable, pick a different fixture", p.Name())
	}
	want, wantGas, wantErr := RunPrecompiledContract(nil, p, addr, input, NewGasBudget(gasCost, 0), nil, rules, cache)
	got, gotGas, gotErr := RunPrecompiledContract(nil, p, addr, input, NewGasBudget(gasCost, 0), nil, rules, cache)
	if !bytes.Equal(got, want) {
		t.Errorf("cached output %x, computed %x", got, want)
	}
	if gotGas != wantGas {
		t.Errorf("cached gas %v, computed %v", gotGas, wantGas)
	}
	if gotErr != wantErr {
		t.Errorf("cached error %v, computed %v", gotErr, wantErr)
	}
	// Prove the second call was served rather than recomputed, the assertions
	// above would also pass if the cache never stored anything.
	scope := precompileCacheScope{activePrecompiledContracts(rules), addr}
	if _, ok := cache.load(scope, key); !ok {
		t.Error("result was not stored under its key")
	}
}

func TestValidationPrecompileMemoHitPreservesGasAndOutput(t *testing.T) {
	const gasCost = uint64(1_234)
	var (
		memo  = NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 2, MaxBytes: 4096})
		addr  = common.HexToAddress("0x01")
		input = []byte{1, 2, 3}
		p     = &countingCacheablePrecompile{gas: gasCost, output: []byte{4, 5, 6}}
		rules = params.Rules{IsBerlin: true}
	)
	want, wantGas, wantErr := RunPrecompiledContract(nil, p, addr, input, NewGasBudget(gasCost+99, 0), nil, rules, memo)
	want[0] = 0xff // Returned bytes must not alias the stored entry.
	got, gotGas, gotErr := RunPrecompiledContract(nil, p, addr, input, NewGasBudget(gasCost+99, 0), nil, rules, memo)
	if !bytes.Equal(got, []byte{4, 5, 6}) {
		t.Fatalf("cached output = %x, want 040506", got)
	}
	if gotGas != wantGas || !errEqual(gotErr, wantErr) {
		t.Fatalf("cached outcome gas/error = %v/%v, want %v/%v", gotGas, gotErr, wantGas, wantErr)
	}
	if runs := p.runs.Load(); runs != 1 {
		t.Fatalf("actual runs = %d, want 1", runs)
	}
	stats := memo.Stats()
	if stats.Hits != 1 || stats.Misses != 1 || stats.ActualRuns != 1 || stats.Stores != 1 || stats.CachedGas != gasCost {
		t.Fatalf("memo stats: %+v", stats)
	}
	if stats.BeforeMutableHits != 1 || stats.BeforeMutableMisses != 1 || stats.BeforeMutableActualRuns != 1 || stats.AfterMutableHits != 0 {
		t.Fatalf("memo watershed stats: %+v", stats)
	}
	if !memo.Complete() {
		t.Fatal("complete memo reported incomplete")
	}
}

func TestValidationPrecompileMemoHitPreservesStateTouch(t *testing.T) {
	memo := NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 1, MaxBytes: 4096})
	p := &countingCacheablePrecompile{gas: 1, output: []byte{1}}
	addr := common.HexToAddress("0x01")
	statedb := &mockStateDB{touches: make(map[common.Address]int)}
	rules := params.Rules{IsAmsterdam: true}
	for range 2 {
		if _, _, err := RunPrecompiledContract(statedb, p, addr, []byte{1}, NewGasBudget(1, 0), nil, rules, memo); err != nil {
			t.Fatal(err)
		}
	}
	if touches := statedb.touches[addr]; touches != 2 {
		t.Fatalf("precompile state touches = %d, want 2", touches)
	}
	if runs := p.runs.Load(); runs != 1 {
		t.Fatalf("precompile actual runs = %d, want 1", runs)
	}
}

func TestValidationPrecompileMemoFrameWatershedIsLocal(t *testing.T) {
	memo := NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 2, MaxBytes: 4096})
	p := &countingCacheablePrecompile{gas: 1, output: []byte{1}}
	addr := common.HexToAddress("0x01")
	rules := params.Rules{}

	stateFirst := memo.ValidationFrameView()
	stateFirst.MarkValidationMutable()
	if _, _, err := RunPrecompiledContract(nil, p, addr, []byte{1}, NewGasBudget(1, 0), nil, rules, stateFirst); err != nil {
		t.Fatal(err)
	}
	pureFirst := memo.ValidationFrameView()
	if _, _, err := RunPrecompiledContract(nil, p, addr, []byte{1}, NewGasBudget(1, 0), nil, rules, pureFirst); err != nil {
		t.Fatal(err)
	}
	stats := memo.Stats()
	if stats.AfterMutableMisses != 1 || stats.AfterMutableActualRuns != 1 || stats.BeforeMutableHits != 1 {
		t.Fatalf("frame-local watershed stats: %+v", stats)
	}
}

func TestValidationPrecompileMemoOOGPrecedesLookup(t *testing.T) {
	memo := NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 1, MaxBytes: 1024})
	p := &countingCacheablePrecompile{gas: 100, output: []byte{1}}
	_, remaining, err := RunPrecompiledContract(nil, p, common.HexToAddress("0x01"), []byte{1}, NewGasBudget(99, 0), nil, params.Rules{}, memo)
	if !errors.Is(err, ErrOutOfGas) || remaining.ExecutionGas != 99 {
		t.Fatalf("OOG result = %v, %v", remaining, err)
	}
	if stats := memo.Stats(); stats != (PrecompileCacheStats{}) {
		t.Fatalf("OOG touched memo: %+v", stats)
	}
}

func TestValidationPrecompileMemoStrictBoundsAndCopies(t *testing.T) {
	var (
		scope = precompileCacheScope{set: activePrecompiledContracts(params.Rules{}), addr: common.HexToAddress("0x01")}
		key   = []byte{1, 2, 3}
		out   = []byte{4, 5}
		size  = validationMemoEntryOverhead + common.AddressLength + uint64(len(key)+len(out))
	)
	t.Run("exact byte limit", func(t *testing.T) {
		memo := NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 1, MaxBytes: size})
		memo.store(scope, key, out)
		key[0], out[0] = 9, 9
		got, ok := memo.load(scope, []byte{1, 2, 3})
		if !ok || !bytes.Equal(got, []byte{4, 5}) {
			t.Fatalf("copied entry = %x, %v", got, ok)
		}
		stats := memo.Stats()
		if stats.Entries != 1 || stats.AccountedBytes != size || stats.Saturated != 0 || !memo.Complete() {
			t.Fatalf("exact-limit stats: %+v complete=%v", stats, memo.Complete())
		}
	})
	t.Run("one byte over", func(t *testing.T) {
		memo := NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 1, MaxBytes: size - 1})
		memo.store(scope, []byte{1, 2, 3}, []byte{4, 5})
		stats := memo.Stats()
		if stats.Entries != 0 || stats.Saturated != 1 || memo.Complete() {
			t.Fatalf("over-limit stats: %+v complete=%v", stats, memo.Complete())
		}
	})
	t.Run("entry limit does not evict", func(t *testing.T) {
		memo := NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 1, MaxBytes: 4096})
		memo.store(scope, []byte{1}, []byte{2})
		memo.store(scope, []byte{3}, []byte{4})
		if _, ok := memo.load(scope, []byte{1}); !ok {
			t.Fatal("saturation evicted the first admission artifact")
		}
		if _, ok := memo.load(scope, []byte{3}); ok {
			t.Fatal("over-limit entry was stored")
		}
		if stats := memo.Stats(); stats.Entries != 1 || stats.Saturated != 1 {
			t.Fatalf("entry-limit stats: %+v", stats)
		}
	})
}

func TestValidationPrecompileMemoExactInputAndForkScope(t *testing.T) {
	memo := NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 4, MaxBytes: 4096})
	p := &countingCacheablePrecompile{gas: 1, output: []byte{1}}
	addr := common.HexToAddress("0x01")
	otherAddr := common.HexToAddress("0x02")
	homestead := params.Rules{}
	berlin := params.Rules{IsBerlin: true}
	for _, call := range []struct {
		input []byte
		rules params.Rules
		addr  common.Address
	}{
		{[]byte{1, 2}, homestead, addr},
		{[]byte{1, 3}, homestead, addr},
		{[]byte{1, 2}, berlin, addr},
		{[]byte{1, 2}, homestead, otherAddr},
	} {
		if _, _, err := RunPrecompiledContract(nil, p, call.addr, call.input, NewGasBudget(1, 0), nil, call.rules, memo); err != nil {
			t.Fatal(err)
		}
	}
	if runs := p.runs.Load(); runs != 4 {
		t.Fatalf("exact input/fork/address actual runs = %d, want 4", runs)
	}
	if stats := memo.Stats(); stats.Misses != 4 || stats.Hits != 0 || stats.Stores != 4 {
		t.Fatalf("exact input/fork/address stats: %+v", stats)
	}
}

func TestValidationPrecompileMemoIsolationAndDisabledBehavior(t *testing.T) {
	limits := ValidationPrecompileMemoLimits{MaxEntries: 1, MaxBytes: 4096}
	first := NewValidationPrecompileMemo(limits)
	second := NewValidationPrecompileMemo(limits)
	scope := precompileCacheScope{set: activePrecompiledContracts(params.Rules{}), addr: common.HexToAddress("0x01")}
	first.store(scope, []byte{1}, []byte{1})
	first.store(scope, []byte{2}, []byte{2})
	second.store(scope, []byte{2}, []byte{2})
	if first.Complete() || !second.Complete() || second.Stats().Entries != 1 {
		t.Fatalf("transaction-local saturation leaked: first=%+v second=%+v", first.Stats(), second.Stats())
	}

	p := &countingCacheablePrecompile{gas: 7, output: []byte{1}}
	for range 2 {
		if _, gas, err := RunPrecompiledContract(nil, p, scope.addr, []byte{3}, NewGasBudget(9, 0), nil, params.Rules{}, nil); err != nil || gas.ExecutionGas != 2 {
			t.Fatalf("cache-disabled invocation = %v, %v", gas, err)
		}
	}
	if runs := p.runs.Load(); runs != 2 {
		t.Fatalf("cache-disabled actual runs = %d, want 2", runs)
	}
}

func TestValidationPrecompileMemoFailureIsIncomplete(t *testing.T) {
	memo := NewValidationPrecompileMemo(ValidationPrecompileMemoLimits{MaxEntries: 1, MaxBytes: 1024})
	p := &countingCacheablePrecompile{gas: 1, err: errors.New("deterministic failure")}
	_, _, err := RunPrecompiledContract(nil, p, common.HexToAddress("0x01"), []byte{1}, NewGasBudget(1, 0), nil, params.Rules{}, memo)
	if err == nil {
		t.Fatal("expected precompile failure")
	}
	stats := memo.Stats()
	if stats.ActualRuns != 1 || stats.Uncacheable != 1 || stats.Stores != 0 || memo.Complete() {
		t.Fatalf("failure stats: %+v complete=%v", stats, memo.Complete())
	}
}

func errEqual(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Error() == b.Error()
}

// undeclaredPrecompile stands in for a precompile added without a caching
// decision.
type undeclaredPrecompile struct{}

func (c *undeclaredPrecompile) RequiredGas([]byte) uint64  { return 0 }
func (c *undeclaredPrecompile) Run([]byte) ([]byte, error) { return nil, nil }
func (c *undeclaredPrecompile) Name() string               { return "UNDECLARED" }

// precompileCacheSynthetic lists the precompiles with no test vectors on disk,
// benchmarked on generated inputs instead.
var precompileCacheSynthetic = []struct{ name, addr string }{
	{"SHA256", "02"}, {"RIPEMD160", "03"}, {"ID", "04"},
}

// precompileCacheFixtures maps a testdata fixture to the address its precompile
// sits at in allPrecompiles. The Byzantium bn256 variants share their Run with
// the Istanbul ones and only differ in price, so they would be duplicate rows.
var precompileCacheFixtures = []struct{ fixture, addr string }{
	{"ecRecover", "01"}, {"modexp_eip2565", "f5"}, {"bn256Add", "06"},
	{"bn256ScalarMul", "07"}, {"bn256Pairing", "08"}, {"blake2F", "09"},
	{"pointEvaluation", "0a"}, {"blsG1Add", "f0a"}, {"blsG2Add", "f0c"},
	{"blsG1MultiExp", "f0b"}, {"blsG2MultiExp", "f0d"}, {"blsPairing", "f0e"},
	{"blsMapG1", "f0f"}, {"blsMapG2", "f10"}, {"p256Verify", "0b"},
}

// BenchmarkPrecompileCacheHitVsRun compares serving a warm entry against just
// running the precompile, over the real test vectors. It is the evidence for
// which precompiles opt in: caching only belongs where the hit is the cheaper
// path, and for sha256 and blake2F that margin is thin enough to be worth
// rechecking on the machine you care about. Run it with -count and read
// medians, the first case measured absorbs the warm-up.
func BenchmarkPrecompileCacheHitVsRun(b *testing.B) {
	rules := params.Rules{IsByzantium: true, IsIstanbul: true, IsBerlin: true, IsCancun: true, IsPrague: true, IsOsaka: true}
	set := activePrecompiledContracts(rules)

	for _, bench := range precompileCacheFixtures {
		tests, err := loadJson(bench.fixture)
		if err != nil {
			b.Fatalf("%s: %v", bench.fixture, err)
		}
		addr := common.HexToAddress(bench.addr)
		p := allPrecompiles[addr]
		for _, tc := range tests {
			if tc.NoBenchmark {
				continue
			}
			in := common.Hex2Bytes(tc.Input)
			key, ok := precompileCacheKey(p, in)
			if !ok || p.RequiredGas(in) > probeGasLimit {
				continue
			}
			out, err := p.Run(in)
			if err != nil {
				continue // errors are never cached, there is no hit to measure
			}
			cache := NewPrecompileCache()
			scope := precompileCacheScope{set, addr}
			cache.store(scope, key, out)

			label := fmt.Sprintf("%s/%s/len=%d", bench.fixture, tc.Name, len(in))
			b.Run(label+"/hit", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					k, _ := precompileCacheKey(p, in)
					cache.load(scope, k)
				}
			})
			b.Run(label+"/run", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					p.Run(in)
				}
			})
		}
	}
}

// BenchmarkPrecompileCacheSynthetic covers the precompiles that ship no test
// vectors, which are also the ones whose caching decision is closest. Their
// cost scales with input length rather than varying per vector, so synthetic
// inputs of a few sizes say more here than a fixture corpus would.
func BenchmarkPrecompileCacheSynthetic(b *testing.B) {
	rules := params.Rules{IsByzantium: true, IsIstanbul: true, IsBerlin: true, IsCancun: true, IsPrague: true, IsOsaka: true}
	set := activePrecompiledContracts(rules)

	for _, tc := range precompileCacheSynthetic {
		addr := common.HexToAddress(tc.addr)
		p := allPrecompiles[addr]
		for _, n := range []int{32, 128, 1024, 8192} {
			in := make([]byte, n)
			for i := range in {
				in[i] = byte(i)
			}
			out, err := p.Run(in)
			if err != nil {
				continue
			}
			var (
				scope = precompileCacheScope{set, addr}
				cache = NewPrecompileCache()
			)
			label := fmt.Sprintf("%s/len=%d", tc.name, n)

			// Only the precompiles that opt in get a hit measured, going through
			// the same path RunPrecompiledContract does. For the one that does
			// not, its run cost against the lookups below is the whole argument.
			if key, ok := precompileCacheKey(p, in); ok && len(out) <= maxCacheablePrecompileOutput {
				cache.store(scope, key, out)
				b.Run(label+"/hit", func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						k, _ := precompileCacheKey(p, in)
						cache.load(scope, k)
					}
				})
			}
			b.Run(label+"/run", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					p.Run(in)
				}
			})
		}
	}
}
