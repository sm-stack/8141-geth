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
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/metrics"
)

var (
	precompileCacheHitMeter          = metrics.NewRegisteredMeter("chain/cache/precompile/hit", nil)
	precompileCacheMissMeter         = metrics.NewRegisteredMeter("chain/cache/precompile/miss", nil)
	precompileCachePrefetchHitMeter  = metrics.NewRegisteredMeter("chain/cache/precompile/prefetch/hit", nil)
	precompileCachePrefetchMissMeter = metrics.NewRegisteredMeter("chain/cache/precompile/prefetch/miss", nil)
)

const (
	// maxCacheablePrecompileInput bounds the normalized input size eligible for
	// result caching. The key is the input itself, so this also bounds how much
	// an entry can cost.
	maxCacheablePrecompileInput = 8192

	// maxCacheablePrecompileOutput bounds the output size stored in the
	// cache, keeping the worst case memory use of an entry small.
	maxCacheablePrecompileOutput = 1024

	// maxCacheablePrecompileBytes is the budget each precompile gets per fork,
	// counting keys and values along with what an entry costs to hold. Entries
	// run from tens of bytes to kilobytes, so a budget in entries would mean
	// very different memory depending on the mix.
	maxCacheablePrecompileBytes = 1024 * 1024

	// validationMemoEntryOverhead conservatively accounts for the map entry,
	// string and slice headers, fork/precompile discriminator, and allocator
	// bookkeeping retained by one transaction-local memo entry.
	validationMemoEntryOverhead uint64 = 128

	// Bound validation memo lookup/allocation independently of the shared cache.
	maxValidationMemoInput = 1024
	minValidationMemoGas   = 2000
)

// ValidationPrecompileMemoLimits bounds one transaction's validation memo.
type ValidationPrecompileMemoLimits struct {
	MaxEntries int
	MaxBytes   uint64
}

// PrecompileCacheStats reports transaction-local validation memo activity.
// CachedGas is gas that was still charged on cache hits while CPU recomputation
// was skipped; it is not gas saved by the transaction.
type PrecompileCacheStats struct {
	Hits                     uint64
	Misses                   uint64
	ActualRuns               uint64
	BeforeMutableHits        uint64
	BeforeMutableMisses      uint64
	BeforeMutableActualRuns  uint64
	AfterMutableHits         uint64
	AfterMutableMisses       uint64
	AfterMutableActualRuns   uint64
	Stores                   uint64
	Uncacheable              uint64
	BeforeMutableUncacheable uint64
	AfterMutableUncacheable  uint64
	Saturated                uint64
	BeforeMutableSaturated   uint64
	AfterMutableSaturated    uint64
	Entries                  uint64
	AccountedBytes           uint64
	CachedGas                uint64
}

// PrecompileCache is a thread-safe cache of precompile outputs, shared between
// the state prefetcher and block processing so the serial pass can reuse what
// the prefetcher already computed. Each precompile gets its own cache per fork,
// so results never cross a repricing and a cheap precompile cannot evict the
// results of an expensive one.
type PrecompileCache struct {
	data       *precompileCacheData
	validation *validationPrecompileMemo

	// Meters are per handle, split between the main pass and the prefetcher
	// so the hit rate of the main pass stays readable on its own.
	prefix   string
	hit      *metrics.Meter
	miss     *metrics.Meter
	mu       sync.RWMutex
	meters   map[common.Address]*precompileCacheMeters
	prefetch *PrecompileCache

	// validationMutable is local to a validation frame view. The memo storage
	// and counters remain shared by every frame belonging to the transaction.
	validationMutable     atomic.Bool
	validationReusableGas atomic.Uint64
}

type validationPrecompileMemo struct {
	mu                    sync.RWMutex
	limits                ValidationPrecompileMemoLimits
	entries               map[precompileCacheScope]map[string]validationPrecompileResult
	stats                 PrecompileCacheStats
	complete              bool
	completeBeforeMutable bool
}

type validationPrecompileResult struct {
	output []byte
	err    error
}

// precompileCacheData is the storage shared by the two cache handles.
type precompileCacheData struct {
	mu     sync.RWMutex
	caches map[precompileCacheScope]*lru.SizeConstrainedCache[string, []byte]
}

// precompileCacheScope identifies the cache of one precompile at one fork. The
// set pointer keeps forks apart, the address keeps precompiles apart.
type precompileCacheScope struct {
	set  *PrecompiledContracts
	addr common.Address
}

// precompileCacheMeters holds the per-address hit and miss meters.
type precompileCacheMeters struct {
	hit  *metrics.Meter
	miss *metrics.Meter
}

// NewPrecompileCache constructs a precompile result cache.
func NewPrecompileCache() *PrecompileCache {
	data := &precompileCacheData{
		caches: make(map[precompileCacheScope]*lru.SizeConstrainedCache[string, []byte]),
	}
	return &PrecompileCache{
		data:   data,
		prefix: "chain/cache/precompile",
		hit:    precompileCacheHitMeter,
		miss:   precompileCacheMissMeter,
		meters: make(map[common.Address]*precompileCacheMeters),

		prefetch: &PrecompileCache{
			data:   data,
			prefix: "chain/cache/precompile/prefetch",
			hit:    precompileCachePrefetchHitMeter,
			miss:   precompileCachePrefetchMissMeter,
			meters: make(map[common.Address]*precompileCacheMeters),
		},
	}
}

// NewValidationPrecompileMemo constructs a strict-bounded, transaction-local
// precompile result cache. It never evicts an admission artifact: calls that do
// not fit execute normally and make Complete report false.
func NewValidationPrecompileMemo(limits ValidationPrecompileMemoLimits) *PrecompileCache {
	return &PrecompileCache{validation: &validationPrecompileMemo{
		limits:                limits,
		entries:               make(map[precompileCacheScope]map[string]validationPrecompileResult),
		complete:              true,
		completeBeforeMutable: true,
	}}
}

// PrefetchView returns a handle of the same cache that marks the prefetcher
// meters instead of the main pass ones.
func (c *PrecompileCache) PrefetchView() *PrecompileCache {
	if c == nil || c.validation != nil {
		return nil
	}
	return c.prefetch
}

// ValidationFrameView returns a frame-local handle over the transaction memo.
// The caller marks a later frame mutable at entry when a prior frame crossed
// the transaction watershed. Exact cached values and counters remain shared.
func (c *PrecompileCache) ValidationFrameView() *PrecompileCache {
	if c == nil || c.validation == nil {
		return c
	}
	return &PrecompileCache{validation: c.validation}
}

// MarkValidationMutable advances this frame view past its first mutable read.
func (c *PrecompileCache) MarkValidationMutable() {
	if c != nil && c.validation != nil {
		c.validationMutable.Store(true)
	}
}

// Stats returns a consistent snapshot of transaction-local memo counters.
func (c *PrecompileCache) Stats() PrecompileCacheStats {
	if c == nil || c.validation == nil {
		return PrecompileCacheStats{}
	}
	c.validation.mu.RLock()
	defer c.validation.mu.RUnlock()
	return c.validation.stats
}

// Complete reports whether every eligible invocation result encountered by
// this validation memo was retained. A miss always falls back to normal
// execution, so incompleteness affects performance only, not correctness.
func (c *PrecompileCache) Complete() bool {
	if c == nil || c.validation == nil {
		return false
	}
	c.validation.mu.RLock()
	defer c.validation.mu.RUnlock()
	return c.validation.complete
}

// CompleteBeforeFirstMutable reports whether every eligible invocation before
// the transaction-global mutable watershed was retained. Later incompleteness
// weakens acceleration but cannot hide uncached pure-prefix replay.
func (c *PrecompileCache) CompleteBeforeFirstMutable() bool {
	if c == nil || c.validation == nil {
		return false
	}
	c.validation.mu.RLock()
	defer c.validation.mu.RUnlock()
	return c.validation.completeBeforeMutable
}

// loadResult retrieves a cached validation result, including deterministic
// failures. The chain cache stores successful outputs only.
func (c *PrecompileCache) loadResult(scope precompileCacheScope, key []byte) ([]byte, error, bool) {
	if c.validation != nil {
		return c.validationLoadResult(scope, key)
	}
	output, ok := c.load(scope, key)
	return output, nil, ok
}

// load retrieves the cached output for the given key. The returned slice is
// a private copy owned by the caller, entries cross goroutine boundaries.
func (c *PrecompileCache) load(scope precompileCacheScope, key []byte) ([]byte, bool) {
	if c.validation != nil {
		output, _, ok := c.validationLoadResult(scope, key)
		return output, ok
	}
	c.data.mu.RLock()
	results := c.data.caches[scope]
	c.data.mu.RUnlock()

	meters := c.metersFor(scope.addr)
	if results != nil {
		if output, ok := results.Get(string(key)); ok {
			c.hit.Mark(1)
			meters.hit.Mark(1)
			return common.CopyBytes(output), true
		}
	}
	c.miss.Mark(1)
	meters.miss.Mark(1)
	return nil, false
}

// store saves the output of a precompile run under the given key. Both the key
// and the value are copied, the cache never aliases caller memory. That matters
// for the key in particular, it aliases the caller's memory which the EVM goes
// on to overwrite.
func (c *PrecompileCache) store(scope precompileCacheScope, key []byte, output []byte) {
	if c.validation != nil {
		c.validationStoreResult(scope, key, output, nil)
		return
	}
	c.data.mu.RLock()
	results := c.data.caches[scope]
	c.data.mu.RUnlock()

	if results == nil {
		c.data.mu.Lock()
		if results = c.data.caches[scope]; results == nil {
			results = lru.NewSizeConstrainedCache[string, []byte](maxCacheablePrecompileBytes)
			c.data.caches[scope] = results
		}
		c.data.mu.Unlock()
	}
	results.Add(string(key), common.CopyBytes(output))
}

// storeResult retains a validation result. Deterministic failures are scoped
// by the same fork, address, and exact normalized input as successful outputs.
func (c *PrecompileCache) storeResult(scope precompileCacheScope, key []byte, output []byte, err error) bool {
	if c.validation != nil {
		return c.validationStoreResult(scope, key, output, err)
	}
	if err == nil {
		c.store(scope, key, output)
	}
	return false
}

func (c *PrecompileCache) validationLoadResult(scope precompileCacheScope, key []byte) ([]byte, error, bool) {
	memo := c.validation
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if scoped := memo.entries[scope]; scoped != nil {
		if result, ok := scoped[string(key)]; ok {
			memo.stats.Hits++
			if c.validationMutable.Load() {
				memo.stats.AfterMutableHits++
			} else {
				memo.stats.BeforeMutableHits++
			}
			return common.CopyBytes(result.output), result.err, true
		}
	}
	memo.stats.Misses++
	if c.validationMutable.Load() {
		memo.stats.AfterMutableMisses++
	} else {
		memo.stats.BeforeMutableMisses++
	}
	return nil, nil, false
}

func (c *PrecompileCache) validationStoreResult(scope precompileCacheScope, key []byte, output []byte, err error) bool {
	memo := c.validation
	memo.mu.Lock()
	defer memo.mu.Unlock()
	keyString := string(key)
	if scoped := memo.entries[scope]; scoped != nil {
		if _, exists := scoped[keyString]; exists {
			return true
		}
	}
	entryBytes := validationMemoEntryOverhead + common.AddressLength
	if ^uint64(0)-entryBytes < uint64(len(key)) {
		c.memoSaturatedLocked(memo)
		return false
	}
	entryBytes += uint64(len(key))
	if ^uint64(0)-entryBytes < uint64(len(output)) {
		c.memoSaturatedLocked(memo)
		return false
	}
	entryBytes += uint64(len(output))
	if err != nil {
		errBytes := uint64(len(err.Error()))
		if ^uint64(0)-entryBytes < errBytes {
			c.memoSaturatedLocked(memo)
			return false
		}
		entryBytes += errBytes
	}
	if memo.limits.MaxEntries <= 0 || memo.stats.Entries >= uint64(memo.limits.MaxEntries) || memo.stats.AccountedBytes > memo.limits.MaxBytes || entryBytes > memo.limits.MaxBytes-memo.stats.AccountedBytes {
		c.memoSaturatedLocked(memo)
		return false
	}
	scoped := memo.entries[scope]
	if scoped == nil {
		scoped = make(map[string]validationPrecompileResult)
		memo.entries[scope] = scoped
	}
	scoped[keyString] = validationPrecompileResult{output: common.CopyBytes(output), err: err}
	memo.stats.Stores++
	memo.stats.Entries++
	memo.stats.AccountedBytes += entryBytes
	return true
}

// ReusableValidationGas is per execution/frame, unlike the cumulative hit metrics.
// Each retained invocation earns credit, including repeated uses of one entry.
func (c *PrecompileCache) ReusableValidationGas() uint64 {
	if c == nil || c.validation == nil {
		return 0
	}
	return c.validationReusableGas.Load()
}

func (c *PrecompileCache) recordReusableValidationGas(gas uint64) {
	if c.validation == nil || c.validationMutable.Load() {
		return
	}
	for {
		previous := c.validationReusableGas.Load()
		next := previous + gas
		if next < previous {
			next = ^uint64(0)
		}
		if c.validationReusableGas.CompareAndSwap(previous, next) {
			return
		}
	}
}

// Validation memo policy is deliberately narrower than the block-processing
// cache. Reject oversized/cheap calls before normalization or key allocation.
func (c *PrecompileCache) invocationKey(p PrecompiledContract, input []byte, gas uint64) ([]byte, bool) {
	if c.validation != nil {
		if len(input) > maxValidationMemoInput || gas < minValidationMemoGas {
			return nil, false
		}
		switch p.(type) {
		case *ecrecover, *bigModExp, *bn256ScalarMulIstanbul, *bn256ScalarMulByzantium,
			*bn256PairingIstanbul, *bn256PairingByzantium, *kzgPointEvaluation, *p256Verify,
			*bls12381G1Add, *bls12381G1MultiExp, *bls12381G2Add, *bls12381G2MultiExp,
			*bls12381Pairing, *bls12381MapG1, *bls12381MapG2:
		default:
			return nil, false
		}
	}
	return precompileCacheKey(p, input)
}

func (c *PrecompileCache) memoSaturatedLocked(memo *validationPrecompileMemo) {
	memo.complete = false
	memo.stats.Saturated++
	if c.validationMutable.Load() {
		memo.stats.AfterMutableSaturated++
	} else {
		memo.stats.BeforeMutableSaturated++
		memo.completeBeforeMutable = false
	}
}

func (c *PrecompileCache) recordActualRun() {
	if c == nil || c.validation == nil {
		return
	}
	c.validation.mu.Lock()
	c.validation.stats.ActualRuns++
	if c.validationMutable.Load() {
		c.validation.stats.AfterMutableActualRuns++
	} else {
		c.validation.stats.BeforeMutableActualRuns++
	}
	c.validation.mu.Unlock()
}

func (c *PrecompileCache) recordUncacheable() {
	if c == nil || c.validation == nil {
		return
	}
	c.validation.mu.Lock()
	c.validation.stats.Uncacheable++
	c.validation.complete = false
	if c.validationMutable.Load() {
		c.validation.stats.AfterMutableUncacheable++
	} else {
		c.validation.stats.BeforeMutableUncacheable++
		c.validation.completeBeforeMutable = false
	}
	c.validation.mu.Unlock()
}

func (c *PrecompileCache) recordCachedGas(gas uint64) {
	if c == nil || c.validation == nil {
		return
	}
	c.validation.mu.Lock()
	if ^uint64(0)-c.validation.stats.CachedGas < gas {
		c.validation.stats.CachedGas = ^uint64(0)
	} else {
		c.validation.stats.CachedGas += gas
	}
	c.validation.mu.Unlock()
}

// metersFor returns the hit and miss meters of the given precompile address,
// registering them on first use.
func (c *PrecompileCache) metersFor(addr common.Address) *precompileCacheMeters {
	c.mu.RLock()
	meters, ok := c.meters[addr]
	c.mu.RUnlock()
	if ok {
		return meters
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if meters, ok = c.meters[addr]; ok {
		return meters
	}
	prefix := fmt.Sprintf("%s/%#x", c.prefix, addr.Big())
	meters = &precompileCacheMeters{
		hit:  metrics.GetOrRegisterMeter(prefix+"/hit", nil),
		miss: metrics.GetOrRegisterMeter(prefix+"/miss", nil),
	}
	c.meters[addr] = meters
	return meters
}

// CacheablePrecompile is implemented by precompiles that opt in to result
// caching. Anything that does not implement it is never cached, so a new
// precompile is not enrolled until someone decides it should be.
type CacheablePrecompile interface {
	Cacheable() bool
}

// NormalizingPrecompile is implemented by precompiles that can narrow an input
// down to the bytes that determine the result.
type NormalizingPrecompile interface {
	// NormalizeInput returns the bytes identifying the result, and whether the
	// invocation is cacheable at all. Two inputs that normalize alike share an
	// entry, so they must run to the same output. Returning false skips the
	// cache, which is how a precompile rejects lengths it will fail on.
	NormalizeInput(input []byte) ([]byte, bool)
}

// precompileCacheKey returns the key identifying an invocation and whether it
// is eligible for result caching.
func precompileCacheKey(p PrecompiledContract, input []byte) ([]byte, bool) {
	c, ok := p.(CacheablePrecompile)
	if !ok || !c.Cacheable() {
		return nil, false
	}
	key := input
	if n, ok := p.(NormalizingPrecompile); ok {
		if key, ok = n.NormalizeInput(input); !ok {
			return nil, false
		}
	}
	if len(key) > maxCacheablePrecompileInput {
		return nil, false
	}
	return key, true
}

// normalizeZeroPadded narrows an input for a precompile that reads a fixed
// length prefix and zero extends anything shorter. Bytes past the prefix are
// never read, and trailing zeros inside it read the same as not being there,
// so both can be dropped from the key.
func normalizeZeroPadded(input []byte, prefix int) []byte {
	if len(input) > prefix {
		input = input[:prefix]
	}
	end := len(input)
	for end > 0 && input[end-1] == 0 {
		end--
	}
	return input[:end]
}
