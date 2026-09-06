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

// Package framepool implements the transaction pool for EIP-8141 frame transactions.
// It validates public-mempool prefixes using EIP-8141 structural and trace rules.
package framepool

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	commonmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/types/bal"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

const (
	// PublicMaxPendingPerSender is the EIP-8141 public-mempool sender limit.
	PublicMaxPendingPerSender = 1

	// PublicMaxPendingPerNonCanonicalPaymaster is the EIP-8141 public-mempool
	// limit for transactions sharing a non-canonical paymaster.
	PublicMaxPendingPerNonCanonicalPaymaster = 1

	// defaultMaxFramePoolSize limits total pooled frame transactions. The experimental
	// capacity matches the legacy pool's default executable-slot count.
	defaultMaxFramePoolSize = 5120

	// PublicMaxVerifyGas is the fixed EIP-8141 public-mempool validation budget.
	PublicMaxVerifyGas uint64 = 100_000
	maxVerifyGas              = PublicMaxVerifyGas

	// Transaction-local validation memo defaults hold several normal proof
	// precompile invocations while bounding a full 5,120-transaction pool to an
	// 80 MiB configured entry budget, plus fixed per-memo and map overhead.
	defaultValidationMemoMaxEntries = 8
	defaultValidationMemoMaxBytes   = 16 * 1024

	// frameTxPriceBump is the same-nonce replacement bump percentage.
	frameTxPriceBump = 10

	// txMaxSize is the maximum frame transaction size.
	txMaxSize uint64 = 512 * 1024

	// defaultResetValidationWorkerLimit bounds the StateDB copies and EVMs used
	// by default to prepare reset validation. Pool accounting is committed separately.
	defaultResetValidationWorkerLimit = 8

	// maxSignatureValidationWorkers bounds admission-time cryptographic work
	// performed concurrently outside the serialized state-validation path.
	maxSignatureValidationWorkers = 4
)

// Config configures frame transaction validation and resource policy.
type Config struct {
	MaxVerifyGas                       uint64
	MaxStateDependentVerifyGas         uint64
	CacheValidationPrecompiles         bool
	RejectIncompleteValidationMemo     bool
	ValidationMemoMaxEntries           int
	ValidationMemoMaxBytes             uint64
	MaxPendingPerSender                int
	MaxPendingPerNonCanonicalPaymaster int
	MaxPoolSize                        int
	ResetValidationWorkers             int
	PayerSolvencyPreflight             bool
	PayerCodeIdentityPreflight         bool
	SelectiveRevalidation              bool
	AllowUnsafeBenchmarkPolicy         bool `toml:"-"`
}

// DefaultConfig follows the EIP-8141 public-mempool constants. Cheap payer
// checks run before protocol signatures and validation-prefix execution.
var DefaultConfig = Config{
	MaxVerifyGas:                       maxVerifyGas,
	MaxStateDependentVerifyGas:         maxVerifyGas,
	CacheValidationPrecompiles:         false,
	RejectIncompleteValidationMemo:     false,
	ValidationMemoMaxEntries:           defaultValidationMemoMaxEntries,
	ValidationMemoMaxBytes:             defaultValidationMemoMaxBytes,
	MaxPendingPerSender:                PublicMaxPendingPerSender,
	MaxPendingPerNonCanonicalPaymaster: PublicMaxPendingPerNonCanonicalPaymaster,
	MaxPoolSize:                        defaultMaxFramePoolSize,
	ResetValidationWorkers:             defaultResetValidationWorkers(),
	PayerSolvencyPreflight:             true,
	PayerCodeIdentityPreflight:         true,
	SelectiveRevalidation:              true,
}

// Sanitized returns a configuration with non-positive numeric values replaced
// by the package defaults. Zero values make partial programmatic configurations
// retain the public-mempool policy.
func (config Config) Sanitized() Config {
	if config.MaxVerifyGas == 0 {
		config.MaxVerifyGas = maxVerifyGas
	}
	if config.MaxStateDependentVerifyGas == 0 {
		config.MaxStateDependentVerifyGas = config.MaxVerifyGas
	}
	if config.MaxStateDependentVerifyGas > config.MaxVerifyGas {
		config.MaxStateDependentVerifyGas = config.MaxVerifyGas
	}
	if config.RejectIncompleteValidationMemo {
		config.CacheValidationPrecompiles = true
	}
	if config.ValidationMemoMaxEntries <= 0 {
		config.ValidationMemoMaxEntries = defaultValidationMemoMaxEntries
	}
	if config.ValidationMemoMaxBytes == 0 {
		config.ValidationMemoMaxBytes = defaultValidationMemoMaxBytes
	}
	if config.MaxPendingPerSender <= 0 {
		config.MaxPendingPerSender = PublicMaxPendingPerSender
	}
	if config.MaxPendingPerNonCanonicalPaymaster <= 0 {
		config.MaxPendingPerNonCanonicalPaymaster = PublicMaxPendingPerNonCanonicalPaymaster
	}
	if config.MaxPoolSize <= 0 {
		config.MaxPoolSize = defaultMaxFramePoolSize
	}
	if config.ResetValidationWorkers <= 0 {
		config.ResetValidationWorkers = defaultResetValidationWorkers()
	}
	return config
}

var (
	// canonicalPaymasterCodeHash is keccak256(CanonicalPaymaster runtime bytecode),
	// compiled by contracts with the pinned EIP-8141 Solidity compiler.
	canonicalPaymasterCodeHash = common.HexToHash("0x6c30f5865065de960a498c71c875f58fc0817d3b5c93819def154c652ba80435")
	// The original PoC CanonicalPaymaster fixes pending withdrawal amount at
	// storage slot 1.
	canonicalPaymasterPendingWithdrawalSlot = common.Hash{31: 1}
)

// BlockChain defines the blockchain interface needed by the frame pool.
type BlockChain interface {
	Config() *params.ChainConfig
	CurrentBlock() *types.Header
	GetBlock(hash common.Hash, number uint64) *types.Block
	StateAt(header *types.Header) (*state.StateDB, error)
}

type framePoolLimits struct {
	maxPendingPerSender                int
	maxPendingPerNonCanonicalPaymaster int
	maxPoolSize                        int
}

type nonceKeyOwnerIndex map[common.Address]map[common.Hash]common.Hash

// FramePool is a transaction pool for EIP-8141 frame transactions.
// It validates VERIFY frames by simulating the EIP-8141 public-mempool
// validation prefix before accepting transactions into the pool.
type FramePool struct {
	chain       BlockChain
	chainconfig *params.ChainConfig
	signer      types.Signer

	gasTip                         uint256.Int
	currentHead                    *types.Header
	currentState                   *state.StateDB
	slotProvider                   func(*types.Header) vm.SlotProvider
	verifyGasCap                   uint64
	stateDependentVerifyGasCap     uint64
	cacheValidationPrecompiles     bool
	rejectIncompleteValidationMemo bool
	validationMemoLimits           vm.ValidationPrecompileMemoLimits
	limits                         framePoolLimits
	payerSolvencyPreflight         bool
	payerCodeIdentityPreflight     bool
	selectiveRevalidation          bool
	resetValidationWorkers         int
	canonicalPaymasters            map[common.Hash]common.Hash

	reserver txpool.Reserver

	validationMu             sync.Mutex
	admissionValidationState *state.StateDB // reusable current-head view, guarded by validationMu
	signatureValidationSlots chan struct{}
	mu                       sync.RWMutex
	pending                  map[common.Address][]*types.Transaction   // sender → txs
	all                      map[common.Hash]*types.Transaction        // hash → tx
	nonceKeyOwner            nonceKeyOwnerIndex                        // sender and nonce key → transaction hash
	meta                     map[common.Hash]frameTxMeta               // hash → validation/accounting metadata
	dependencyIndex          *validationDependencyIndex                // mutable validation dependency → transaction hashes
	stalePayerCode           map[common.Hash]payerCodeIdentity         // hash → admission-time payer code identity
	staleValidationPrograms  map[common.Hash]validationProgramIdentity // hash → admission-time validation program identity
	blobSidecars             map[common.Hash]cachedBlobSidecar         // recently mined tx hash → full sidecar
	blobCells                map[common.Hash][]kzg4844.Cell            // validated cells for pooled and recently mined txs

	paymasterReserved map[common.Address]*big.Int // payer → reserved pending max cost
	paymasterPending  map[common.Address]int      // non-canonical payer → pending count

	discoverFeed event.Feed // Transactions newly added from the network or local RPC
	insertFeed   event.Feed // All inserted transactions, including reorg reinjections
}

type frameTxMeta struct {
	payer                 common.Address
	usesPaymaster         bool
	canonicalPaymaster    bool
	nonCanonicalPaymaster bool
	signatureValidated    bool
	signatureGas          uint64
	maxCost               *big.Int
	payerAvailableBalance *big.Int
	payerCodeHash         common.Hash
	validationDeps        *validationDependencySnapshot
	validationWork        validationWorkSummary
	validationMemo        *vm.PrecompileCache
}

type validationWorkSummary struct {
	StateDependentGasLimit uint64
	FirstMutableFrames     int
	ConservativeFrames     int
	DeployValidationGas    uint64
	FrameProfiles          map[int]vm.ValidationWorkProfile
}

type validationArtifacts struct {
	precompileMemo *vm.PrecompileCache
}

func (summary *validationWorkSummary) addFrame(index int, profile vm.ValidationWorkProfile) error {
	if summary.FrameProfiles == nil {
		summary.FrameProfiles = make(map[int]vm.ValidationWorkProfile)
	}
	summary.FrameProfiles[index] = profile
	return summary.recompute()
}

func (summary *validationWorkSummary) recompute() error {
	summary.StateDependentGasLimit = 0
	summary.FirstMutableFrames = 0
	summary.ConservativeFrames = 0
	summary.DeployValidationGas = 0
	firstMutableIndex := -1
	for frameIndex, profile := range summary.FrameProfiles {
		if profile.HasMutableRead {
			summary.FirstMutableFrames++
			if firstMutableIndex < 0 || frameIndex < firstMutableIndex {
				firstMutableIndex = frameIndex
			}
		}
		if profile.GasAccountingConservative {
			summary.ConservativeFrames++
		}
		if profile.FirstMutableReadKind == vm.ValidationMutableReadDeployment {
			summary.DeployValidationGas = profile.StateDependentGasLimit
		}
	}
	if firstMutableIndex < 0 {
		return nil
	}
	for frameIndex, profile := range summary.FrameProfiles {
		if frameIndex < firstMutableIndex {
			continue
		}
		// Frame results, gas-used fields, and the transaction access journal can
		// carry mutable influence into every later validation frame. The first
		// mutable frame contributes its suffix; every later frame its full budget.
		contribution := profile.FrameGasLimit
		if frameIndex == firstMutableIndex {
			contribution = profile.StateDependentGasLimit
		}
		total, overflow := commonmath.SafeAdd(summary.StateDependentGasLimit, contribution)
		if overflow {
			summary.StateDependentGasLimit = ^uint64(0)
			return fmt.Errorf("validation state-dependent gas overflows uint64")
		}
		summary.StateDependentGasLimit = total
	}
	return nil
}

func (summary validationWorkSummary) hasEarlierMutableFrame(index int) bool {
	for frameIndex, profile := range summary.FrameProfiles {
		if frameIndex < index && profile.HasMutableRead {
			return true
		}
	}
	return false
}

type storageDependency struct {
	address common.Address
	slot    common.Hash
}

type validationDependencySnapshot struct {
	senderCodeHash common.Hash
	deployedSender bool
	rules          params.Rules
	legacyNonce    *uint64
	blobBaseFee    *big.Int
	senderBalance  *common.Hash
	storageValues  map[storageDependency]common.Hash
	codeHashes     map[common.Address]common.Hash
}

type validationDependencyKind uint8

const (
	validationCodeDependency validationDependencyKind = iota
	validationStorageDependency
	validationNonceDependency
	validationBalanceDependency
)

type validationDependencyKey struct {
	kind    validationDependencyKind
	address common.Address
	slot    common.Hash
}

type validationDependencyEntry struct {
	value      common.Hash
	conflicted bool
	dependents map[common.Hash]struct{}
}

// validationDependencyIndex is an acceleration structure over the authoritative
// per-transaction snapshots in frameTxMeta. Missing or conflicted entries always
// fall back to transaction-local comparison or full validation.
type validationDependencyIndex struct {
	byKey           map[validationDependencyKey]*validationDependencyEntry
	byTx            map[common.Hash][]validationDependencyKey
	accountingByKey map[validationDependencyKey]map[common.Hash]struct{}
	accountingByTx  map[common.Hash][]validationDependencyKey
}

type validationDependencyChanges struct {
	affected                map[common.Hash]struct{}
	indexed                 map[common.Hash]struct{}
	accountingAffected      map[common.Hash]struct{}
	accountingIndexed       map[common.Hash]struct{}
	selectiveAccountingScan bool
}

type validationDependencyTouches struct {
	keys map[validationDependencyKey]struct{}
}

type payerCodeIdentity struct {
	payer    common.Address
	codeHash common.Hash
}

type validationProgramIdentity struct {
	rules      params.Rules
	codeHashes map[common.Address]common.Hash
}

type cachedBlobSidecar struct {
	sidecar     *types.BlobTxSidecar
	blockNumber uint64
}

type resetValidationClass uint8

const (
	resetReuse resetValidationClass = iota
	resetAccountingOnly
	resetFullValidation
)

type resetValidation struct {
	tx            *types.Transaction
	class         resetValidationClass
	meta          frameTxMeta
	err           error
	verifyElapsed time.Duration
	memoBefore    vm.PrecompileCacheStats
	memoAfter     vm.PrecompileCacheStats
}

// New creates a new frame transaction pool.
func New(chain BlockChain) *FramePool {
	return NewWithConfig(DefaultConfig, chain)
}

// NewWithConfig creates a frame transaction pool with explicit policy settings.
func NewWithConfig(config Config, chain BlockChain) *FramePool {
	config = config.Sanitized()
	return &FramePool{
		chain:                          chain,
		chainconfig:                    chain.Config(),
		signer:                         types.LatestSigner(chain.Config()),
		verifyGasCap:                   config.MaxVerifyGas,
		stateDependentVerifyGasCap:     config.MaxStateDependentVerifyGas,
		cacheValidationPrecompiles:     config.CacheValidationPrecompiles,
		rejectIncompleteValidationMemo: config.RejectIncompleteValidationMemo,
		validationMemoLimits: vm.ValidationPrecompileMemoLimits{
			MaxEntries: config.ValidationMemoMaxEntries,
			MaxBytes:   config.ValidationMemoMaxBytes,
		},
		limits: framePoolLimits{
			maxPendingPerSender:                config.MaxPendingPerSender,
			maxPendingPerNonCanonicalPaymaster: config.MaxPendingPerNonCanonicalPaymaster,
			maxPoolSize:                        config.MaxPoolSize,
		},
		payerSolvencyPreflight:     config.PayerSolvencyPreflight,
		payerCodeIdentityPreflight: config.PayerCodeIdentityPreflight,
		selectiveRevalidation:      config.SelectiveRevalidation,
		resetValidationWorkers:     config.ResetValidationWorkers,
		signatureValidationSlots:   make(chan struct{}, defaultSignatureValidationWorkers()),
		canonicalPaymasters:        make(map[common.Hash]common.Hash),
		pending:                    make(map[common.Address][]*types.Transaction),
		all:                        make(map[common.Hash]*types.Transaction),
		nonceKeyOwner:              make(nonceKeyOwnerIndex),
		meta:                       make(map[common.Hash]frameTxMeta),
		dependencyIndex:            newValidationDependencyIndex(),
		stalePayerCode:             make(map[common.Hash]payerCodeIdentity),
		staleValidationPrograms:    make(map[common.Hash]validationProgramIdentity),
		blobSidecars:               make(map[common.Hash]cachedBlobSidecar),
		blobCells:                  make(map[common.Hash][]kzg4844.Cell),
		slotProvider: func(head *types.Header) vm.SlotProvider {
			if head.SlotNumber != nil {
				return vm.SlotNumberProvider(*head.SlotNumber)
			}
			return vm.TimestampSlotProvider{Timestamp: head.Time}
		},

		paymasterReserved: make(map[common.Address]*big.Int),
		paymasterPending:  make(map[common.Address]int),
	}
}

// Filter returns true for frame transactions.
func (p *FramePool) Filter(tx *types.Transaction) bool {
	return p.FilterType(tx.Type())
}

// FilterType returns true for the EIP-8141 frame transaction type.
func (p *FramePool) FilterType(kind byte) bool { return kind == types.FrameTxType }

// Init initializes the frame pool.
func (p *FramePool) Init(gasTip uint64, head *types.Header, reserver txpool.Reserver) error {
	p.reserver = reserver
	p.gasTip = *uint256.NewInt(gasTip)

	statedb, err := p.chain.StateAt(head)
	if err != nil {
		emptyHead := types.CopyHeader(head)
		emptyHead.Root = types.EmptyRootHash
		statedb, err = p.chain.StateAt(emptyHead)
	}
	if err != nil {
		return err
	}
	p.currentHead = head
	p.currentState = statedb
	p.admissionValidationState = nil
	return nil
}

// Close is a no-op (no background goroutines).
func (p *FramePool) Close() error { return nil }

// Reset updates the pool state when the chain head changes.
func (p *FramePool) Reset(oldHead, newHead *types.Header) {
	lockWaitStart := time.Now()
	p.validationMu.Lock()
	lockWait := time.Since(lockWaitStart)
	holdStart := time.Now()
	resetLastLockWaitGauge.Update(lockWait.Nanoseconds())
	resetLastVerifySumGauge.Update(0)
	resetLastVerifyMeanGauge.Update(0)
	resetLastVerifyMaxGauge.Update(0)
	resetLastVerifyCountGauge.Update(0)
	resetLastVerifyWorkersGauge.Update(0)
	resetLastMemoHitsGauge.Update(0)
	resetLastMemoMissesGauge.Update(0)
	resetLastMemoActualRunsGauge.Update(0)
	resetLastMemoCachedGasGauge.Update(0)
	resetLastStateDependentGasGauge.Update(0)

	resetRunMeter.Mark(1)
	defer func() {
		hold := time.Since(holdStart)
		resetTimeTimer.Update(hold)
		resetLastTimeGauge.Update(hold.Nanoseconds())
		resetLastHoldGauge.Update(hold.Nanoseconds())
		p.validationMu.Unlock()
	}()

	reinject, included, dependencyTouches := p.reorgTransactions(oldHead, newHead)
	statedb, err := p.chain.StateAt(newHead)
	if err != nil {
		log.Error("Failed to reset frame pool state", "err", err)
		return
	}

	p.mu.Lock()
	p.cacheIncludedBlobSidecars(included, newHead.Number.Uint64())
	for i, tx := range reinject {
		if tx.BlobGas() == 0 || tx.BlobTxSidecar() != nil {
			continue
		}
		if cached, ok := p.blobSidecars[tx.Hash()]; ok {
			reinject[i] = tx.WithBlobTxSidecar(cached.sidecar)
		}
	}
	var txs []*types.Transaction
	seen := make(map[common.Hash]struct{})
	existingSenders := make(map[common.Address]struct{}, len(p.pending))
	for sender, senderTxs := range p.pending {
		if len(senderTxs) > 0 {
			existingSenders[sender] = struct{}{}
		}
		for _, tx := range senderTxs {
			txs = append(txs, tx)
			seen[tx.Hash()] = struct{}{}
		}
	}
	for _, tx := range reinject {
		if _, ok := seen[tx.Hash()]; !ok {
			txs = append(txs, tx)
		}
	}
	oldMeta := p.meta
	oldDependencyIndex := p.dependencyIndex
	stalePayerCode := make(map[common.Hash]payerCodeIdentity, len(p.stalePayerCode))
	for hash, identity := range p.stalePayerCode {
		stalePayerCode[hash] = identity
	}
	staleValidationPrograms := make(map[common.Hash]validationProgramIdentity, len(p.staleValidationPrograms))
	for hash, identity := range p.staleValidationPrograms {
		staleValidationPrograms[hash] = identity
	}
	blobCells := make(map[common.Hash][]kzg4844.Cell, len(p.blobCells))
	for hash, cells := range p.blobCells {
		blobCells[hash] = cells
	}
	reserver := &resetReserver{base: p.reserver, existing: existingSenders, acquired: make(map[common.Address]struct{})}
	candidate := &FramePool{
		chain:                          p.chain,
		chainconfig:                    p.chainconfig,
		signer:                         p.signer,
		gasTip:                         p.gasTip,
		currentHead:                    newHead,
		currentState:                   statedb,
		slotProvider:                   p.slotProvider,
		verifyGasCap:                   p.verifyGasCap,
		stateDependentVerifyGasCap:     p.stateDependentVerifyGasCap,
		cacheValidationPrecompiles:     p.cacheValidationPrecompiles,
		rejectIncompleteValidationMemo: p.rejectIncompleteValidationMemo,
		validationMemoLimits:           p.validationMemoLimits,
		limits:                         p.limits,
		payerSolvencyPreflight:         p.payerSolvencyPreflight,
		payerCodeIdentityPreflight:     p.payerCodeIdentityPreflight,
		selectiveRevalidation:          p.selectiveRevalidation,
		resetValidationWorkers:         p.resetValidationWorkers,
		canonicalPaymasters:            p.canonicalPaymasters,
		reserver:                       reserver,
		pending:                        make(map[common.Address][]*types.Transaction),
		all:                            make(map[common.Hash]*types.Transaction),
		nonceKeyOwner:                  make(nonceKeyOwnerIndex),
		meta:                           make(map[common.Hash]frameTxMeta),
		dependencyIndex:                newValidationDependencyIndex(),
		stalePayerCode:                 stalePayerCode,
		staleValidationPrograms:        staleValidationPrograms,
		blobCells:                      blobCells,
		paymasterReserved:              make(map[common.Address]*big.Int),
		paymasterPending:               make(map[common.Address]int),
	}
	p.mu.Unlock()

	dependencyChanges := oldDependencyIndex.changes(statedb, dependencyTouches)
	candidate.revalidate(txs, oldMeta, dependencyChanges)

	p.mu.Lock()
	for sender := range existingSenders {
		if len(candidate.pending[sender]) == 0 && p.reserver != nil {
			p.reserver.Release(sender)
		}
	}
	p.currentHead = newHead
	p.currentState = statedb
	p.admissionValidationState = nil
	for hash := range candidate.blobCells {
		if candidate.all[hash] == nil {
			if _, cached := p.blobSidecars[hash]; !cached {
				delete(candidate.blobCells, hash)
			}
		}
	}
	p.pending = candidate.pending
	p.all = candidate.all
	p.nonceKeyOwner = candidate.nonceKeyOwner
	p.meta = candidate.meta
	p.dependencyIndex = candidate.dependencyIndex
	p.stalePayerCode = candidate.stalePayerCode
	p.staleValidationPrograms = candidate.staleValidationPrograms
	p.blobCells = candidate.blobCells
	p.paymasterReserved = candidate.paymasterReserved
	p.paymasterPending = candidate.paymasterPending

	var reorgs []*types.Transaction
	for _, tx := range reinject {
		if retained := p.all[tx.Hash()]; retained != nil {
			reorgs = append(reorgs, retained)
		}
	}
	p.mu.Unlock()
	if len(reorgs) > 0 {
		p.insertFeed.Send(core.NewTxsEvent{Txs: reorgs})
	}
}

type resetReserver struct {
	base     txpool.Reserver
	existing map[common.Address]struct{}
	acquired map[common.Address]struct{}
}

func (r *resetReserver) Hold(addr common.Address) error {
	if r.base == nil {
		return nil
	}
	if _, ok := r.existing[addr]; ok {
		return nil
	}
	if err := r.base.Hold(addr); err != nil {
		return err
	}
	r.acquired[addr] = struct{}{}
	return nil
}

func (r *resetReserver) Release(addr common.Address) error {
	if r.base == nil {
		return nil
	}
	if _, ok := r.existing[addr]; ok {
		return nil
	}
	delete(r.acquired, addr)
	return r.base.Release(addr)
}

func (r *resetReserver) Has(addr common.Address) bool {
	return r.base != nil && r.base.Has(addr)
}

func (p *FramePool) revalidate(txs []*types.Transaction, oldMeta map[common.Hash]frameTxMeta, dependencyChanges *validationDependencyChanges) {
	resetCandidateMeter.Mark(int64(len(txs)))
	sortResetTransactions(txs, oldMeta)
	// revalidated counts full validation-prefix simulations. Transactions rejected
	// by the payer solvency preflight are candidates and evictions, but not revalidations.
	revalidated := int64(0)
	reused := int64(0)
	dependencyChanged := int64(0)
	retained := int64(0)
	defer func() {
		resetRevalidatedMeter.Mark(revalidated)
		resetReusedMeter.Mark(reused)
		resetDependencyChangedMeter.Mark(dependencyChanged)
		resetRetainedMeter.Mark(retained)
		resetEvictedMeter.Mark(int64(len(txs)) - retained)
	}()
	validations := make([]resetValidation, 0, len(txs))
	for _, tx := range txs {
		frameTx := tx.GetFrameTx()
		if frameTx == nil {
			continue
		}
		if err := p.ValidateTxBasics(tx); err != nil {
			continue
		}
		simulationTime := p.currentHead.Time + params.SecondsPerSlot
		if _, err := p.validationPrefixPlan(frameTx, p.currentState, simulationTime); err != nil {
			continue
		}
		if tx.BlobGas() > 0 {
			if _, ok := p.blobCells[tx.Hash()]; !ok {
				cells, err := validateFrameBlobProofs(tx)
				if err != nil {
					continue
				}
				p.blobCells[tx.Hash()] = cells
			}
		}
		if err := validateFrameNonce(frameTx, p.currentState); err != nil {
			continue
		}
		if err := p.validateRecentRootReferences(frameTx, p.currentState, p.currentHead); err != nil {
			continue
		}
		meta, metaOK := oldMeta[tx.Hash()]
		if metaOK && p.rejectChangedValidationProgram(tx.Hash(), frameTx, meta) {
			continue
		}
		if p.selectiveRevalidation {
			if metaOK && p.validationDependenciesUnchangedIndexed(tx.Hash(), frameTx, meta, dependencyChanges) {
				class := resetReuse
				checkAccounting := true
				if dependencyChanges != nil && dependencyChanges.selectiveAccountingScan && meta.payerAvailableBalance != nil {
					_, indexed := dependencyChanges.accountingIndexed[tx.Hash()]
					_, affected := dependencyChanges.accountingAffected[tx.Hash()]
					checkAccounting = !indexed || affected
				}
				if checkAccounting {
					available := p.payerAvailableBalance(meta)
					// An increase cannot invalidate prior solvency. A decrease (or
					// legacy metadata without a balance) needs accounting only.
					if meta.payerAvailableBalance == nil || available.Cmp(meta.payerAvailableBalance) < 0 {
						class = resetAccountingOnly
					}
					meta.payerAvailableBalance = available
				}
				validations = append(validations, resetValidation{tx: tx, class: class, meta: meta})
				continue
			}
			dependencyChanged++
		}
		if err := p.preflightPayerSolvency(tx, nil); err != nil {
			continue
		}
		revalidated++
		validations = append(validations, resetValidation{tx: tx, class: resetFullValidation, meta: meta})
	}
	p.prepareResetValidations(validations)

	// Commit in the sorted candidate order. Payer reservations, sender limits,
	// and reserver ownership are deliberately never mutated by workers.
	for _, validation := range validations {
		tx := validation.tx
		if validation.err != nil || len(p.all) >= p.limits.maxPoolSize {
			continue
		}
		frameTx := tx.GetFrameTx()
		replacement, _, err := p.checkNonceKeyAdmission(frameTx)
		if err != nil || replacement != nil {
			continue
		}
		sender := frameTx.Sender
		if validation.class == resetAccountingOnly {
			if err := p.validatePayerSolvency(tx, validation.meta, nil); err != nil {
				continue
			}
		}
		if validation.class == resetFullValidation {
			if err := p.validatePaymasterAccounting(tx, validation.meta, nil); err != nil {
				continue
			}
		}
		if len(p.pending[sender]) == 0 && p.reserver != nil {
			if err := p.reserver.Hold(sender); err != nil {
				continue
			}
		}
		p.pending[sender] = append(p.pending[sender], tx)
		p.all[tx.Hash()] = tx
		p.reserveNonceKeys(tx)
		p.reserveTxAccounting(tx, validation.meta)
		if validation.class != resetFullValidation {
			reused++
		}
		retained++
	}
}

func defaultResetValidationWorkers() int {
	return min(max(runtime.GOMAXPROCS(0), 1), defaultResetValidationWorkerLimit)
}

func defaultSignatureValidationWorkers() int {
	return min(max(runtime.GOMAXPROCS(0), 1), maxSignatureValidationWorkers)
}

// prepareResetValidations reruns the full current-format validation prefix for
// state-affected candidates in parallel. Precompile memo hits may skip CPU
// recomputation, but pure EVM still starts at PC 0. Each worker owns a StateDB
// snapshot; results are committed later in deterministic reset priority order.
func (p *FramePool) prepareResetValidations(validations []resetValidation) {
	var full []int
	for i := range validations {
		if validations[i].class == resetFullValidation {
			full = append(full, i)
		}
	}
	if len(full) == 0 {
		return
	}
	workers := min(max(p.resetValidationWorkers, 1), len(full))
	views := make([]*FramePool, workers)
	for i := range views {
		views[i] = p.validationViewLocked()
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for _, view := range views {
		wg.Add(1)
		go func(view *FramePool) {
			defer wg.Done()
			for index := range jobs {
				validation := &validations[index]
				cached := validation.meta
				artifacts := validationArtifacts{precompileMemo: cached.validationMemo}
				if artifacts.precompileMemo == nil {
					artifacts = view.newValidationArtifacts()
				}
				validation.memoBefore = artifacts.precompileMemo.Stats()
				start := time.Now()
				if cached.signatureValidated {
					validation.meta, validation.err = view.simulateVerifyFramesWithSignatureGasAndArtifacts(validation.tx, cached.signatureGas, artifacts)
					if validation.err == nil {
						validation.meta.signatureValidated = true
						validation.meta.signatureGas = cached.signatureGas
					}
				} else {
					validation.meta, validation.err = view.simulateVerifyFrames(validation.tx)
				}
				validation.verifyElapsed = time.Since(start)
				if validation.meta.validationMemo != nil {
					validation.memoAfter = validation.meta.validationMemo.Stats()
				} else {
					validation.memoAfter = artifacts.precompileMemo.Stats()
				}
				if validation.err == nil && cached.validationDeps != nil && cached.validationWork.FrameProfiles != nil && !validationWorkInvariantEqual(cached.validationWork, validation.meta.validationWork) {
					resetProfileMismatchMeter.Mark(1)
					validation.err = fmt.Errorf("%w: validation work profile changed without a program fingerprint change", core.ErrFrameTxInvalid)
				}
			}
		}(view)
	}
	for _, index := range full {
		jobs <- index
	}
	close(jobs)
	wg.Wait()

	var (
		sum, maximum                      time.Duration
		memoHits, memoMisses, actualRuns  uint64
		cachedGas, stateDependentGasTotal uint64
	)
	for _, index := range full {
		validation := validations[index]
		elapsed := validation.verifyElapsed
		sum += elapsed
		maximum = max(maximum, elapsed)
		memoHits += validation.memoAfter.Hits - validation.memoBefore.Hits
		memoMisses += validation.memoAfter.Misses - validation.memoBefore.Misses
		actualRuns += validation.memoAfter.ActualRuns - validation.memoBefore.ActualRuns
		cachedGas += validation.memoAfter.CachedGas - validation.memoBefore.CachedGas
		stateDependentGasTotal += validation.meta.validationWork.StateDependentGasLimit
	}
	resetLastVerifySumGauge.Update(sum.Nanoseconds())
	resetLastVerifyMeanGauge.Update((sum / time.Duration(len(full))).Nanoseconds())
	resetLastVerifyMaxGauge.Update(maximum.Nanoseconds())
	resetLastVerifyCountGauge.Update(int64(len(full)))
	resetLastVerifyWorkersGauge.Update(int64(workers))
	resetLastMemoHitsGauge.Update(int64(memoHits))
	resetLastMemoMissesGauge.Update(int64(memoMisses))
	resetLastMemoActualRunsGauge.Update(int64(actualRuns))
	resetLastMemoCachedGasGauge.Update(int64(cachedGas))
	resetLastStateDependentGasGauge.Update(int64(stateDependentGasTotal))
}

func validationWorkEqual(left, right validationWorkSummary) bool {
	if left.StateDependentGasLimit != right.StateDependentGasLimit ||
		left.FirstMutableFrames != right.FirstMutableFrames ||
		left.ConservativeFrames != right.ConservativeFrames ||
		left.DeployValidationGas != right.DeployValidationGas ||
		len(left.FrameProfiles) != len(right.FrameProfiles) {
		return false
	}
	for index, profile := range left.FrameProfiles {
		if right.FrameProfiles[index] != profile {
			return false
		}
	}
	return true
}

// validationWorkInvariantEqual compares only the transaction-global watershed
// and its conservative bound. Profiles of later frames may legitimately change
// because an earlier mutable frame can influence FRAMEPARAM values and the
// shared access journal.
func validationWorkInvariantEqual(left, right validationWorkSummary) bool {
	if left.StateDependentGasLimit != right.StateDependentGasLimit {
		return false
	}
	leftIndex, leftProfile, leftOK := firstMutableWorkProfile(left)
	rightIndex, rightProfile, rightOK := firstMutableWorkProfile(right)
	return leftOK == rightOK && (!leftOK || leftIndex == rightIndex && leftProfile == rightProfile)
}

func firstMutableWorkProfile(summary validationWorkSummary) (int, vm.ValidationWorkProfile, bool) {
	index := -1
	var first vm.ValidationWorkProfile
	for frameIndex, profile := range summary.FrameProfiles {
		if profile.HasMutableRead && (index < 0 || frameIndex < index) {
			index, first = frameIndex, profile
		}
	}
	return index, first, index >= 0
}

func (p *FramePool) reorgTransactions(oldHead, newHead *types.Header) (types.Transactions, types.Transactions, *validationDependencyTouches) {
	if oldHead == nil || newHead == nil {
		return nil, nil, nil
	}
	if oldHead.Hash() == newHead.ParentHash {
		block := p.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64())
		if block == nil {
			return nil, nil, nil
		}
		if accessList := block.AccessList(); accessList != nil {
			touches := newValidationDependencyTouches()
			touches.add(accessList)
			return nil, block.Transactions(), touches
		}
		return nil, block.Transactions(), nil
	}
	oldNum, newNum := oldHead.Number.Uint64(), newHead.Number.Uint64()
	var depth uint64
	if newNum > oldNum {
		depth = newNum - oldNum
	} else {
		depth = oldNum - newNum
	}
	if depth > 64 {
		return nil, nil, nil
	}
	rem := p.chain.GetBlock(oldHead.Hash(), oldNum)
	add := p.chain.GetBlock(newHead.Hash(), newNum)
	if rem == nil || add == nil {
		return nil, nil, nil
	}
	touches := newValidationDependencyTouches()
	touchesComplete := true
	addTouches := func(block *types.Block) {
		if accessList := block.AccessList(); accessList != nil {
			touches.add(accessList)
		} else {
			touchesComplete = false
		}
	}
	var discarded, included types.Transactions
	for rem.NumberU64() > add.NumberU64() {
		discarded = append(discarded, rem.Transactions()...)
		addTouches(rem)
		rem = p.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1)
		if rem == nil {
			return nil, nil, nil
		}
	}
	for add.NumberU64() > rem.NumberU64() {
		included = append(included, add.Transactions()...)
		addTouches(add)
		add = p.chain.GetBlock(add.ParentHash(), add.NumberU64()-1)
		if add == nil {
			return nil, nil, nil
		}
	}
	for rem.Hash() != add.Hash() {
		discarded = append(discarded, rem.Transactions()...)
		included = append(included, add.Transactions()...)
		addTouches(rem)
		addTouches(add)
		if rem.NumberU64() == 0 || add.NumberU64() == 0 {
			return nil, nil, nil
		}
		rem = p.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1)
		add = p.chain.GetBlock(add.ParentHash(), add.NumberU64()-1)
		if rem == nil || add == nil {
			return nil, nil, nil
		}
	}
	var lost types.Transactions
	for _, tx := range types.TxDifference(discarded, included) {
		if p.Filter(tx) {
			lost = append(lost, tx)
		}
	}
	if !touchesComplete {
		touches = nil
	}
	return lost, included, touches
}

func (p *FramePool) cacheIncludedBlobSidecars(included types.Transactions, blockNumber uint64) {
	for _, tx := range included {
		pooled := p.all[tx.Hash()]
		if pooled == nil || pooled.BlobGas() == 0 || pooled.BlobTxSidecar() == nil {
			continue
		}
		p.blobSidecars[tx.Hash()] = cachedBlobSidecar{
			sidecar:     pooled.BlobTxSidecar(),
			blockNumber: blockNumber,
		}
	}
	if blockNumber <= 64 {
		return
	}
	oldest := blockNumber - 64
	for hash, cached := range p.blobSidecars {
		if cached.blockNumber < oldest {
			delete(p.blobSidecars, hash)
			delete(p.blobCells, hash)
		}
	}
}

// SetGasTip updates the minimum gas tip and evicts underpriced transactions.
func (p *FramePool) SetGasTip(tip *big.Int) {
	p.validationMu.Lock()
	defer p.validationMu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.gasTip = *uint256.MustFromBig(tip)

	for addr, txs := range p.pending {
		var valid []*types.Transaction
		for _, tx := range txs {
			if tx.GasTipCapIntCmp(tip) >= 0 {
				valid = append(valid, tx)
			} else {
				delete(p.all, tx.Hash())
				delete(p.blobCells, tx.Hash())
				p.releaseNonceKeys(tx)
				p.releaseTxAccounting(tx.Hash())
			}
		}
		if len(valid) == 0 {
			delete(p.pending, addr)
			if p.reserver != nil {
				p.reserver.Release(addr)
			}
		} else {
			p.pending[addr] = valid
		}
	}
}

// Has returns whether the pool contains a transaction with the given hash.
func (p *FramePool) Has(hash common.Hash) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.all[hash] != nil
}

// Get returns a transaction if it exists in the pool.
func (p *FramePool) Get(hash common.Hash) *types.Transaction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.all[hash]
}

// GetCells returns validated cells for a pooled blob frame transaction.
func (p *FramePool) GetCells(hash common.Hash, mask types.CustodyBitmap) []kzg4844.Cell {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.all[hash] == nil {
		return nil
	}
	all := p.blobCells[hash]
	if len(all) == 0 {
		return nil
	}
	indices := mask.Indices()
	cells := make([]kzg4844.Cell, 0, len(all)/kzg4844.CellsPerBlob*len(indices))
	for blob := 0; blob < len(all)/kzg4844.CellsPerBlob; blob++ {
		for _, index := range indices {
			cells = append(cells, all[blob*kzg4844.CellsPerBlob+int(index)])
		}
	}
	return cells
}

// GetRLP returns the RLP-encoded transaction if found.
func (p *FramePool) GetRLP(hash common.Hash, version uint) []byte {
	tx := p.Get(hash)
	if tx == nil {
		return nil
	}
	if version >= 72 && tx.BlobGas() > 0 {
		sidecar := tx.BlobTxSidecar()
		if sidecar == nil {
			return nil
		}
		tx = tx.WithBlobTxSidecar(types.NewBlobTxSidecar(sidecar.Version, nil, sidecar.Commitments, sidecar.Proofs))
	}
	data, _ := rlp.EncodeToBytes(tx)
	return data
}

// GetMetadata returns the type and size of a pooled transaction.
func (p *FramePool) GetMetadata(hash common.Hash) *txpool.TxMetadata {
	p.mu.RLock()
	defer p.mu.RUnlock()
	tx := p.all[hash]
	if tx == nil {
		return nil
	}
	encoded, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return nil
	}
	meta := &txpool.TxMetadata{Type: tx.Type(), Size: uint64(len(encoded))}
	if tx.BlobGas() > 0 {
		sidecar := tx.BlobTxSidecar()
		if sidecar == nil {
			return nil
		}
		withoutBlobs := tx.WithBlobTxSidecar(types.NewBlobTxSidecar(sidecar.Version, nil, sidecar.Commitments, sidecar.Proofs))
		encoded, err := rlp.EncodeToBytes(withoutBlobs)
		if err != nil {
			return nil
		}
		meta.SizeWithoutBlob = uint64(len(encoded))
	}
	return meta
}

// ValidateTxBasics performs stateless validation of a frame transaction.
func (p *FramePool) ValidateTxBasics(tx *types.Transaction) error {
	p.mu.RLock()
	head := types.CopyHeader(p.currentHead)
	minTip := p.gasTip.ToBig()
	p.mu.RUnlock()
	opts := &txpool.ValidationOptions{
		Config:       p.chainconfig,
		Accept:       1 << types.FrameTxType,
		MaxSize:      txMaxSize,
		MaxBlobCount: params.BlobTxMaxBlobs,
		MinTip:       minTip,
	}
	return txpool.ValidateTransaction(tx, head, p.signer, opts)
}

// Add validates and adds frame transactions to the pool.
func (p *FramePool) Add(txs []*types.Transaction, sync bool) []error {
	errs := make([]error, len(txs))
	var added []*types.Transaction

	for i, tx := range txs {
		if err := p.ValidateTxBasics(tx); err != nil {
			errs[i] = err
			continue
		}
		if err := p.preflightAdmission(tx); err != nil {
			markInsufficientPayerRejection(err)
			errs[i] = err
			continue
		}
		cells, err := validateFrameBlobProofs(tx)
		if err != nil {
			errs[i] = err
			continue
		}
		frameTx := tx.GetFrameTx()
		if frameTx == nil {
			errs[i] = fmt.Errorf("not a frame transaction")
			continue
		}
		signatureGas, err := p.validateFrameSignaturesBounded(frameTx)
		if err != nil {
			errs[i] = err
			continue
		}
		if err := p.validateAndAdd(tx, cells, signatureGas); err != nil {
			errs[i] = err
			continue
		}
		added = append(added, tx)
	}
	if len(added) > 0 {
		event := core.NewTxsEvent{Txs: added}
		p.discoverFeed.Send(event)
		p.insertFeed.Send(event)
	}
	return errs
}

// preflightAdmission rejects transactions that are already invalid against the
// current pool or state before KZG or protocol-signature verification. The
// result is advisory: callers release p.mu during cryptographic work and repeat
// every check in validateAndAdd before insertion.
func (p *FramePool) preflightAdmission(tx *types.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.checkAdmissionCheap(tx, true)
	return err
}

func markInsufficientPayerRejection(err error) {
	if errors.Is(err, core.ErrInsufficientFunds) {
		accountingRejectMeter.Mark(1)
		accountingInsufficientMeter.Mark(1)
	}
}

func validateFrameBlobProofs(tx *types.Transaction) ([]kzg4844.Cell, error) {
	if tx.BlobGas() == 0 {
		return nil, nil
	}
	sidecar := tx.BlobTxSidecar()
	if sidecar == nil {
		return nil, errors.New("missing sidecar in blob frame transaction")
	}
	cells, err := kzg4844.ComputeCells(sidecar.Blobs)
	if err != nil {
		return nil, err
	}
	if err := txpool.ValidateCells(&types.BlobTxCellSidecar{
		Version:     sidecar.Version,
		Commitments: sidecar.Commitments,
		Proofs:      sidecar.Proofs,
		Cells:       cells,
		Custody:     types.CustodyBitmapAll,
	}); err != nil {
		return nil, err
	}
	return cells, nil
}

func validateFrameNonce(tx *types.FrameTx, statedb *state.StateDB) error {
	_, err := validateFrameNonceAndCountFirstUse(tx, statedb)
	return err
}

func validateFrameNonceAndCountFirstUse(tx *types.FrameTx, statedb *state.StateDB) (uint64, error) {
	want := new(big.Int).SetUint64(tx.NonceSeq)
	var firstUse uint64
	for _, key := range tx.NonceKeys {
		var have *big.Int
		if key.IsZero() {
			have = new(big.Int).SetUint64(statedb.GetNonce(tx.Sender))
		} else {
			value := statedb.GetState(params.NonceManagerAddress, types.NonceManagerSlot(tx.Sender, key))
			have = value.Big()
			if value == (common.Hash{}) {
				firstUse++
			}
		}
		switch have.Cmp(want) {
		case -1:
			return 0, fmt.Errorf("%w: sender %s nonce key %x tx sequence %d state sequence %s", core.ErrNonceTooHigh, tx.Sender.Hex(), key.Bytes32(), tx.NonceSeq, have)
		case 1:
			return 0, fmt.Errorf("%w: sender %s nonce key %x tx sequence %d state sequence %s", core.ErrNonceTooLow, tx.Sender.Hex(), key.Bytes32(), tx.NonceSeq, have)
		}
	}
	return firstUse, nil
}

func (p *FramePool) validateRecentRootReferences(tx *types.FrameTx, statedb *state.StateDB, head *types.Header) error {
	currentSlot := p.slotProvider(head).CurrentSlot()
	for i, ref := range tx.RecentRootRefs {
		if !types.RecentRootReferenceInWindow(currentSlot, ref.Slot) {
			return fmt.Errorf("%w: recent root reference %d slot %d is invalid at current slot %d", core.ErrFrameTxInvalid, i, ref.Slot, currentSlot)
		}
		key := types.RecentRootStorageKey(ref.SourceID, ref.Slot)
		want := types.RecentRootEntryHash(ref.SourceID, ref.Slot, ref.Root)
		if have := statedb.GetState(params.RecentRootAddress, key); have != want {
			return fmt.Errorf("%w: recent root reference %d mismatch", core.ErrFrameTxInvalid, i)
		}
	}
	return nil
}

func warmRecentRootReferences(statedb *state.StateDB, refs []types.RecentRootRef) {
	if len(refs) == 0 {
		return
	}
	statedb.AddAddressToAccessList(params.RecentRootAddress)
	for _, ref := range refs {
		statedb.AddSlotToAccessList(params.RecentRootAddress, types.RecentRootStorageKey(ref.SourceID, ref.Slot))
	}
}

type admissionCheck struct {
	replacement      *types.Transaction
	replacementIndex int
	eviction         *types.Transaction
}

// checkAdmissionCheap performs all rejection-only admission checks that don't
// require protocol-signature verification or validation-prefix EVM execution.
// The caller must hold p.mu. Since signature verification runs without p.mu,
// callers must repeat this check immediately before insertion.
func (p *FramePool) checkAdmissionCheap(tx *types.Transaction, meterPreflight bool) (admissionCheck, error) {
	check := admissionCheck{replacementIndex: -1}
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return check, fmt.Errorf("not a frame transaction")
	}
	if err := validateFrameOrdering(frameTx.Frames, frameTx.Sender); err != nil {
		return check, err
	}
	plan, err := buildValidationPrefixPlan(frameTx)
	if err != nil {
		return check, err
	}
	signatureGas, err := frameTx.SignatureGas()
	if err != nil {
		return check, err
	}
	if err := validatePrefixGasBudget(frameTx, plan, signatureGas, true, p.verifyGasCap); err != nil {
		return check, err
	}
	if p.all[tx.Hash()] != nil {
		return check, txpool.ErrAlreadyKnown
	}
	if staleProgram, stale := p.staleValidationPrograms[tx.Hash()]; p.payerCodeIdentityPreflight && stale {
		if changed, address := p.validationProgramIdentityChanged(staleProgram); changed {
			if meterPreflight {
				payerCodeIdentityReplayRejectMeter.Mark(1)
			}
			return check, fmt.Errorf("%w: validation program at %s changed since transaction admission", core.ErrFrameTxInvalid, address)
		}
		delete(p.staleValidationPrograms, tx.Hash())
		delete(p.stalePayerCode, tx.Hash())
	}
	firstUse, err := validateFrameNonceAndCountFirstUse(frameTx, p.currentState)
	if err != nil {
		return check, err
	}
	if err := validateNonceSurchargeGasLimit(frameTx, plan, firstUse); err != nil {
		return check, err
	}
	if err := p.validateRecentRootReferences(frameTx, p.currentState, p.currentHead); err != nil {
		return check, err
	}
	check.replacement, check.replacementIndex, err = p.checkNonceKeyAdmission(frameTx)
	if err != nil {
		return check, err
	}
	if check.replacement != nil && !isFrameTxPriceBumped(tx, check.replacement) {
		return check, txpool.ErrReplaceUnderpriced
	}
	if check.replacement == nil && len(p.all) >= p.limits.maxPoolSize {
		check.eviction = p.lowestPricedTransaction()
		if check.eviction == nil || !isFrameTxPriceBumped(tx, check.eviction) {
			return check, fmt.Errorf("%w: frame pool full", txpool.ErrUnderpriced)
		}
	}
	simulationTime := p.currentHead.Time + params.SecondsPerSlot
	if err := validateValidationPrefixState(frameTx, plan, p.currentState, simulationTime); err != nil {
		return check, err
	}
	if err := validateDefaultCodeVerifyFrames(frameTx, plan, p.currentState); err != nil {
		return check, err
	}
	accountingReplacement := check.replacement
	if accountingReplacement == nil {
		accountingReplacement = check.eviction
	}
	payerMeta := p.validationPayerMeta(frameTx, plan)
	if err := p.validateNonCanonicalPaymasterLimit(payerMeta, accountingReplacement); err != nil {
		return check, err
	}
	if p.payerSolvencyPreflight {
		if err := p.preflightPayerSolvencyWithMeta(tx, accountingReplacement, payerMeta, meterPreflight); err != nil {
			return check, err
		}
	}
	return check, nil
}

// validateAndAdd performs stateful validation (nonce, VERIFY simulation) and inserts.
func (p *FramePool) validateAndAdd(tx *types.Transaction, cells []kzg4844.Cell, signatureGas uint64) error {
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return fmt.Errorf("not a frame transaction")
	}
	p.validationMu.Lock()
	defer p.validationMu.Unlock()
	if err := p.ValidateTxBasics(tx); err != nil {
		return err
	}

	p.mu.Lock()
	check, err := p.checkAdmissionCheap(tx, false)
	if err != nil {
		markInsufficientPayerRejection(err)
		p.mu.Unlock()
		return err
	}
	replacement := check.replacement
	replacementIndex := check.replacementIndex
	eviction := check.eviction
	sender := frameTx.Sender

	// Reserve address (if first tx for this sender).
	held := false
	if len(p.pending[sender]) == 0 {
		if p.reserver != nil {
			if err := p.reserver.Hold(sender); err != nil {
				p.mu.Unlock()
				return err
			}
		}
		held = true
	}
	validationView := p.admissionValidationViewLocked()
	p.mu.Unlock()

	// Simulate the validation prefix.
	meta, err := validationView.simulateVerifyFramesWithSignatureGas(tx, signatureGas)
	if stateErr := validationView.currentState.Error(); stateErr != nil {
		// StateDB errors are sticky and are not reverted by a journal snapshot.
		// Never let a poisoned validation view affect a later admission.
		p.admissionValidationState = nil
		if err == nil {
			err = fmt.Errorf("frame validation state error: %w", stateErr)
		}
	}
	if err != nil {
		if held && p.reserver != nil {
			p.reserver.Release(sender)
		}
		return err
	}
	meta.signatureValidated = true
	meta.signatureGas = signatureGas
	p.mu.Lock()
	defer p.mu.Unlock()
	accountingReplacement := replacement
	if accountingReplacement == nil {
		accountingReplacement = eviction
	}
	if err := p.validatePaymasterAccounting(tx, meta, accountingReplacement); err != nil {
		accountingRejectMeter.Mark(1)
		if errors.Is(err, core.ErrInsufficientFunds) {
			accountingInsufficientMeter.Mark(1)
		}
		if held && p.reserver != nil {
			p.reserver.Release(sender)
		}
		return err
	}

	// Insert into pool.
	if replacement != nil {
		p.releaseTxAccounting(replacement.Hash())
		p.releaseNonceKeys(replacement)
		delete(p.all, replacement.Hash())
		delete(p.blobCells, replacement.Hash())
		p.pending[sender][replacementIndex] = tx
	} else {
		if eviction != nil {
			p.removeTransaction(eviction)
		}
		p.pending[sender] = append(p.pending[sender], tx)
	}
	p.all[tx.Hash()] = tx
	p.reserveNonceKeys(tx)
	if len(cells) > 0 {
		p.blobCells[tx.Hash()] = cells
	}
	p.reserveTxAccounting(tx, meta)
	delete(p.stalePayerCode, tx.Hash())
	delete(p.staleValidationPrograms, tx.Hash())
	return nil
}

func (p *FramePool) lowestPricedTransaction() *types.Transaction {
	var worst *types.Transaction
	for _, tx := range p.all {
		if worst == nil || compareFrameTxPrice(tx, worst) < 0 {
			worst = tx
		}
	}
	return worst
}

func compareFrameTxPrice(a, b *types.Transaction) int {
	if cmp := a.GasTipCap().Cmp(b.GasTipCap()); cmp != 0 {
		return cmp
	}
	if cmp := a.GasFeeCap().Cmp(b.GasFeeCap()); cmp != 0 {
		return cmp
	}
	if cmp := a.BlobGasFeeCap().Cmp(b.BlobGasFeeCap()); cmp != 0 {
		return cmp
	}
	aHash, bHash := a.Hash(), b.Hash()
	return bytes.Compare(aHash[:], bHash[:])
}

// removeTransaction removes a non-replacement transaction and releases its
// sender reservation if the sender has no other frame transaction.
func (p *FramePool) removeTransaction(tx *types.Transaction) {
	hash := tx.Hash()
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return
	}
	p.releaseTxAccounting(hash)
	p.releaseNonceKeys(tx)
	delete(p.all, hash)
	delete(p.blobCells, hash)
	sender := frameTx.Sender
	txs := p.pending[sender]
	for i, pendingTx := range txs {
		if pendingTx.Hash() == hash {
			txs = slices.Delete(txs, i, i+1)
			break
		}
	}
	if len(txs) == 0 {
		delete(p.pending, sender)
		if p.reserver != nil {
			p.reserver.Release(sender)
		}
	} else {
		p.pending[sender] = txs
	}
}

// validationViewLocked snapshots all state used by validation-prefix execution.
// The caller holds p.mu for writing, excluding StateDB reads that may populate
// internal caches while Copy iterates over them.
func (p *FramePool) validationViewLocked() *FramePool {
	return p.validationViewWithStateLocked(p.currentState.Copy())
}

// admissionValidationViewLocked returns the validation view serialized by
// validationMu. The StateDB is copied once per canonical head and reused across
// admissions; simulateVerifyFramesWithSignatureGasOutcome snapshots and reverts
// the complete validation prefix before it returns. The caller holds p.mu while
// lazily copying currentState.
func (p *FramePool) admissionValidationViewLocked() *FramePool {
	if p.admissionValidationState == nil {
		p.admissionValidationState = p.currentState.Copy()
	}
	return p.validationViewWithStateLocked(p.admissionValidationState)
}

func (p *FramePool) validationViewWithStateLocked(statedb *state.StateDB) *FramePool {
	canonicalPaymasters := make(map[common.Hash]common.Hash, len(p.canonicalPaymasters))
	for codeHash, slot := range p.canonicalPaymasters {
		canonicalPaymasters[codeHash] = slot
	}
	return &FramePool{
		chain:                      p.chain,
		chainconfig:                p.chainconfig,
		signer:                     p.signer,
		currentHead:                types.CopyHeader(p.currentHead),
		currentState:               statedb,
		slotProvider:               p.slotProvider,
		verifyGasCap:               p.verifyGasCap,
		stateDependentVerifyGasCap: p.stateDependentVerifyGasCap,
		cacheValidationPrecompiles: p.cacheValidationPrecompiles,
		validationMemoLimits:       p.validationMemoLimits,
		limits:                     p.limits,
		payerSolvencyPreflight:     p.payerSolvencyPreflight,
		payerCodeIdentityPreflight: p.payerCodeIdentityPreflight,
		selectiveRevalidation:      p.selectiveRevalidation,
		resetValidationWorkers:     p.resetValidationWorkers,
		canonicalPaymasters:        canonicalPaymasters,
	}
}

// simulateVerifyFrames validates the EIP-8141 validation prefix and returns the
// payer metadata needed by framepool accounting. Expiry verifier validity is
// checked directly, then its deterministic execution is replayed so later
// validation frames observe production-equivalent results and gas usage.
func (p *FramePool) simulateVerifyFrames(tx *types.Transaction) (frameTxMeta, error) {
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return frameTxMeta{}, fmt.Errorf("not a frame transaction")
	}
	signatureGas, err := p.validateFrameSignatures(frameTx)
	if err != nil {
		return frameTxMeta{}, err
	}
	meta, err := p.simulateVerifyFramesWithSignatureGas(tx, signatureGas)
	if err != nil {
		return frameTxMeta{}, err
	}
	meta.signatureValidated = true
	meta.signatureGas = signatureGas
	return meta, nil
}

func (p *FramePool) validateFrameSignatures(frameTx *types.FrameTx) (signatureGas uint64, err error) {
	start := time.Now()
	signatureRunMeter.Mark(1)
	var meteredGas uint64
	defer func() {
		signatureTimeTimer.UpdateSince(start)
		signatureGasMeter.Mark(int64(meteredGas))
		signatureGasHistogram.Update(int64(meteredGas))
		if err != nil {
			signatureFailureMeter.Mark(1)
		} else {
			signatureSuccessMeter.Mark(1)
		}
	}()

	signatureGas, err = frameTx.SignatureGas()
	if err != nil {
		return 0, err
	}
	meteredGas = signatureGas
	if signatureGas > p.verifyGasCap {
		return 0, fmt.Errorf("signature validation gas %d exceeds cap %d", signatureGas, p.verifyGasCap)
	}
	sigHash := frameTx.SigHash(p.chainconfig.ChainID)
	if err := types.ValidateFrameTxSignatures(frameTx, sigHash); err != nil {
		return 0, err
	}
	return signatureGas, nil
}

func (p *FramePool) validateFrameSignaturesBounded(frameTx *types.FrameTx) (uint64, error) {
	if p.signatureValidationSlots == nil {
		return p.validateFrameSignatures(frameTx)
	}
	p.signatureValidationSlots <- struct{}{}
	defer func() { <-p.signatureValidationSlots }()
	return p.validateFrameSignatures(frameTx)
}

func (p *FramePool) simulateVerifyFramesWithSignatureGas(tx *types.Transaction, signatureGas uint64) (frameTxMeta, error) {
	return p.simulateVerifyFramesWithSignatureGasAndArtifacts(tx, signatureGas, p.newValidationArtifacts())
}

func (p *FramePool) simulateVerifyFramesWithSignatureGasAndArtifacts(tx *types.Transaction, signatureGas uint64, artifacts validationArtifacts) (frameTxMeta, error) {
	start := time.Now()
	memoBefore := artifacts.precompileMemo.Stats()
	meta, outcome, err := p.simulateVerifyFramesWithSignatureGasOutcomeAndArtifacts(tx, signatureGas, artifacts)
	markValidationMemoDelta(memoBefore, artifacts.precompileMemo.Stats())
	verifyRunMeter.Mark(1)
	verifyTimeTimer.UpdateSince(start)
	verifyGasMeter.Mark(int64(outcome.gasUsed()))
	verifyGasHistogram.Update(int64(outcome.gasUsed()))
	markVerifyOutcome(outcome.failureClass, err != nil)
	return meta, err
}

func markValidationMemoDelta(before, after vm.PrecompileCacheStats) {
	validationMemoHitMeter.Mark(int64(after.Hits - before.Hits))
	validationMemoMissMeter.Mark(int64(after.Misses - before.Misses))
	validationMemoActualRunMeter.Mark(int64(after.ActualRuns - before.ActualRuns))
	validationMemoStoreMeter.Mark(int64(after.Stores - before.Stores))
	validationMemoUncacheableMeter.Mark(int64(after.Uncacheable - before.Uncacheable))
	validationMemoSaturatedMeter.Mark(int64(after.Saturated - before.Saturated))
	validationMemoBeforeUncacheableMeter.Mark(int64(after.BeforeMutableUncacheable - before.BeforeMutableUncacheable))
	validationMemoAfterUncacheableMeter.Mark(int64(after.AfterMutableUncacheable - before.AfterMutableUncacheable))
	validationMemoBeforeSaturatedMeter.Mark(int64(after.BeforeMutableSaturated - before.BeforeMutableSaturated))
	validationMemoAfterSaturatedMeter.Mark(int64(after.AfterMutableSaturated - before.AfterMutableSaturated))
}

// simulateVerifyFramesWithSignatureGasOutcome runs the production validation
// path while retaining the final VERIFY execution outcome for benchmarks and
// corpus qualification. Admission callers intentionally discard the outcome.
func (p *FramePool) simulateVerifyFramesWithSignatureGasOutcome(tx *types.Transaction, signatureGas uint64) (frameTxMeta, verifyResult, error) {
	return p.simulateVerifyFramesWithSignatureGasOutcomeAndArtifacts(tx, signatureGas, p.newValidationArtifacts())
}

func (p *FramePool) newValidationArtifacts() validationArtifacts {
	if !p.cacheValidationPrecompiles {
		return validationArtifacts{}
	}
	return validationArtifacts{precompileMemo: vm.NewValidationPrecompileMemo(p.validationMemoLimits)}
}

func (p *FramePool) simulateVerifyFramesWithSignatureGasOutcomeAndArtifacts(tx *types.Transaction, signatureGas uint64, artifacts validationArtifacts) (frameTxMeta, verifyResult, error) {
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return frameTxMeta{}, verifyResult{}, fmt.Errorf("not a frame transaction")
	}
	head := p.currentHead
	rules := p.chainconfig.Rules(head.Number, head.Difficulty.Sign() == 0, head.Time)
	precompiles := vm.ActivePrecompiles(rules)
	sigHash := frameTx.SigHash(p.chainconfig.ChainID)

	// Build FrameContext (mirrors state_transition.go:806-821).
	frameCtx := &vm.FrameContext{
		Sender:         frameTx.Sender,
		NonceKeys:      frameTx.NonceKeys,
		NonceSeq:       frameTx.NonceSeq,
		LegacyNonce:    p.currentState.GetNonce(frameTx.Sender),
		NonceKeysHash:  frameTx.NonceKeysHash(),
		Frames:         frameTx.Frames,
		Signatures:     frameTx.Signatures,
		GasTipCap:      new(uint256.Int).Set(frameTx.GasTipCap),
		GasFeeCap:      new(uint256.Int).Set(frameTx.GasFeeCap),
		GasLimit:       frameTx.TotalGas(),
		SigHash:        sigHash,
		FrameIndex:     0,
		FrameResults:   make([]uint8, len(frameTx.Frames)),
		FrameGasUsed:   make([]types.FrameGasUsed, len(frameTx.Frames)),
		RecentRootRefs: frameTx.RecentRootRefs,
	}
	if frameTx.BlobFeeCap != nil {
		frameCtx.BlobFeeCap = new(uint256.Int).Set(frameTx.BlobFeeCap)
	}
	if len(frameTx.BlobHashes) > 0 {
		frameCtx.BlobHashes = frameTx.BlobHashes
	}

	// Shared block context used for both simulation phases.
	random := common.Hash{}
	simulationHead := *head
	simulationHead.Number = new(big.Int).Add(head.Number, big.NewInt(1))
	simulationHead.Time = head.Time + params.SecondsPerSlot
	blockCtx := vm.BlockContext{
		CanTransfer:  core.CanTransfer,
		Transfer:     core.Transfer,
		GetHash:      func(uint64) common.Hash { return common.Hash{} },
		Coinbase:     common.Address{},
		GasLimit:     head.GasLimit,
		BlockNumber:  simulationHead.Number,
		Time:         simulationHead.Time,
		Difficulty:   new(big.Int),
		BaseFee:      head.BaseFee,
		Random:       &random,
		SlotProvider: p.slotProvider(&simulationHead),
	}
	blockCtx.BlobBaseFee = framePoolBlobBaseFee(p.chainconfig, head)

	plan, err := p.validationPrefixPlan(frameTx, p.currentState, blockCtx.Time)
	if err != nil {
		return frameTxMeta{}, verifyResult{}, err
	}
	if err := validatePrefixGasBudget(frameTx, plan, signatureGas, true, p.verifyGasCap); err != nil {
		return frameTxMeta{}, verifyResult{}, err
	}
	// Validation views are caller-owned. Reuse their StateDB read caches across
	// transactions, but roll back the entire validation prefix before returning.
	baseState := p.currentState
	transactionSnapshot := baseState.Snapshot()
	defer baseState.RevertToSnapshot(transactionSnapshot)
	baseState.Prepare(rules, frameTx.Sender, common.Address{}, nil, precompiles, nil)
	warmRecentRootReferences(baseState, frameTx.RecentRootRefs)
	storageReads := make(map[common.Hash]struct{})
	codeReads := make(map[common.Address]struct{})
	legacyNonceRead := false
	blobBaseFeeRead := false
	workSummary := validationWorkSummary{FrameProfiles: make(map[int]vm.ValidationWorkProfile)}
	mergeDependencies := func(result verifyResult) {
		for _, slot := range result.storageReads {
			storageReads[slot] = struct{}{}
		}
		for _, addr := range result.codeReads {
			codeReads[addr] = struct{}{}
		}
		legacyNonceRead = legacyNonceRead || result.legacyNonceRead
		blobBaseFeeRead = blobBaseFeeRead || result.blobBaseFeeRead
	}
	mergeWork := func(result verifyResult) error {
		return workSummary.addFrame(result.frameIndex, result.workProfile)
	}
	directDefaultCode := canDirectEvaluateDefaultCodePrefix(frameTx, plan, baseState)
	if directDefaultCode {
		directVerifyRunMeter.Mark(1)
	}
	if plan.expiryIndex >= 0 {
		resetValidationTransientState(baseState, plan.expiryIndex)
		expiryResult, expiryErr := p.simulateVerifyFrame(frameTx, frameCtx, blockCtx, precompiles, baseState, plan.expiryIndex, true, false, false, artifacts)
		if expiryErr != nil {
			return frameTxMeta{}, expiryResult, expiryErr
		}
		recordSuccessfulValidationFrame(frameCtx, expiryResult)
	}

	if plan.deployIndex >= 0 {
		resetValidationTransientState(baseState, plan.deployIndex)
		if len(baseState.GetCode(frameTx.Sender)) != 0 {
			return frameTxMeta{}, verifyResult{}, fmt.Errorf("deploy frame requires code-less sender in transaction pre-state")
		}
		i := plan.deployIndex
		frame := frameTx.Frames[i]
		target := frameTx.Sender
		if frame.Target != nil {
			target = *frame.Target
		}
		frameMemo := artifacts.precompileMemo.ValidationFrameView()
		tracer := vm.NewFrameValidationTracerWithOptions(baseState, frameTx.Sender, target, precompiles, vm.FrameValidationTracerOptions{
			AllowCreate:               true,
			AllowSenderStorageWrites:  true,
			Deployment:                true,
			FrameGasLimit:             frame.GasLimit,
			PrecompileMemo:            frameMemo,
			BlobBaseFeeAffectsMaxCost: len(frameTx.BlobHashes) > 0,
		})
		evm := vm.NewEVM(blockCtx, baseState, p.chainconfig, vm.Config{Tracer: tracer.Hooks()})
		evm.SetPrecompileCache(frameMemo)
		evm.SetTxContext(vm.TxContext{
			Origin:   params.FrameEntryPointAddress,
			GasPrice: new(uint256.Int),
		})
		evm.TxContext.FrameCtx = frameCtx
		frameCtx.FrameIndex = i
		_, remaining, vmerr := evm.Call(params.FrameEntryPointAddress, target, frame.Data, vm.NewFrameGasBudget(frame.GasLimit, frame.StateGasLimit), new(uint256.Int))
		evm.TxContext.FrameCtx = nil
		for _, slot := range tracer.StorageReads() {
			storageReads[slot] = struct{}{}
		}
		for _, addr := range tracer.CodeReads() {
			codeReads[addr] = struct{}{}
		}
		legacyNonceRead = legacyNonceRead || tracer.ReadsLegacyNonce()
		blobBaseFeeRead = blobBaseFeeRead || tracer.ReadsBlobBaseFee()
		if err := workSummary.addFrame(i, tracer.WorkProfile()); err != nil {
			return frameTxMeta{}, verifyResult{}, err
		}
		if violation := tracer.Violation(); violation != nil {
			return frameTxMeta{}, verifyResult{}, fmt.Errorf("deploy frame %d: %w", i, violation)
		}
		if vmerr != nil {
			return frameTxMeta{}, verifyResult{}, fmt.Errorf("deploy frame %d simulation failed: %v", i, vmerr)
		}
		if hasNoCode(baseState, frameTx.Sender) {
			return frameTxMeta{}, verifyResult{}, fmt.Errorf("deploy frame %d did not install sender code", i)
		}
		frameCtx.FrameResults[i] = types.FrameReceiptStatusSuccessful
		frameCtx.FrameGasUsed[i] = types.FrameGasUsed{
			Execution: frame.GasLimit - remaining.ExecutionGas,
			State:     frame.StateGasLimit - remaining.StateGas,
		}
	}

	var senderResult verifyResult
	resetValidationTransientState(baseState, plan.senderVerifyIndex)
	if directDefaultCode {
		senderResult, err = evaluateDefaultCodeVerifyFrame(frameTx, plan.senderVerifyIndex)
	} else {
		senderResult, err = p.simulateVerifyFrame(frameTx, frameCtx, blockCtx, precompiles, baseState, plan.senderVerifyIndex, true, true, workSummary.hasEarlierMutableFrame(plan.senderVerifyIndex), artifacts)
	}
	mergeDependencies(senderResult)
	if workErr := mergeWork(senderResult); workErr != nil {
		return frameTxMeta{}, senderResult, workErr
	}
	senderVerifyRunMeter.Mark(1)
	senderVerifyGasMeter.Mark(int64(senderResult.frameGasUsed()))
	if err != nil {
		return frameTxMeta{}, senderResult, err
	}
	recordSuccessfulValidationFrame(frameCtx, senderResult)
	if senderResult.approveScope == vm.ApproveBoth {
		if err := p.validateNonceSurcharge(frameTx, senderResult.gasRemaining); err != nil {
			return frameTxMeta{}, senderResult, err
		}
		meta := frameTxMeta{
			payer:                 frameTx.Sender,
			maxCost:               p.maxCost(tx),
			payerAvailableBalance: p.currentState.GetBalance(frameTx.Sender).ToBig(),
			payerCodeHash:         p.currentState.GetCodeHash(frameTx.Sender),
		}
		meta.validationDeps = p.snapshotValidationDependencies(frameTx, plan, meta, storageReads, codeReads, legacyNonceRead, blobBaseFeeRead, directDefaultCode)
		if err := p.finalizeValidationArtifacts(&meta, workSummary, artifacts); err != nil {
			return frameTxMeta{}, senderResult, err
		}
		return meta, senderResult, nil
	}
	if senderResult.approveScope != vm.ApproveExecution {
		return frameTxMeta{}, senderResult, fmt.Errorf("VERIFY frame %d approved scope %d, want self approval 3 or execution approval 2", plan.senderVerifyIndex, senderResult.approveScope)
	}
	if plan.payVerifyIndex < 0 {
		return frameTxMeta{}, senderResult, fmt.Errorf("execution-only validation prefix missing payment VERIFY frame")
	}
	payTarget := resolveFrameTarget(frameTx.Sender, frameTx.Frames[plan.payVerifyIndex])
	meta := p.classifyPayer(frameTx.Sender, payTarget)
	var payResult verifyResult
	resetValidationTransientState(baseState, plan.payVerifyIndex)
	if directDefaultCode {
		payResult, err = evaluateDefaultCodeVerifyFrame(frameTx, plan.payVerifyIndex)
	} else {
		payResult, err = p.simulateVerifyFrame(frameTx, frameCtx, blockCtx, precompiles, baseState, plan.payVerifyIndex, !meta.canonicalPaymaster, true, workSummary.hasEarlierMutableFrame(plan.payVerifyIndex), artifacts)
	}
	mergeDependencies(payResult)
	if workErr := mergeWork(payResult); workErr != nil {
		return frameTxMeta{}, payResult, workErr
	}
	payResult.prefixGasUsed = senderResult.gasUsed() + payResult.frameGasUsed()
	if err != nil {
		return frameTxMeta{}, payResult, err
	}
	recordSuccessfulValidationFrame(frameCtx, payResult)
	if payResult.approveScope != vm.ApprovePayment {
		return frameTxMeta{}, payResult, fmt.Errorf("VERIFY frame %d approved scope %d, want payment approval 1", plan.payVerifyIndex, payResult.approveScope)
	}
	if err := p.validateNonceSurcharge(frameTx, payResult.gasRemaining); err != nil {
		return frameTxMeta{}, payResult, err
	}
	meta.maxCost = p.maxCost(tx)
	meta.payerAvailableBalance = p.payerAvailableBalance(meta)
	meta.payerCodeHash = p.currentState.GetCodeHash(meta.payer)
	meta.validationDeps = p.snapshotValidationDependencies(frameTx, plan, meta, storageReads, codeReads, legacyNonceRead, blobBaseFeeRead, directDefaultCode)
	if err := p.finalizeValidationArtifacts(&meta, workSummary, artifacts); err != nil {
		return frameTxMeta{}, payResult, err
	}
	return meta, payResult, nil
}

func (p *FramePool) finalizeValidationArtifacts(meta *frameTxMeta, work validationWorkSummary, artifacts validationArtifacts) error {
	meta.validationWork = work
	meta.validationMemo = artifacts.precompileMemo
	stateDependentGasMeter.Mark(int64(work.StateDependentGasLimit))
	stateDependentGasHistogram.Update(int64(work.StateDependentGasLimit))
	for _, profile := range work.FrameProfiles {
		markFirstMutable(profile)
	}
	cap := p.stateDependentVerifyGasCap
	if cap == 0 {
		cap = p.verifyGasCap
	}
	if work.StateDependentGasLimit > cap {
		stateDependentRejectMeter.Mark(1)
		return fmt.Errorf("%w: state-dependent validation gas %d exceeds cap %d", core.ErrFrameTxInvalid, work.StateDependentGasLimit, cap)
	}
	if p.rejectIncompleteValidationMemo && (artifacts.precompileMemo == nil || !artifacts.precompileMemo.CompleteBeforeFirstMutable()) {
		validationMemoIncompleteRejectMeter.Mark(1)
		return fmt.Errorf("%w: validation precompile memo incomplete before first mutable read", core.ErrFrameTxInvalid)
	}
	return nil
}

func markFirstMutable(profile vm.ValidationWorkProfile) {
	if profile.GasAccountingConservative {
		firstMutableConservativeMeter.Mark(1)
	}
	switch profile.FirstMutableReadKind {
	case vm.ValidationMutableReadStorage:
		firstMutableStorageMeter.Mark(1)
	case vm.ValidationMutableReadLegacyNonce:
		firstMutableLegacyNonceMeter.Mark(1)
	case vm.ValidationMutableReadCode:
		firstMutableCodeMeter.Mark(1)
	case vm.ValidationMutableReadEnvironment:
		firstMutableEnvironmentMeter.Mark(1)
	case vm.ValidationMutableReadPriorFrame:
		firstMutablePriorFrameMeter.Mark(1)
	}
}

type validationPrefixPlan struct {
	expiryIndex       int
	deployIndex       int
	senderVerifyIndex int
	payVerifyIndex    int
}

func (p *FramePool) validationPrefixPlan(frameTx *types.FrameTx, statedb *state.StateDB, timestamp uint64) (validationPrefixPlan, error) {
	plan, err := buildValidationPrefixPlan(frameTx)
	if err != nil {
		return plan, err
	}
	if err := validateValidationPrefixState(frameTx, plan, statedb, timestamp); err != nil {
		return plan, err
	}
	return plan, nil
}

func buildValidationPrefixPlan(frameTx *types.FrameTx) (validationPrefixPlan, error) {
	plan := validationPrefixPlan{
		expiryIndex:       -1,
		deployIndex:       -1,
		senderVerifyIndex: -1,
		payVerifyIndex:    -1,
	}
	if len(frameTx.Frames) == 0 {
		return plan, fmt.Errorf("no frames in transaction")
	}
	start := 0
	if frame := frameTx.Frames[0]; types.IsFrameExpiryVerifier(frame, resolveFrameTarget(frameTx.Sender, frame)) {
		plan.expiryIndex = 0
		start = 1
	}
	for i := start; i < len(frameTx.Frames); i++ {
		frame := frameTx.Frames[i]
		if frame.Mode > types.FrameModeSender {
			return plan, fmt.Errorf("frame has invalid mode %d", frame.Mode)
		}
		target := resolveFrameTarget(frameTx.Sender, frame)
		if types.IsFrameExpiryVerifier(frame, target) {
			return plan, fmt.Errorf("expiry verifier frame %d must be first", i)
		}
	}
	if start == len(frameTx.Frames) {
		return plan, fmt.Errorf("no non-expiry validation prefix frames")
	}
	pos := start
	first := frameTx.Frames[pos]
	if first.Mode == types.FrameModeDefault {
		if first.Flags != 0 {
			return plan, fmt.Errorf("deploy frame %d has flags %d, want 0", pos, first.Flags)
		}
		plan.deployIndex = pos
		pos++
		if pos >= len(frameTx.Frames) {
			return plan, fmt.Errorf("deploy validation prefix missing sender VERIFY frame")
		}
	}
	senderVerifyIndex := pos
	senderVerify := frameTx.Frames[senderVerifyIndex]
	if senderVerify.Mode != types.FrameModeVerify || resolveFrameTarget(frameTx.Sender, senderVerify) != frameTx.Sender {
		return plan, fmt.Errorf("validation prefix must begin with VERIFY targeting sender")
	}
	plan.senderVerifyIndex = senderVerifyIndex
	pos++
	switch senderVerify.Flags {
	case vm.ApproveBoth:
	case vm.ApproveExecution:
		if pos >= len(frameTx.Frames) {
			return plan, fmt.Errorf("execution-only validation prefix missing payment VERIFY frame")
		}
		payFrame := frameTx.Frames[pos]
		if payFrame.Mode != types.FrameModeVerify || payFrame.Flags != vm.ApprovePayment {
			return plan, fmt.Errorf("payment frame %d must be VERIFY with flags 1", pos)
		}
		plan.payVerifyIndex = pos
		pos++
	default:
		return plan, fmt.Errorf("sender VERIFY frame %d has flags %d, want 2 or 3", senderVerifyIndex, senderVerify.Flags)
	}
	for i := pos; i < len(frameTx.Frames); i++ {
		if frameTx.Frames[i].Mode == types.FrameModeVerify {
			return plan, fmt.Errorf("VERIFY frame %d appears after validation prefix", i)
		}
	}
	return plan, nil
}

func validateValidationPrefixState(frameTx *types.FrameTx, plan validationPrefixPlan, statedb *state.StateDB, timestamp uint64) error {
	if plan.deployIndex >= 0 {
		frame := frameTx.Frames[plan.deployIndex]
		target := resolveFrameTarget(frameTx.Sender, frame)
		if delegate, ok := types.ParseDelegation(statedb.GetCode(target)); ok {
			return fmt.Errorf("%w: deploy frame target %s is EIP-7702 delegated to %s", core.ErrFrameTxInvalid, target, delegate)
		}
	}
	if plan.expiryIndex < 0 {
		return nil
	}
	frame := frameTx.Frames[plan.expiryIndex]
	target := resolveFrameTarget(frameTx.Sender, frame)
	return validateExpiryVerifierFrame(statedb, plan.expiryIndex, frame, target, timestamp)
}

func validateDefaultCodeVerifyFrames(frameTx *types.FrameTx, plan validationPrefixPlan, statedb *state.StateDB) error {
	for _, index := range []int{plan.senderVerifyIndex, plan.payVerifyIndex} {
		if index < 0 {
			continue
		}
		target := resolveFrameTarget(frameTx.Sender, frameTx.Frames[index])
		// A deploy frame may replace the sender's default code before either
		// sender-targeted VERIFY executes. Its result requires simulation.
		if plan.deployIndex >= 0 && target == frameTx.Sender {
			continue
		}
		if !hasNoCode(statedb, target) {
			continue
		}
		frame := frameTx.Frames[index]
		if _, _, err := vm.EvaluateDefaultCodeVerify(frame, frameTx.Signatures, frameTx.Sender, target, vm.NewFrameGasBudget(frame.GasLimit, frame.StateGasLimit)); err != nil {
			return fmt.Errorf("default-code VERIFY frame %d failed preflight: %w", index, err)
		}
	}
	return nil
}

func validateExpiryVerifierFrame(statedb *state.StateDB, index int, frame types.Frame, target common.Address, timestamp uint64) error {
	if !bytes.Equal(statedb.GetCode(target), params.FrameExpiryVerifierCode) {
		return fmt.Errorf("expiry verifier frame %d missing canonical code", index)
	}
	deadline, ok := types.DecodeFrameExpiryDeadline(frame.Data)
	if !ok {
		return fmt.Errorf("expiry verifier frame %d has invalid data length", index)
	}
	if deadline < timestamp {
		return fmt.Errorf("expiry verifier frame %d expired: deadline %d < timestamp %d", index, deadline, timestamp)
	}
	return nil
}

func validatePrefixGasBudget(frameTx *types.FrameTx, plan validationPrefixPlan, signatureGas uint64, includePay bool, gasCap uint64) error {
	total := signatureGas
	var stateTotal uint64
	indices := []int{plan.expiryIndex, plan.deployIndex, plan.senderVerifyIndex}
	if includePay {
		indices = append(indices, plan.payVerifyIndex)
	}
	for _, index := range indices {
		if index < 0 {
			continue
		}
		frame := frameTx.Frames[index]
		if frame.Flags&types.FrameFlagAtomicBatch != 0 {
			return fmt.Errorf("validation prefix frame %d has atomic batch flag", index)
		}
		var overflow bool
		total, overflow = commonmath.SafeAdd(total, frame.GasLimit)
		if overflow || total > gasCap {
			return fmt.Errorf("validation prefix gas %d exceeds cap %d", total, gasCap)
		}
		stateTotal, overflow = commonmath.SafeAdd(stateTotal, frame.StateGasLimit)
		if overflow || stateTotal > params.FrameTxMaxVerifyStateGas {
			return fmt.Errorf("validation prefix state gas %d exceeds cap %d", stateTotal, params.FrameTxMaxVerifyStateGas)
		}
	}
	return nil
}

func canDirectEvaluateDefaultCodePrefix(frameTx *types.FrameTx, plan validationPrefixPlan, statedb *state.StateDB) bool {
	if plan.deployIndex >= 0 || !hasNoCode(statedb, frameTx.Sender) {
		return false
	}
	if plan.payVerifyIndex < 0 {
		return true
	}
	payTarget := resolveFrameTarget(frameTx.Sender, frameTx.Frames[plan.payVerifyIndex])
	return hasNoCode(statedb, payTarget)
}

func evaluateDefaultCodeVerifyFrame(frameTx *types.FrameTx, index int) (verifyResult, error) {
	frame := frameTx.Frames[index]
	target := resolveFrameTarget(frameTx.Sender, frame)
	scope, remaining, err := vm.EvaluateDefaultCodeVerify(frame, frameTx.Signatures, frameTx.Sender, target, vm.NewFrameGasBudget(frame.GasLimit, frame.StateGasLimit))
	result := verifyResult{
		approveScope:      scope,
		frameIndex:        index,
		target:            target,
		gasLimit:          frame.GasLimit,
		gasRemaining:      remaining.ExecutionGas,
		stateGasLimit:     frame.StateGasLimit,
		stateGasRemaining: remaining.StateGas,
		workProfile: vm.ValidationWorkProfile{
			FrameGasLimit: frame.GasLimit,
		},
	}
	if err == nil {
		return result, nil
	}
	switch {
	case errors.Is(err, vm.ErrOutOfGas):
		result.failureClass = verifyFailureOutOfGas
	case errors.Is(err, vm.ErrExecutionReverted):
		result.failureClass = verifyFailureReverted
	default:
		result.failureClass = verifyFailureEVM
	}
	return result, fmt.Errorf("VERIFY frame %d execution failed: %v", index, err)
}

func (p *FramePool) simulateVerifyFrame(frameTx *types.FrameTx, frameCtx *vm.FrameContext, blockCtx vm.BlockContext, precompiles []common.Address, baseState *state.StateDB, index int, enforceRules, requireApprove, priorFrameMutable bool, artifacts validationArtifacts) (verifyResult, error) {
	frame := frameTx.Frames[index]
	target := resolveFrameTarget(frameTx.Sender, frame)

	// Successful validation frames share the transaction access journal. The
	// outer transaction snapshot rolls all simulation effects back on return;
	// failed EVM calls revert their own frame snapshot.
	simState := baseState
	frameMemo := artifacts.precompileMemo.ValidationFrameView()
	tracer := vm.NewFrameValidationTracerWithOptions(simState, frameTx.Sender, target, precompiles, vm.FrameValidationTracerOptions{
		ProfileOnly:               !enforceRules,
		PriorFrameMutable:         priorFrameMutable,
		BlobBaseFeeAffectsMaxCost: len(frameTx.BlobHashes) > 0,
		FrameGasLimit:             frame.GasLimit,
		PrecompileMemo:            frameMemo,
	})
	evmConfig := vm.Config{Tracer: tracer.Hooks()}
	evm := vm.NewEVM(blockCtx, simState, p.chainconfig, evmConfig)
	evm.SetPrecompileCache(frameMemo)
	evm.SetTxContext(vm.TxContext{
		Origin:   params.FrameEntryPointAddress,
		GasPrice: new(uint256.Int),
	})
	evm.TxContext.FrameCtx = frameCtx
	frameCtx.FrameIndex = index

	caller := params.FrameEntryPointAddress
	var (
		remaining vm.GasBudget
		vmerr     error
	)
	if hasNoCode(simState, target) {
		_, remaining, vmerr = vm.ExecuteDefaultCodeWithGasBudget(evm, caller, target, frame.Data, vm.NewFrameGasBudget(frame.GasLimit, frame.StateGasLimit), frame.Mode)
	} else {
		_, remaining, vmerr = evm.StaticCall(caller, target, frame.Data, vm.NewFrameGasBudget(frame.GasLimit, frame.StateGasLimit))
	}
	evm.TxContext.FrameCtx = nil
	result := verifyResult{
		frameIndex:        index,
		target:            target,
		gasLimit:          frame.GasLimit,
		gasRemaining:      remaining.ExecutionGas,
		stateGasLimit:     frame.StateGasLimit,
		stateGasRemaining: remaining.StateGas,
		workProfile:       tracer.WorkProfile(),
	}
	result.storageReads = tracer.StorageReads()
	result.codeReads = tracer.CodeReads()
	result.legacyNonceRead = tracer.ReadsLegacyNonce()
	result.blobBaseFeeRead = tracer.ReadsBlobBaseFee()
	if violation := tracer.Violation(); violation != nil {
		if violation.Rule == "OP-020" {
			result.failureClass = verifyFailureOutOfGas
		} else {
			result.failureClass = verifyFailureTracerViolation
		}
		return result, fmt.Errorf("VERIFY frame %d: %w", index, violation)
	}
	if vmerr != nil {
		switch {
		case errors.Is(vmerr, vm.ErrOutOfGas):
			result.failureClass = verifyFailureOutOfGas
		case errors.Is(vmerr, vm.ErrExecutionReverted):
			result.failureClass = verifyFailureReverted
		default:
			result.failureClass = verifyFailureEVM
		}
		return result, fmt.Errorf("VERIFY frame %d execution failed: %v", index, vmerr)
	}
	scope := evm.TxContext.ApproveScope
	if requireApprove && scope == vm.ApproveNone {
		result.failureClass = verifyFailureDidNotApprove
		return result, fmt.Errorf("VERIFY frame %d did not APPROVE", index)
	}
	result.approveScope = scope
	return result, nil
}

func recordSuccessfulValidationFrame(frameCtx *vm.FrameContext, result verifyResult) {
	frameCtx.FrameResults[result.frameIndex] = types.FrameReceiptStatusSuccessful
	frameCtx.FrameGasUsed[result.frameIndex] = types.FrameGasUsed{
		Execution: result.frameGasUsed(),
		State:     result.frameStateGasUsed(),
	}
}

func resetValidationTransientState(statedb *state.StateDB, frameIndex int) {
	if frameIndex > 0 {
		statedb.ResetTransientStorage()
	}
}

func (p *FramePool) validateNonceSurcharge(frameTx *types.FrameTx, gasRemaining uint64) error {
	if frameTx.UsesLegacyNonce() {
		return nil
	}
	var firstUse uint64
	for _, key := range frameTx.NonceKeys {
		slot := types.NonceManagerSlot(frameTx.Sender, key)
		if p.currentState.GetState(params.NonceManagerAddress, slot) == (common.Hash{}) {
			firstUse++
		}
	}
	required := firstUse * params.KeyedNonceFirstUseGas
	if gasRemaining < required {
		return fmt.Errorf("payment VERIFY frame has %d gas remaining, need %d for keyed nonce first use", gasRemaining, required)
	}
	return nil
}

func validateNonceSurchargeGasLimit(frameTx *types.FrameTx, plan validationPrefixPlan, firstUse uint64) error {
	if frameTx.UsesLegacyNonce() || firstUse == 0 {
		return nil
	}
	index := plan.senderVerifyIndex
	if plan.payVerifyIndex >= 0 {
		index = plan.payVerifyIndex
	}
	required := firstUse * params.KeyedNonceFirstUseGas
	if gasLimit := frameTx.Frames[index].GasLimit; gasLimit < required {
		return fmt.Errorf("payment VERIFY frame %d has gas limit %d, need at least %d for keyed nonce first use", index, gasLimit, required)
	}
	return nil
}

func resolveFrameTarget(sender common.Address, frame types.Frame) common.Address {
	if frame.Target != nil {
		return *frame.Target
	}
	return sender
}

// canonicalPaymasterWithdrawalSlot identifies the exact canonical runtime and
// returns the storage slot containing its pending withdrawal amount. The slot
// is part of the runtime-specific public-mempool accounting contract.
func (p *FramePool) canonicalPaymasterWithdrawalSlot(addr common.Address) (common.Hash, bool) {
	codeHash := p.currentState.GetCodeHash(addr)
	if codeHash == canonicalPaymasterCodeHash {
		return canonicalPaymasterPendingWithdrawalSlot, true
	}
	slot, ok := p.canonicalPaymasters[codeHash]
	return slot, ok
}

func (p *FramePool) isCanonicalPaymaster(addr common.Address) bool {
	_, canonical := p.canonicalPaymasterWithdrawalSlot(addr)
	return canonical
}

func (p *FramePool) pendingCanonicalWithdrawal(addr common.Address) *big.Int {
	slot, canonical := p.canonicalPaymasterWithdrawalSlot(addr)
	if !canonical {
		return new(big.Int)
	}
	return p.currentState.GetState(addr, slot).Big()
}

// classifyPayer records the public-mempool accounting class of a resolved payer.
// The non-canonical pending cap applies only to code-bearing paymasters. Raw code
// is intentional here: an EIP-7702 delegation indicator is non-empty code and is
// not a default-code sponsor, irrespective of the delegate's resolved code.
func (p *FramePool) classifyPayer(sender, payer common.Address) frameTxMeta {
	usesPaymaster := payer != sender
	canonical := p.isCanonicalPaymaster(payer)
	return frameTxMeta{
		payer:                 payer,
		usesPaymaster:         usesPaymaster,
		canonicalPaymaster:    canonical,
		nonCanonicalPaymaster: usesPaymaster && !canonical && len(p.currentState.GetCode(payer)) != 0,
		payerCodeHash:         p.currentState.GetCodeHash(payer),
	}
}

func newValidationDependencyIndex() *validationDependencyIndex {
	return &validationDependencyIndex{
		byKey:           make(map[validationDependencyKey]*validationDependencyEntry),
		byTx:            make(map[common.Hash][]validationDependencyKey),
		accountingByKey: make(map[validationDependencyKey]map[common.Hash]struct{}),
		accountingByTx:  make(map[common.Hash][]validationDependencyKey),
	}
}

func newValidationDependencyTouches() *validationDependencyTouches {
	return &validationDependencyTouches{keys: make(map[validationDependencyKey]struct{})}
}

func (touches *validationDependencyTouches) add(accessList *bal.BlockAccessList) {
	for _, account := range *accessList {
		if len(account.BalanceChanges) > 0 {
			touches.keys[validationDependencyKey{kind: validationBalanceDependency, address: account.Address}] = struct{}{}
		}
		if len(account.NonceChanges) > 0 {
			touches.keys[validationDependencyKey{kind: validationNonceDependency, address: account.Address}] = struct{}{}
		}
		if len(account.CodeChanges) > 0 {
			touches.keys[validationDependencyKey{kind: validationCodeDependency, address: account.Address}] = struct{}{}
		}
		for _, storage := range account.StorageChanges {
			if storage.Slot == nil {
				continue
			}
			touches.keys[validationDependencyKey{
				kind:    validationStorageDependency,
				address: account.Address,
				slot:    storage.Slot.Bytes32(),
			}] = struct{}{}
		}
	}
}

func (index *validationDependencyIndex) add(hash common.Hash, sender common.Address, meta frameTxMeta, accountingKeys ...validationDependencyKey) {
	if index == nil || meta.validationDeps == nil {
		return
	}
	index.remove(hash)
	snapshot := meta.validationDeps
	dependencies := make(map[validationDependencyKey]common.Hash)
	conflicts := make(map[validationDependencyKey]struct{})
	addDependency := func(key validationDependencyKey, value common.Hash) {
		if previous, ok := dependencies[key]; ok && previous != value {
			conflicts[key] = struct{}{}
		}
		dependencies[key] = value
	}
	addDependency(validationDependencyKey{kind: validationCodeDependency, address: sender}, snapshot.senderCodeHash)
	addDependency(validationDependencyKey{kind: validationCodeDependency, address: meta.payer}, meta.payerCodeHash)
	if snapshot.legacyNonce != nil {
		addDependency(validationDependencyKey{kind: validationNonceDependency, address: sender}, uint64DependencyValue(*snapshot.legacyNonce))
	}
	if snapshot.senderBalance != nil {
		addDependency(validationDependencyKey{kind: validationBalanceDependency, address: sender}, *snapshot.senderBalance)
	}
	for location, value := range snapshot.storageValues {
		addDependency(validationDependencyKey{kind: validationStorageDependency, address: location.address, slot: location.slot}, value)
	}
	for address, value := range snapshot.codeHashes {
		addDependency(validationDependencyKey{kind: validationCodeDependency, address: address}, value)
	}
	keys := make([]validationDependencyKey, 0, len(dependencies))
	for key, value := range dependencies {
		entry := index.byKey[key]
		if entry == nil {
			entry = &validationDependencyEntry{value: value, dependents: make(map[common.Hash]struct{})}
			index.byKey[key] = entry
		} else if entry.value != value {
			// This should not occur while validation and reset are serialized.
			// Treat every dependent as affected rather than trusting either value.
			entry.conflicted = true
		}
		if _, conflicted := conflicts[key]; conflicted {
			entry.conflicted = true
		}
		entry.dependents[hash] = struct{}{}
		keys = append(keys, key)
	}
	index.byTx[hash] = keys
	for _, key := range accountingKeys {
		dependents := index.accountingByKey[key]
		if dependents == nil {
			dependents = make(map[common.Hash]struct{})
			index.accountingByKey[key] = dependents
		}
		dependents[hash] = struct{}{}
	}
	index.accountingByTx[hash] = accountingKeys
}

func (index *validationDependencyIndex) remove(hash common.Hash) {
	if index == nil {
		return
	}
	for _, key := range index.byTx[hash] {
		entry := index.byKey[key]
		if entry == nil {
			continue
		}
		delete(entry.dependents, hash)
		if len(entry.dependents) == 0 {
			delete(index.byKey, key)
		}
	}
	delete(index.byTx, hash)
	for _, key := range index.accountingByTx[hash] {
		dependents := index.accountingByKey[key]
		delete(dependents, hash)
		if len(dependents) == 0 {
			delete(index.accountingByKey, key)
		}
	}
	delete(index.accountingByTx, hash)
}

func (index *validationDependencyIndex) changes(statedb *state.StateDB, touches *validationDependencyTouches) *validationDependencyChanges {
	if index == nil {
		return nil
	}
	changes := &validationDependencyChanges{
		affected:                make(map[common.Hash]struct{}),
		indexed:                 make(map[common.Hash]struct{}),
		accountingAffected:      make(map[common.Hash]struct{}),
		accountingIndexed:       make(map[common.Hash]struct{}),
		selectiveAccountingScan: touches != nil,
	}
	// Only advertise a transaction as indexed when both directions agree. Any
	// partial entry is omitted and therefore uses the authoritative snapshot.
	for hash, keys := range index.byTx {
		complete := len(keys) > 0
		for _, key := range keys {
			entry := index.byKey[key]
			if entry == nil {
				complete = false
				break
			}
			if _, ok := entry.dependents[hash]; !ok {
				complete = false
				break
			}
		}
		if complete {
			changes.indexed[hash] = struct{}{}
		}
	}
	for hash, keys := range index.accountingByTx {
		complete := len(keys) > 0
		for _, key := range keys {
			if _, ok := index.accountingByKey[key][hash]; !ok {
				complete = false
				break
			}
		}
		if complete {
			changes.accountingIndexed[hash] = struct{}{}
		}
	}
	checkDependency := func(key validationDependencyKey, entry *validationDependencyEntry) {
		if !entry.conflicted && validationDependencyValue(statedb, key) == entry.value {
			return
		}
		for hash := range entry.dependents {
			changes.affected[hash] = struct{}{}
		}
	}
	if touches == nil {
		for key, entry := range index.byKey {
			checkDependency(key, entry)
		}
	} else {
		for key := range touches.keys {
			if entry := index.byKey[key]; entry != nil {
				checkDependency(key, entry)
			}
			for hash := range index.accountingByKey[key] {
				changes.accountingAffected[hash] = struct{}{}
			}
		}
	}
	return changes
}

func validationDependencyValue(statedb *state.StateDB, key validationDependencyKey) common.Hash {
	switch key.kind {
	case validationCodeDependency:
		return statedb.GetCodeHash(key.address)
	case validationStorageDependency:
		return statedb.GetState(key.address, key.slot)
	case validationNonceDependency:
		return uint64DependencyValue(statedb.GetNonce(key.address))
	case validationBalanceDependency:
		return common.Hash(statedb.GetBalance(key.address).Bytes32())
	default:
		panic("unknown framepool validation dependency")
	}
}

func uint64DependencyValue(value uint64) common.Hash {
	return common.BigToHash(new(big.Int).SetUint64(value))
}

// snapshotValidationDependencies records the mutable state that a successful
// public-mempool validation was permitted to observe. Transaction fields and
// signatures are immutable for a given hash; nonce and recent-root references
// are checked directly on every reset. The remaining reusable dependencies are
// sender storage, validation-reached code, sender code, and payer code. Direct
// default-code evaluation additionally depends on sender existence, represented
// by the sender's legacy nonce and balance together with its code hash.
func (p *FramePool) snapshotValidationDependencies(frameTx *types.FrameTx, plan validationPrefixPlan, meta frameTxMeta, storageReads map[common.Hash]struct{}, codeReads map[common.Address]struct{}, legacyNonceRead, blobBaseFeeRead, senderExistence bool) *validationDependencySnapshot {
	snapshot := &validationDependencySnapshot{
		senderCodeHash: p.currentState.GetCodeHash(frameTx.Sender),
		deployedSender: plan.deployIndex >= 0,
		rules:          p.chainconfig.Rules(p.currentHead.Number, p.currentHead.Difficulty.Sign() == 0, p.currentHead.Time),
		storageValues:  make(map[storageDependency]common.Hash),
		codeHashes:     make(map[common.Address]common.Hash),
	}
	if legacyNonceRead || senderExistence {
		nonce := p.currentState.GetNonce(frameTx.Sender)
		snapshot.legacyNonce = &nonce
	}
	if blobBaseFeeRead {
		if fee := framePoolBlobBaseFee(p.chainconfig, p.currentHead); fee != nil {
			snapshot.blobBaseFee = fee
		}
	}
	if senderExistence {
		balance := common.Hash(p.currentState.GetBalance(frameTx.Sender).Bytes32())
		snapshot.senderBalance = &balance
	}
	for slot := range storageReads {
		location := storageDependency{address: frameTx.Sender, slot: slot}
		snapshot.storageValues[location] = p.currentState.GetState(location.address, location.slot)
	}
	for addr := range codeReads {
		snapshot.codeHashes[addr] = p.currentState.GetCodeHash(addr)
	}
	// Top-level validation targets do not produce CALL-entry hooks. Track any
	// target other than sender/payer explicitly, notably deploy factories and
	// the canonical expiry verifier.
	for _, index := range []int{plan.expiryIndex, plan.deployIndex, plan.senderVerifyIndex, plan.payVerifyIndex} {
		if index < 0 {
			continue
		}
		target := resolveFrameTarget(frameTx.Sender, frameTx.Frames[index])
		if target != frameTx.Sender && target != meta.payer {
			snapshot.codeHashes[target] = p.currentState.GetCodeHash(target)
		}
	}
	// Raw delegation designators can remain unchanged while the delegate's code
	// changes. Include the one-level execution target for every primary account.
	for _, addr := range []common.Address{frameTx.Sender, meta.payer} {
		if target, ok := types.ParseDelegation(p.currentState.GetCode(addr)); ok {
			snapshot.codeHashes[target] = p.currentState.GetCodeHash(target)
		}
	}
	// The recognized canonical paymaster payment path authenticates against the
	// signer stored in slot zero. Withdrawal amount and balance are evaluated by
	// validatePaymasterAccounting on every reset and are not cached here.
	if meta.canonicalPaymaster {
		location := storageDependency{address: meta.payer, slot: common.Hash{}}
		snapshot.storageValues[location] = p.currentState.GetState(location.address, location.slot)
	}
	return snapshot
}

func (p *FramePool) validationDependenciesUnchanged(frameTx *types.FrameTx, meta frameTxMeta) bool {
	snapshot := meta.validationDeps
	if snapshot == nil {
		return false
	}
	if p.currentState.GetCodeHash(frameTx.Sender) != snapshot.senderCodeHash {
		return false
	}
	currentRules := p.chainconfig.Rules(p.currentHead.Number, p.currentHead.Difficulty.Sign() == 0, p.currentHead.Time)
	if currentRules != snapshot.rules {
		return false
	}
	if p.currentState.GetCodeHash(meta.payer) != meta.payerCodeHash {
		return false
	}
	if snapshot.legacyNonce != nil && p.currentState.GetNonce(frameTx.Sender) != *snapshot.legacyNonce {
		return false
	}
	if snapshot.senderBalance != nil && common.Hash(p.currentState.GetBalance(frameTx.Sender).Bytes32()) != *snapshot.senderBalance {
		return false
	}
	if snapshot.blobBaseFee != nil && !sameBigInt(framePoolBlobBaseFee(p.chainconfig, p.currentHead), snapshot.blobBaseFee) {
		return false
	}
	for location, value := range snapshot.storageValues {
		if p.currentState.GetState(location.address, location.slot) != value {
			return false
		}
	}
	for addr, codeHash := range snapshot.codeHashes {
		if p.currentState.GetCodeHash(addr) != codeHash {
			return false
		}
	}
	return true
}

func (p *FramePool) validationDependenciesUnchangedIndexed(hash common.Hash, frameTx *types.FrameTx, meta frameTxMeta, changes *validationDependencyChanges) bool {
	if changes == nil || meta.validationDeps == nil {
		return p.validationDependenciesUnchanged(frameTx, meta)
	}
	if _, indexed := changes.indexed[hash]; !indexed {
		return p.validationDependenciesUnchanged(frameTx, meta)
	}
	if _, affected := changes.affected[hash]; affected {
		return false
	}
	if meta.validationDeps.blobBaseFee != nil && !sameBigInt(framePoolBlobBaseFee(p.chainconfig, p.currentHead), meta.validationDeps.blobBaseFee) {
		return false
	}
	currentRules := p.chainconfig.Rules(p.currentHead.Number, p.currentHead.Difficulty.Sign() == 0, p.currentHead.Time)
	return currentRules == meta.validationDeps.rules
}

func framePoolBlobBaseFee(config *params.ChainConfig, head *types.Header) *big.Int {
	if head == nil || head.ExcessBlobGas == nil {
		return nil
	}
	return eip4844.CalcBlobFee(config, head)
}

func sameBigInt(left, right *big.Int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Cmp(right) == 0
}

// rejectChangedValidationProgram drops a pending transaction before signatures
// or EVM execution when any code identity or fork rule used by its admission
// profile has changed. The old profile and memo are valid only for the exact
// validation program that produced them.
func (p *FramePool) rejectChangedValidationProgram(hash common.Hash, frameTx *types.FrameTx, meta frameTxMeta) bool {
	if !p.payerCodeIdentityPreflight || meta.validationDeps == nil {
		return false
	}
	if meta.usesPaymaster {
		payerCodeIdentityCheckMeter.Mark(1)
	}
	identity := validationProgramIdentityFromMeta(frameTx, meta)
	changed, address := p.validationProgramIdentityChanged(identity)
	if !changed {
		return false
	}
	resetProgramDropMeter.Mark(1)
	if meta.usesPaymaster && address == meta.payer {
		payerCodeIdentityRejectMeter.Mark(1)
	}
	if len(p.stalePayerCode) >= p.limits.maxPoolSize {
		for staleHash := range p.stalePayerCode {
			delete(p.stalePayerCode, staleHash)
			break
		}
	}
	if meta.usesPaymaster && address == meta.payer {
		p.stalePayerCode[hash] = payerCodeIdentity{payer: meta.payer, codeHash: meta.payerCodeHash}
	}
	if len(p.staleValidationPrograms) >= p.limits.maxPoolSize {
		for staleHash := range p.staleValidationPrograms {
			delete(p.staleValidationPrograms, staleHash)
			delete(p.stalePayerCode, staleHash)
			break
		}
	}
	p.staleValidationPrograms[hash] = identity
	return true
}

func validationProgramIdentityFromMeta(frameTx *types.FrameTx, meta frameTxMeta) validationProgramIdentity {
	identity := validationProgramIdentity{
		rules:      meta.validationDeps.rules,
		codeHashes: make(map[common.Address]common.Hash, len(meta.validationDeps.codeHashes)+2),
	}
	if !meta.validationDeps.deployedSender {
		identity.codeHashes[frameTx.Sender] = meta.validationDeps.senderCodeHash
	}
	if !meta.validationDeps.deployedSender || meta.payer != frameTx.Sender {
		identity.codeHashes[meta.payer] = meta.payerCodeHash
	}
	for address, codeHash := range meta.validationDeps.codeHashes {
		if meta.validationDeps.deployedSender && address == frameTx.Sender {
			continue
		}
		identity.codeHashes[address] = codeHash
	}
	return identity
}

func (p *FramePool) validationProgramIdentityChanged(identity validationProgramIdentity) (bool, common.Address) {
	currentRules := p.chainconfig.Rules(p.currentHead.Number, p.currentHead.Difficulty.Sign() == 0, p.currentHead.Time)
	if currentRules != identity.rules {
		return true, common.Address{}
	}
	for address, codeHash := range identity.codeHashes {
		if p.currentState.GetCodeHash(address) != codeHash {
			return true, address
		}
	}
	return false, common.Address{}
}

// preflightPayerSolvency applies the all-payer solvency-only optimization before
// executing the validation prefix. A structurally valid self_verify prefix resolves
// the payer to the sender; a split prefix resolves it from the explicit pay frame.
// The check compares balance against existing pool reservations plus the candidate's
// maximum cost, subtracting a pending withdrawal only for an exact canonical-paymaster
// runtime. Passing never substitutes for complete VERIFY simulation.
func (p *FramePool) preflightPayerSolvency(tx *types.Transaction, replacement *types.Transaction) error {
	if !p.payerSolvencyPreflight {
		return nil
	}
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return nil
	}
	simulationTime := p.currentHead.Time + params.SecondsPerSlot
	plan, err := p.validationPrefixPlan(frameTx, p.currentState, simulationTime)
	if err != nil {
		// Prefix errors remain the responsibility of the normal simulation path.
		// This keeps the optimization limited to necessary payer accounting.
		return nil
	}
	return p.preflightPayerSolvencyWithMeta(tx, replacement, p.validationPayerMeta(frameTx, plan), true)
}

func (p *FramePool) validationPayerMeta(frameTx *types.FrameTx, plan validationPrefixPlan) frameTxMeta {
	payer := frameTx.Sender
	if plan.payVerifyIndex >= 0 {
		payer = resolveFrameTarget(frameTx.Sender, frameTx.Frames[plan.payVerifyIndex])
	}
	return p.classifyPayer(frameTx.Sender, payer)
}

func (p *FramePool) preflightPayerSolvencyWithMeta(tx *types.Transaction, replacement *types.Transaction, meta frameTxMeta, meter bool) error {
	start := time.Now()
	if meter {
		preflightRunMeter.Mark(1)
	}
	meta.maxCost = p.maxCost(tx)
	err := p.validatePayerSolvency(tx, meta, replacement)
	if meter {
		preflightTimeTimer.UpdateSince(start)
	}
	if err != nil {
		if meter {
			preflightRejectMeter.Mark(1)
		}
		return err
	}
	if meter {
		preflightPassMeter.Mark(1)
	}
	return nil
}

// sortResetTransactions makes shared-payer reservation rebuilding independent
// of Go map iteration order. Higher-paying transactions win scarce payer balance;
// transaction hash provides a stable final tie-breaker.
func sortResetTransactions(txs []*types.Transaction, oldMeta map[common.Hash]frameTxMeta) {
	slices.SortFunc(txs, func(a, b *types.Transaction) int {
		aMeta, aOK := oldMeta[a.Hash()]
		bMeta, bOK := oldMeta[b.Hash()]
		if aOK != bOK {
			if aOK {
				return -1
			}
			return 1
		}
		if aOK {
			if cmp := bytes.Compare(aMeta.payer[:], bMeta.payer[:]); cmp != 0 {
				return cmp
			}
		}
		if cmp := b.GasTipCap().Cmp(a.GasTipCap()); cmp != 0 {
			return cmp
		}
		if cmp := b.GasFeeCap().Cmp(a.GasFeeCap()); cmp != 0 {
			return cmp
		}
		aHash, bHash := a.Hash(), b.Hash()
		return bytes.Compare(aHash[:], bHash[:])
	})
}

// hasNoCode returns true if the address uses frame default code. An EIP-7702
// delegation designator is code, even when its delegated target has no code.
func hasNoCode(statedb *state.StateDB, addr common.Address) bool {
	return len(statedb.GetCode(addr)) == 0
}

// verifyFailureClass is a stable classification of post-execution VERIFY outcomes.
type verifyFailureClass string

const (
	verifyFailureNone            verifyFailureClass = ""
	verifyFailureDidNotApprove   verifyFailureClass = "did_not_approve"
	verifyFailureReverted        verifyFailureClass = "evm_revert"
	verifyFailureOutOfGas        verifyFailureClass = "out_of_gas"
	verifyFailureTracerViolation verifyFailureClass = "tracer_violation"
	verifyFailureEVM             verifyFailureClass = "evm_error"
)

// verifyResult records the structured outcome of a simulated VERIFY frame.
type verifyResult struct {
	approveScope      uint8
	frameIndex        int
	target            common.Address
	gasLimit          uint64
	gasRemaining      uint64
	stateGasLimit     uint64
	stateGasRemaining uint64
	prefixGasUsed     uint64
	failureClass      verifyFailureClass
	storageReads      []common.Hash
	codeReads         []common.Address
	legacyNonceRead   bool
	blobBaseFeeRead   bool
	workProfile       vm.ValidationWorkProfile
}

func (r verifyResult) frameGasUsed() uint64 {
	if r.gasRemaining > r.gasLimit {
		return 0
	}
	return r.gasLimit - r.gasRemaining
}

func (r verifyResult) frameStateGasUsed() uint64 {
	if r.stateGasRemaining > r.stateGasLimit {
		return 0
	}
	return r.stateGasLimit - r.stateGasRemaining
}

func (r verifyResult) gasUsed() uint64 {
	if r.prefixGasUsed != 0 {
		return r.prefixGasUsed
	}
	return r.frameGasUsed()
}

// validateFrameOrdering performs pre-simulation static validation of frame ordering.
// It checks structural constraints that don't require EVM execution.
func validateFrameOrdering(frames []types.Frame, sender common.Address) error {
	if len(frames) == 0 {
		return fmt.Errorf("frame transaction has no frames")
	}
	hasVerify := false
	hasSenderVerify := false // VERIFY frame targeting sender has been seen
	for _, frame := range frames {
		if frame.Mode > types.FrameModeSender {
			return fmt.Errorf("frame has invalid mode %d", frame.Mode)
		}
		if frame.Mode == types.FrameModeVerify {
			hasVerify = true
			target := sender
			if frame.Target != nil {
				target = *frame.Target
			}
			if target == sender {
				hasSenderVerify = true
			}
		}
		if frame.Mode == types.FrameModeSender && !hasSenderVerify {
			return fmt.Errorf("SENDER frame before any VERIFY targeting sender")
		}
	}
	if !hasVerify {
		return fmt.Errorf("no VERIFY frame in transaction")
	}
	return nil
}

// validatePayerSolvency checks only the payer's aggregate balance exposure. The
// exact canonical runtime additionally reserves its announced withdrawal amount.
func (p *FramePool) validatePayerSolvency(tx *types.Transaction, meta frameTxMeta, replacement *types.Transaction) error {
	if meta.maxCost == nil {
		meta.maxCost = p.maxCost(tx)
	}
	reserved := p.reservedExcluding(meta.payer, replacement)
	required := new(big.Int).Add(reserved, meta.maxCost)
	balance := p.payerAvailableBalance(meta)
	pendingWithdrawal := p.pendingCanonicalWithdrawalForMeta(meta)
	if balance.Cmp(required) < 0 {
		return fmt.Errorf("%w: payer %s available balance %v, reserved %v, pending withdrawal %v, tx cost %v", core.ErrInsufficientFunds, meta.payer.Hex(), balance, reserved, pendingWithdrawal, meta.maxCost)
	}
	return nil
}

func (p *FramePool) maxCost(tx *types.Transaction) *big.Int {
	cost := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasFeeCap())
	if tx.BlobGas() == 0 {
		return cost
	}
	blobFee := eip4844.CalcBlobFee(p.chain.Config(), p.currentHead)
	return cost.Add(cost, new(big.Int).Mul(new(big.Int).SetUint64(tx.BlobGas()), blobFee))
}

func (p *FramePool) pendingCanonicalWithdrawalForMeta(meta frameTxMeta) *big.Int {
	if !meta.usesPaymaster || !meta.canonicalPaymaster {
		return new(big.Int)
	}
	return p.pendingCanonicalWithdrawal(meta.payer)
}

func (p *FramePool) payerAvailableBalance(meta frameTxMeta) *big.Int {
	balance := p.currentState.GetBalance(meta.payer).ToBig()
	balance.Sub(balance, p.pendingCanonicalWithdrawalForMeta(meta))
	if balance.Sign() < 0 {
		balance.SetInt64(0)
	}
	return balance
}

func (p *FramePool) validateNonCanonicalPaymasterLimit(meta frameTxMeta, replacement *types.Transaction) error {
	if !meta.nonCanonicalPaymaster {
		return nil
	}
	pending := p.nonCanonicalPendingExcluding(meta.payer, replacement)
	if pending >= p.limits.maxPendingPerNonCanonicalPaymaster {
		return fmt.Errorf("%w: non-canonical paymaster %s has %d pending frame txs", txpool.ErrAccountLimitExceeded, meta.payer.Hex(), pending)
	}
	return nil
}

// validatePaymasterAccounting performs full post-simulation accounting. The
// caller repeats both checks immediately before insertion to protect against
// pool changes since the rejection-only admission preflight.
func (p *FramePool) validatePaymasterAccounting(tx *types.Transaction, meta frameTxMeta, replacement *types.Transaction) error {
	if err := p.validatePayerSolvency(tx, meta, replacement); err != nil {
		return err
	}
	return p.validateNonCanonicalPaymasterLimit(meta, replacement)
}

func (p *FramePool) reserveTxAccounting(tx *types.Transaction, meta frameTxMeta) {
	hash := tx.Hash()
	if meta.maxCost == nil {
		meta.maxCost = new(big.Int)
	}
	meta.maxCost = new(big.Int).Set(meta.maxCost)
	if meta.payerAvailableBalance != nil {
		meta.payerAvailableBalance = new(big.Int).Set(meta.payerAvailableBalance)
	}
	p.meta[hash] = meta
	if frameTx := tx.GetFrameTx(); frameTx != nil {
		accountingKeys := []validationDependencyKey{{kind: validationBalanceDependency, address: meta.payer}}
		if meta.canonicalPaymaster {
			if slot, ok := p.canonicalPaymasterWithdrawalSlot(meta.payer); ok {
				accountingKeys = append(accountingKeys, validationDependencyKey{kind: validationStorageDependency, address: meta.payer, slot: slot})
			}
		}
		p.dependencyIndex.add(hash, frameTx.Sender, meta, accountingKeys...)
	}
	if p.paymasterReserved[meta.payer] == nil {
		p.paymasterReserved[meta.payer] = new(big.Int)
	}
	p.paymasterReserved[meta.payer].Add(p.paymasterReserved[meta.payer], meta.maxCost)
	if meta.nonCanonicalPaymaster {
		p.paymasterPending[meta.payer]++
	}
}

func (p *FramePool) releaseTxAccounting(hash common.Hash) {
	p.dependencyIndex.remove(hash)
	meta, ok := p.meta[hash]
	if !ok {
		return
	}
	if reserved := p.paymasterReserved[meta.payer]; reserved != nil {
		reserved.Sub(reserved, meta.maxCost)
		if reserved.Sign() <= 0 {
			delete(p.paymasterReserved, meta.payer)
		}
	}
	if meta.nonCanonicalPaymaster {
		p.paymasterPending[meta.payer]--
		if p.paymasterPending[meta.payer] <= 0 {
			delete(p.paymasterPending, meta.payer)
		}
	}
	delete(p.meta, hash)
}

func (p *FramePool) reservedExcluding(payer common.Address, replacement *types.Transaction) *big.Int {
	reserved := new(big.Int)
	if current := p.paymasterReserved[payer]; current != nil {
		reserved.Set(current)
	}
	if replacement != nil {
		if meta, ok := p.meta[replacement.Hash()]; ok && meta.payer == payer {
			reserved.Sub(reserved, meta.maxCost)
			if reserved.Sign() < 0 {
				reserved.SetInt64(0)
			}
		}
	}
	return reserved
}

func (p *FramePool) nonCanonicalPendingExcluding(payer common.Address, replacement *types.Transaction) int {
	pending := p.paymasterPending[payer]
	if replacement != nil {
		if meta, ok := p.meta[replacement.Hash()]; ok && meta.payer == payer && meta.nonCanonicalPaymaster {
			pending--
		}
	}
	if pending < 0 {
		return 0
	}
	return pending
}

func isFrameTxPriceBumped(tx, old *types.Transaction) bool {
	return tx.GasFeeCapIntCmp(bumpedPrice(old.GasFeeCap(), frameTxPriceBump)) >= 0 &&
		tx.GasTipCapIntCmp(bumpedPrice(old.GasTipCap(), frameTxPriceBump)) >= 0 &&
		tx.BlobGasFeeCapIntCmp(bumpedPrice(old.BlobGasFeeCap(), frameTxPriceBump)) >= 0
}

func bumpedPrice(price *big.Int, bump uint64) *big.Int {
	threshold := new(big.Int).Mul(price, new(big.Int).SetUint64(100+bump))
	threshold.Div(threshold, big.NewInt(100))
	if price.Sign() > 0 && threshold.Cmp(price) == 0 {
		threshold.Add(threshold, big.NewInt(1))
	}
	return threshold
}

// Pending returns all processable frame transactions.
func (p *FramePool) Pending(filter txpool.PendingFilter) (map[common.Address][]*txpool.LazyTransaction, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	pending := make(map[common.Address][]*txpool.LazyTransaction, len(p.pending))
	count := 0
	for addr, txs := range p.pending {
		lazies := make([]*txpool.LazyTransaction, 0, len(txs))
		for _, tx := range txs {
			isBlob := tx.BlobGas() > 0
			if isBlob != filter.BlobTxs {
				continue
			}
			if filter.MinTip != nil && filter.BaseFee != nil && tx.EffectiveGasTipIntCmp(filter.MinTip, filter.BaseFee) < 0 {
				continue
			}
			if isBlob && filter.BlobFee != nil && tx.BlobGasFeeCapIntCmp(filter.BlobFee.ToBig()) < 0 {
				continue
			}
			if filter.GasLimitCap != 0 && tx.Gas() > filter.GasLimitCap {
				continue
			}
			if isBlob {
				sidecar := tx.BlobTxSidecar()
				if sidecar == nil || sidecar.Version != filter.BlobVersion {
					continue
				}
			}
			lazies = append(lazies, &txpool.LazyTransaction{
				Pool:      p,
				Hash:      tx.Hash(),
				Tx:        tx,
				Time:      tx.Time(),
				GasFeeCap: uint256.MustFromBig(tx.GasFeeCap()),
				GasTipCap: uint256.MustFromBig(tx.GasTipCap()),
				Gas:       tx.Gas(),
				BlobGas:   tx.BlobGas(),
			})
		}
		if len(lazies) != 0 {
			pending[addr] = lazies
			count += len(lazies)
		}
	}
	return pending, count
}

// SubscribeTransactions subscribes to new transaction events, optionally
// including transactions resurrected by a reorg.
func (p *FramePool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	if reorgs {
		return p.insertFeed.Subscribe(ch)
	}
	return p.discoverFeed.Subscribe(ch)
}

// Nonce returns the next nonce for the given address.
func (p *FramePool) Nonce(addr common.Address) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()

	nonce := p.currentState.GetNonce(addr)
	if txs := p.pending[addr]; len(txs) > 0 {
		for _, tx := range txs {
			frameTx := tx.GetFrameTx()
			if frameTx != nil && frameTx.UsesLegacyNonce() && frameTx.NonceSeq+1 > nonce {
				nonce = frameTx.NonceSeq + 1
			}
		}
	}
	return nonce
}

// Stats returns the number of pending and queued transactions.
func (p *FramePool) Stats() (int, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	count := 0
	for _, txs := range p.pending {
		count += len(txs)
	}
	return count, 0
}

// Content returns all pending and queued transactions.
func (p *FramePool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	pending := make(map[common.Address][]*types.Transaction, len(p.pending))
	for addr, txs := range p.pending {
		cpy := make([]*types.Transaction, len(txs))
		copy(cpy, txs)
		pending[addr] = cpy
	}
	return pending, make(map[common.Address][]*types.Transaction)
}

// ContentFrom returns pending and queued transactions from a specific address.
func (p *FramePool) ContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var pending []*types.Transaction
	if txs := p.pending[addr]; len(txs) > 0 {
		pending = make([]*types.Transaction, len(txs))
		copy(pending, txs)
	}
	return pending, nil
}

// Status returns the status of a transaction.
func (p *FramePool) Status(hash common.Hash) txpool.TxStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.all[hash] != nil {
		return txpool.TxStatusPending
	}
	return txpool.TxStatusUnknown
}

// Clear removes all transactions from the pool.
func (p *FramePool) Clear() {
	p.validationMu.Lock()
	defer p.validationMu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	for addr := range p.pending {
		if p.reserver != nil {
			p.reserver.Release(addr)
		}
	}
	p.pending = make(map[common.Address][]*types.Transaction)
	p.all = make(map[common.Hash]*types.Transaction)
	p.nonceKeyOwner = make(nonceKeyOwnerIndex)
	p.meta = make(map[common.Hash]frameTxMeta)
	p.paymasterReserved = make(map[common.Address]*big.Int)
	p.paymasterPending = make(map[common.Address]int)
}
