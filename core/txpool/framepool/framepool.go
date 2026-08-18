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
	// maxFrameTxsPerAccount is the EIP-8141 public-mempool sender limit.
	maxFrameTxsPerAccount = 1

	// maxPendingTxsUsingNonCanonicalPaymaster limits pooled transactions per
	// non-canonical paymaster.
	maxPendingTxsUsingNonCanonicalPaymaster = 1

	// maxFramePoolSize limits total pooled frame transactions.
	maxFramePoolSize = 256

	// PublicMaxVerifyGas is the fixed EIP-8141 public-mempool validation budget.
	PublicMaxVerifyGas uint64 = 100_000
	maxVerifyGas              = PublicMaxVerifyGas

	// frameTxPriceBump is the same-nonce replacement bump percentage.
	frameTxPriceBump = 10

	// txMaxSize is the maximum frame transaction size.
	txMaxSize uint64 = 512 * 1024

	// maxResetValidationWorkers bounds the StateDB copies and EVMs used to
	// prepare reset validation. Pool accounting is committed separately.
	maxResetValidationWorkers = 4
)

// Config configures frame transaction validation policy. Values above
// PublicMaxVerifyGas are only permitted on isolated nodes with no peers.
type Config struct {
	MaxVerifyGas               uint64
	PayerSolvencyPreflight     bool
	PayerCodeIdentityPreflight bool
	SelectiveRevalidation      bool
}

// DefaultConfig follows the EIP-8141 public-mempool constants. Payer solvency
// is checked before protocol signatures and validation-prefix execution.
var DefaultConfig = Config{
	MaxVerifyGas:               maxVerifyGas,
	PayerSolvencyPreflight:     true,
	PayerCodeIdentityPreflight: false,
	SelectiveRevalidation:      true,
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

// FramePool is a transaction pool for EIP-8141 frame transactions.
// It validates VERIFY frames by simulating the EIP-8141 public-mempool
// validation prefix before accepting transactions into the pool.
type FramePool struct {
	chain       BlockChain
	chainconfig *params.ChainConfig
	signer      types.Signer

	gasTip                     uint256.Int
	currentHead                *types.Header
	currentState               *state.StateDB
	slotProvider               func(*types.Header) vm.SlotProvider
	verifyGasCap               uint64
	payerSolvencyPreflight     bool
	payerCodeIdentityPreflight bool
	selectiveRevalidation      bool
	resetValidationWorkers     int
	canonicalPaymasters        map[common.Hash]common.Hash

	reserver txpool.Reserver

	validationMu    sync.Mutex
	mu              sync.RWMutex
	pending         map[common.Address][]*types.Transaction // sender → txs (up to maxFrameTxsPerAccount)
	all             map[common.Hash]*types.Transaction      // hash → tx
	meta            map[common.Hash]frameTxMeta             // hash → validation/accounting metadata
	dependencyIndex *validationDependencyIndex              // mutable validation dependency → transaction hashes
	stalePayerCode  map[common.Hash]payerCodeIdentity       // hash → admission-time payer code identity
	blobSidecars    map[common.Hash]cachedBlobSidecar       // recently mined tx hash → full sidecar
	blobCells       map[common.Hash][]kzg4844.Cell          // validated cells for pooled and recently mined txs

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
}

type storageDependency struct {
	address common.Address
	slot    common.Hash
}

type validationDependencySnapshot struct {
	senderCodeHash common.Hash
	rules          params.Rules
	legacyNonce    *uint64
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
	tx    *types.Transaction
	class resetValidationClass
	meta  frameTxMeta
	err   error
}

// New creates a new frame transaction pool.
func New(chain BlockChain) *FramePool {
	return NewWithConfig(DefaultConfig, chain)
}

// NewWithConfig creates a frame transaction pool with explicit policy settings.
func NewWithConfig(config Config, chain BlockChain) *FramePool {
	if config.MaxVerifyGas == 0 {
		config.MaxVerifyGas = maxVerifyGas
	}
	return &FramePool{
		chain:                      chain,
		chainconfig:                chain.Config(),
		signer:                     types.LatestSigner(chain.Config()),
		verifyGasCap:               config.MaxVerifyGas,
		payerSolvencyPreflight:     config.PayerSolvencyPreflight,
		payerCodeIdentityPreflight: config.PayerCodeIdentityPreflight,
		selectiveRevalidation:      config.SelectiveRevalidation,
		resetValidationWorkers:     defaultResetValidationWorkers(),
		canonicalPaymasters:        make(map[common.Hash]common.Hash),
		pending:                    make(map[common.Address][]*types.Transaction),
		all:                        make(map[common.Hash]*types.Transaction),
		meta:                       make(map[common.Hash]frameTxMeta),
		dependencyIndex:            newValidationDependencyIndex(),
		stalePayerCode:             make(map[common.Hash]payerCodeIdentity),
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
	return nil
}

// Close is a no-op (no background goroutines).
func (p *FramePool) Close() error { return nil }

// Reset updates the pool state when the chain head changes.
func (p *FramePool) Reset(oldHead, newHead *types.Header) {
	p.validationMu.Lock()
	defer p.validationMu.Unlock()
	resetRunMeter.Mark(1)
	resetStart := time.Now()
	defer func() {
		elapsed := time.Since(resetStart)
		resetTimeTimer.Update(elapsed)
		resetLastTimeGauge.Update(elapsed.Nanoseconds())
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
	blobCells := make(map[common.Hash][]kzg4844.Cell, len(p.blobCells))
	for hash, cells := range p.blobCells {
		blobCells[hash] = cells
	}
	reserver := &resetReserver{base: p.reserver, existing: existingSenders, acquired: make(map[common.Address]struct{})}
	candidate := &FramePool{
		chain:                      p.chain,
		chainconfig:                p.chainconfig,
		signer:                     p.signer,
		gasTip:                     p.gasTip,
		currentHead:                newHead,
		currentState:               statedb,
		slotProvider:               p.slotProvider,
		verifyGasCap:               p.verifyGasCap,
		payerSolvencyPreflight:     p.payerSolvencyPreflight,
		payerCodeIdentityPreflight: p.payerCodeIdentityPreflight,
		selectiveRevalidation:      p.selectiveRevalidation,
		resetValidationWorkers:     p.resetValidationWorkers,
		canonicalPaymasters:        p.canonicalPaymasters,
		reserver:                   reserver,
		pending:                    make(map[common.Address][]*types.Transaction),
		all:                        make(map[common.Hash]*types.Transaction),
		meta:                       make(map[common.Hash]frameTxMeta),
		dependencyIndex:            newValidationDependencyIndex(),
		stalePayerCode:             stalePayerCode,
		blobCells:                  blobCells,
		paymasterReserved:          make(map[common.Address]*big.Int),
		paymasterPending:           make(map[common.Address]int),
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
	for hash := range candidate.blobCells {
		if candidate.all[hash] == nil {
			if _, cached := p.blobSidecars[hash]; !cached {
				delete(candidate.blobCells, hash)
			}
		}
	}
	p.pending = candidate.pending
	p.all = candidate.all
	p.meta = candidate.meta
	p.dependencyIndex = candidate.dependencyIndex
	p.stalePayerCode = candidate.stalePayerCode
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
		if metaOK && p.rejectChangedPayerCode(tx.Hash(), meta) {
			continue
		}
		if p.selectiveRevalidation {
			simulationTime := p.currentHead.Time + params.SecondsPerSlot
			if _, err := p.validationPrefixPlan(frameTx, p.currentState, simulationTime); err != nil {
				continue
			}
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
		sender := tx.GetFrameTx().Sender
		if validation.err != nil || len(p.pending[sender]) >= maxFrameTxsPerAccount {
			continue
		}
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
		p.reserveTxAccounting(tx, validation.meta)
		if validation.class != resetFullValidation {
			reused++
		}
		retained++
	}
}

func defaultResetValidationWorkers() int {
	return min(max(runtime.GOMAXPROCS(0), 1), maxResetValidationWorkers)
}

// prepareResetValidations runs only the state-dependent EVM work in parallel.
// Each worker owns a StateDB snapshot; results are written to their original
// positions and committed later in deterministic reset priority order.
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
	views[0] = p
	for i := 1; i < len(views); i++ {
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
				if cached.signatureValidated {
					validation.meta, validation.err = view.simulateVerifyFramesWithSignatureGas(validation.tx, cached.signatureGas)
					if validation.err == nil {
						validation.meta.signatureValidated = true
						validation.meta.signatureGas = cached.signatureGas
					}
				} else {
					validation.meta, validation.err = view.simulateVerifyFrames(validation.tx)
				}
			}
		}(view)
	}
	for _, index := range full {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
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
		cells, err := validateFrameBlobProofs(tx)
		if err != nil {
			errs[i] = err
			continue
		}
		if err := p.validateAndAdd(tx, cells); err != nil {
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
	want := new(big.Int).SetUint64(tx.NonceSeq)
	for _, key := range tx.NonceKeys {
		var have *big.Int
		if key.IsZero() {
			have = new(big.Int).SetUint64(statedb.GetNonce(tx.Sender))
		} else {
			have = statedb.GetState(params.NonceManagerAddress, types.NonceManagerSlot(tx.Sender, key)).Big()
		}
		switch have.Cmp(want) {
		case -1:
			return fmt.Errorf("%w: sender %s nonce key %x tx sequence %d state sequence %s", core.ErrNonceTooHigh, tx.Sender.Hex(), key.Bytes32(), tx.NonceSeq, have)
		case 1:
			return fmt.Errorf("%w: sender %s nonce key %x tx sequence %d state sequence %s", core.ErrNonceTooLow, tx.Sender.Hex(), key.Bytes32(), tx.NonceSeq, have)
		}
	}
	return nil
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
	if p.all[tx.Hash()] != nil {
		return check, txpool.ErrAlreadyKnown
	}
	if staleCode, stale := p.stalePayerCode[tx.Hash()]; p.payerCodeIdentityPreflight && stale && p.currentState.GetCodeHash(staleCode.payer) != staleCode.codeHash {
		if meterPreflight {
			payerCodeIdentityReplayRejectMeter.Mark(1)
		}
		return check, fmt.Errorf("%w: payer %s code hash changed since transaction admission", core.ErrFrameTxInvalid, staleCode.payer)
	}
	if err := validateFrameNonce(frameTx, p.currentState); err != nil {
		return check, err
	}
	if err := p.validateRecentRootReferences(frameTx, p.currentState, p.currentHead); err != nil {
		return check, err
	}
	sender := frameTx.Sender
	if txs := p.pending[sender]; len(txs) > 0 {
		for index, pendingTx := range txs {
			oldFrameTx := pendingTx.GetFrameTx()
			if frameTx.NonceSeq == oldFrameTx.NonceSeq && frameTx.NonceKeySetEqual(oldFrameTx) {
				check.replacement = pendingTx
				check.replacementIndex = index
				break
			}
		}
		if check.replacement != nil {
			if !isFrameTxPriceBumped(tx, check.replacement) {
				return check, txpool.ErrReplaceUnderpriced
			}
		} else if len(txs) >= maxFrameTxsPerAccount {
			return check, fmt.Errorf("%w: sender %s has %d pending frame transactions", txpool.ErrAccountLimitExceeded, sender.Hex(), len(txs))
		}
	}
	if check.replacement == nil && len(p.all) >= maxFramePoolSize {
		check.eviction = p.lowestPricedTransaction()
		if check.eviction == nil || !isFrameTxPriceBumped(tx, check.eviction) {
			return check, fmt.Errorf("%w: frame pool full", txpool.ErrUnderpriced)
		}
	}
	if err := validateFrameOrdering(frameTx.Frames, sender); err != nil {
		return check, err
	}
	simulationTime := p.currentHead.Time + params.SecondsPerSlot
	plan, err := p.validationPrefixPlan(frameTx, p.currentState, simulationTime)
	if err != nil {
		return check, err
	}
	if p.payerSolvencyPreflight {
		if err := p.preflightPayerSolvencyWithPlan(tx, check.replacement, plan, meterPreflight); err != nil {
			return check, err
		}
	}
	return check, nil
}

// validateAndAdd performs stateful validation (nonce, VERIFY simulation) and inserts.
func (p *FramePool) validateAndAdd(tx *types.Transaction, cells []kzg4844.Cell) error {
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
	_, err := p.checkAdmissionCheap(tx, true)
	p.mu.Unlock()
	if err != nil {
		if errors.Is(err, core.ErrInsufficientFunds) {
			accountingRejectMeter.Mark(1)
			accountingInsufficientMeter.Mark(1)
		}
		return err
	}
	signatureGas, err := p.validateFrameSignatures(frameTx)
	if err != nil {
		return err
	}

	p.mu.Lock()

	check, err := p.checkAdmissionCheap(tx, false)
	if err != nil {
		if errors.Is(err, core.ErrInsufficientFunds) {
			accountingRejectMeter.Mark(1)
			accountingInsufficientMeter.Mark(1)
		}
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
	validationView := p.validationViewLocked()
	p.mu.Unlock()

	// Simulate the validation prefix.
	meta, err := validationView.simulateVerifyFramesWithSignatureGas(tx, signatureGas)
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
	if len(cells) > 0 {
		p.blobCells[tx.Hash()] = cells
	}
	p.reserveTxAccounting(tx, meta)
	delete(p.stalePayerCode, tx.Hash())
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
	canonicalPaymasters := make(map[common.Hash]common.Hash, len(p.canonicalPaymasters))
	for codeHash, slot := range p.canonicalPaymasters {
		canonicalPaymasters[codeHash] = slot
	}
	return &FramePool{
		chain:                      p.chain,
		chainconfig:                p.chainconfig,
		signer:                     p.signer,
		currentHead:                types.CopyHeader(p.currentHead),
		currentState:               p.currentState.Copy(),
		slotProvider:               p.slotProvider,
		verifyGasCap:               p.verifyGasCap,
		payerSolvencyPreflight:     p.payerSolvencyPreflight,
		payerCodeIdentityPreflight: p.payerCodeIdentityPreflight,
		selectiveRevalidation:      p.selectiveRevalidation,
		resetValidationWorkers:     p.resetValidationWorkers,
		canonicalPaymasters:        canonicalPaymasters,
	}
}

// simulateVerifyFrames validates the EIP-8141 validation prefix and returns the
// payer metadata needed by framepool accounting. Expiry verifier frames are
// checked directly, skipped for prefix shape, and included in the gas budget.
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

func (p *FramePool) simulateVerifyFramesWithSignatureGas(tx *types.Transaction, signatureGas uint64) (frameTxMeta, error) {
	start := time.Now()
	meta, outcome, err := p.simulateVerifyFramesWithSignatureGasOutcome(tx, signatureGas)
	verifyRunMeter.Mark(1)
	verifyTimeTimer.UpdateSince(start)
	verifyGasMeter.Mark(int64(outcome.gasUsed()))
	verifyGasHistogram.Update(int64(outcome.gasUsed()))
	markVerifyOutcome(outcome.failureClass, err != nil)
	return meta, err
}

// simulateVerifyFramesWithSignatureGasOutcome runs the production validation
// path while retaining the final VERIFY execution outcome for benchmarks and
// corpus qualification. Admission callers intentionally discard the outcome.
func (p *FramePool) simulateVerifyFramesWithSignatureGasOutcome(tx *types.Transaction, signatureGas uint64) (frameTxMeta, verifyResult, error) {
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

	plan, err := p.validationPrefixPlan(frameTx, p.currentState, blockCtx.Time)
	if err != nil {
		return frameTxMeta{}, verifyResult{}, err
	}
	if err := validatePrefixGasBudget(frameTx, plan, signatureGas, false, p.verifyGasCap); err != nil {
		return frameTxMeta{}, verifyResult{}, err
	}
	baseState := p.currentState.Copy()
	storageReads := make(map[common.Hash]struct{})
	codeReads := make(map[common.Address]struct{})
	legacyNonceRead := false
	mergeDependencies := func(result verifyResult) {
		for _, slot := range result.storageReads {
			storageReads[slot] = struct{}{}
		}
		for _, addr := range result.codeReads {
			codeReads[addr] = struct{}{}
		}
		legacyNonceRead = legacyNonceRead || result.legacyNonceRead
	}

	if plan.deployIndex >= 0 {
		if len(baseState.GetCode(frameTx.Sender)) != 0 {
			return frameTxMeta{}, verifyResult{}, fmt.Errorf("deploy frame requires code-less sender in transaction pre-state")
		}
		i := plan.deployIndex
		frame := frameTx.Frames[i]
		target := frameTx.Sender
		if frame.Target != nil {
			target = *frame.Target
		}
		tracer := vm.NewFrameValidationTracerWithOptions(baseState, frameTx.Sender, target, precompiles, vm.FrameValidationTracerOptions{
			AllowCreate:              true,
			AllowSenderStorageWrites: true,
		})
		evm := vm.NewEVM(blockCtx, baseState, p.chainconfig, vm.Config{Tracer: tracer.Hooks()})
		evm.SetTxContext(vm.TxContext{
			Origin:   params.FrameEntryPointAddress,
			GasPrice: new(uint256.Int),
		})
		evm.TxContext.FrameCtx = frameCtx
		frameCtx.FrameIndex = i
		baseState.Prepare(rules, frameTx.Sender, common.Address{}, &target, precompiles, nil)
		warmRecentRootReferences(baseState, frameTx.RecentRootRefs)
		_, _, vmerr := evm.Call(params.FrameEntryPointAddress, target, frame.Data, vm.NewFrameGasBudget(frame.GasLimit, frame.StateGasLimit), new(uint256.Int))
		evm.TxContext.FrameCtx = nil
		for _, slot := range tracer.StorageReads() {
			storageReads[slot] = struct{}{}
		}
		for _, addr := range tracer.CodeReads() {
			codeReads[addr] = struct{}{}
		}
		legacyNonceRead = legacyNonceRead || tracer.ReadsLegacyNonce()
		if violation := tracer.Violation(); violation != nil {
			return frameTxMeta{}, verifyResult{}, fmt.Errorf("deploy frame %d: %w", i, violation)
		}
		if vmerr != nil {
			return frameTxMeta{}, verifyResult{}, fmt.Errorf("deploy frame %d simulation failed: %v", i, vmerr)
		}
		if hasNoCode(baseState, frameTx.Sender) {
			return frameTxMeta{}, verifyResult{}, fmt.Errorf("deploy frame %d did not install sender code", i)
		}
	}

	senderResult, err := p.simulateVerifyFrame(frameTx, frameCtx, blockCtx, rules, precompiles, baseState, plan.senderVerifyIndex, true)
	mergeDependencies(senderResult)
	senderVerifyRunMeter.Mark(1)
	senderVerifyGasMeter.Mark(int64(senderResult.frameGasUsed()))
	if err != nil {
		return frameTxMeta{}, senderResult, err
	}
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
		meta.validationDeps = p.snapshotValidationDependencies(frameTx, plan, meta, storageReads, codeReads, legacyNonceRead)
		return meta, senderResult, nil
	}
	if senderResult.approveScope != vm.ApproveExecution {
		return frameTxMeta{}, senderResult, fmt.Errorf("VERIFY frame %d approved scope %d, want self approval 3 or execution approval 2", plan.senderVerifyIndex, senderResult.approveScope)
	}
	if plan.payVerifyIndex < 0 {
		return frameTxMeta{}, senderResult, fmt.Errorf("execution-only validation prefix missing payment VERIFY frame")
	}
	if err := validatePrefixGasBudget(frameTx, plan, signatureGas, true, p.verifyGasCap); err != nil {
		return frameTxMeta{}, senderResult, err
	}
	payTarget := resolveFrameTarget(frameTx.Sender, frameTx.Frames[plan.payVerifyIndex])
	meta := p.classifyPayer(frameTx.Sender, payTarget)
	payResult, err := p.simulateVerifyFrame(frameTx, frameCtx, blockCtx, rules, precompiles, baseState, plan.payVerifyIndex, !meta.canonicalPaymaster)
	mergeDependencies(payResult)
	payResult.prefixGasUsed = senderResult.gasUsed() + payResult.frameGasUsed()
	if err != nil {
		return frameTxMeta{}, payResult, err
	}
	if payResult.approveScope != vm.ApprovePayment {
		return frameTxMeta{}, payResult, fmt.Errorf("VERIFY frame %d approved scope %d, want payment approval 1", plan.payVerifyIndex, payResult.approveScope)
	}
	if err := p.validateNonceSurcharge(frameTx, payResult.gasRemaining); err != nil {
		return frameTxMeta{}, payResult, err
	}
	meta.maxCost = p.maxCost(tx)
	meta.payerAvailableBalance = p.payerAvailableBalance(meta)
	meta.payerCodeHash = p.currentState.GetCodeHash(meta.payer)
	meta.validationDeps = p.snapshotValidationDependencies(frameTx, plan, meta, storageReads, codeReads, legacyNonceRead)
	return meta, payResult, nil
}

type validationPrefixPlan struct {
	expiryIndex       int
	deployIndex       int
	senderVerifyIndex int
	payVerifyIndex    int
}

func (p *FramePool) validationPrefixPlan(frameTx *types.FrameTx, statedb *state.StateDB, timestamp uint64) (validationPrefixPlan, error) {
	plan := validationPrefixPlan{
		expiryIndex:       -1,
		deployIndex:       -1,
		senderVerifyIndex: -1,
		payVerifyIndex:    -1,
	}
	start := 0
	if frame := frameTx.Frames[0]; types.IsFrameExpiryVerifier(frame, resolveFrameTarget(frameTx.Sender, frame)) {
		if err := validateExpiryVerifierFrame(statedb, 0, frame, resolveFrameTarget(frameTx.Sender, frame), timestamp); err != nil {
			return plan, err
		}
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

func (p *FramePool) simulateVerifyFrame(frameTx *types.FrameTx, frameCtx *vm.FrameContext, blockCtx vm.BlockContext, rules params.Rules, precompiles []common.Address, baseState *state.StateDB, index int, useTracer bool) (verifyResult, error) {
	frame := frameTx.Frames[index]
	target := resolveFrameTarget(frameTx.Sender, frame)

	simState := baseState.Copy()
	var tracer *vm.FrameValidationTracer
	evmConfig := vm.Config{}
	if useTracer {
		tracer = vm.NewFrameValidationTracer(simState, frameTx.Sender, target, precompiles)
		evmConfig.Tracer = tracer.Hooks()
	}
	evm := vm.NewEVM(blockCtx, simState, p.chainconfig, evmConfig)
	evm.SetTxContext(vm.TxContext{
		Origin:   params.FrameEntryPointAddress,
		GasPrice: new(uint256.Int),
	})
	evm.TxContext.FrameCtx = frameCtx
	frameCtx.FrameIndex = index

	simState.Prepare(rules, frameTx.Sender, common.Address{}, &target, precompiles, nil)
	warmRecentRootReferences(simState, frameTx.RecentRootRefs)

	caller := params.FrameEntryPointAddress
	var (
		gasRemaining uint64
		vmerr        error
	)
	if hasNoCode(simState, target) {
		var result vm.GasBudget
		_, result, vmerr = vm.ExecuteDefaultCodeWithGasBudget(evm, caller, target, frame.Data, vm.NewFrameGasBudget(frame.GasLimit, frame.StateGasLimit), frame.Mode)
		gasRemaining = result.ExecutionGas
	} else {
		var result vm.GasBudget
		_, result, vmerr = evm.StaticCall(caller, target, frame.Data, vm.NewFrameGasBudget(frame.GasLimit, frame.StateGasLimit))
		gasRemaining = result.ExecutionGas
	}
	evm.TxContext.FrameCtx = nil
	result := verifyResult{
		frameIndex:   index,
		target:       target,
		gasLimit:     frame.GasLimit,
		gasRemaining: gasRemaining,
	}
	if tracer != nil {
		result.storageReads = tracer.StorageReads()
		result.codeReads = tracer.CodeReads()
		result.legacyNonceRead = tracer.ReadsLegacyNonce()
		if violation := tracer.Violation(); violation != nil {
			if violation.Rule == "OP-020" {
				result.failureClass = verifyFailureOutOfGas
			} else {
				result.failureClass = verifyFailureTracerViolation
			}
			return result, fmt.Errorf("VERIFY frame %d: %w", index, violation)
		}
	}
	scope := evm.TxContext.ApproveScope
	if scope == vm.ApproveNone {
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
		result.failureClass = verifyFailureDidNotApprove
		return result, fmt.Errorf("VERIFY frame %d did not APPROVE", index)
	}
	result.approveScope = scope
	return result, nil
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
// sender storage, validation-reached code, sender code, and payer code.
func (p *FramePool) snapshotValidationDependencies(frameTx *types.FrameTx, plan validationPrefixPlan, meta frameTxMeta, storageReads map[common.Hash]struct{}, codeReads map[common.Address]struct{}, legacyNonceRead bool) *validationDependencySnapshot {
	snapshot := &validationDependencySnapshot{
		senderCodeHash: p.currentState.GetCodeHash(frameTx.Sender),
		rules:          p.chainconfig.Rules(p.currentHead.Number, p.currentHead.Difficulty.Sign() == 0, p.currentHead.Time),
		storageValues:  make(map[storageDependency]common.Hash),
		codeHashes:     make(map[common.Address]common.Hash),
	}
	if legacyNonceRead {
		nonce := p.currentState.GetNonce(frameTx.Sender)
		snapshot.legacyNonce = &nonce
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
	currentRules := p.chainconfig.Rules(p.currentHead.Number, p.currentHead.Difficulty.Sign() == 0, p.currentHead.Time)
	return currentRules == meta.validationDeps.rules
}

// rejectChangedPayerCode performs the admission-time payer code-identity gate
// during head reset. A mismatch is known before signatures or validation-prefix
// EVM execution, so the transaction is evicted directly and remembered for
// cheap rejection if the exact same hash is replayed while the mismatch remains.
func (p *FramePool) rejectChangedPayerCode(hash common.Hash, meta frameTxMeta) bool {
	if !p.payerCodeIdentityPreflight {
		return false
	}
	payerCodeIdentityCheckMeter.Mark(1)
	if p.currentState.GetCodeHash(meta.payer) == meta.payerCodeHash {
		return false
	}
	payerCodeIdentityRejectMeter.Mark(1)
	if len(p.stalePayerCode) >= maxFramePoolSize {
		for staleHash := range p.stalePayerCode {
			delete(p.stalePayerCode, staleHash)
			break
		}
	}
	p.stalePayerCode[hash] = payerCodeIdentity{payer: meta.payer, codeHash: meta.payerCodeHash}
	return true
}

// preflightPayerSolvency applies the all-payer solvency-only optimization before
// executing the validation prefix. A structurally valid self_verify prefix resolves
// the payer to the sender; a split prefix resolves it from the explicit pay frame.
// The check compares balance against existing pool reservations plus the candidate's
// maximum cost, subtracting a pending withdrawal only for an exact canonical-paymaster
// runtime. It intentionally does not enforce the non-canonical pending cap; that check
// remains post-simulation. Passing never substitutes for complete VERIFY simulation.
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
	return p.preflightPayerSolvencyWithPlan(tx, replacement, plan, true)
}

func (p *FramePool) preflightPayerSolvencyWithPlan(tx *types.Transaction, replacement *types.Transaction, plan validationPrefixPlan, meter bool) error {
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return nil
	}
	start := time.Now()
	payer := frameTx.Sender
	if plan.payVerifyIndex >= 0 {
		payer = resolveFrameTarget(frameTx.Sender, frameTx.Frames[plan.payVerifyIndex])
	}
	if meter {
		preflightRunMeter.Mark(1)
	}
	usesPaymaster := payer != frameTx.Sender
	meta := frameTxMeta{
		payer:              payer,
		usesPaymaster:      usesPaymaster,
		canonicalPaymaster: usesPaymaster && p.isCanonicalPaymaster(payer),
		maxCost:            p.maxCost(tx),
	}
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

// hasNoCode returns true if the given address has no code (is an EOA).
// It follows EIP-7702 delegation designators to check the delegated code.
func hasNoCode(statedb *state.StateDB, addr common.Address) bool {
	code := statedb.GetCode(addr)
	if len(code) == 0 {
		return true
	}
	if target, ok := types.ParseDelegation(code); ok {
		return len(statedb.GetCode(target)) == 0
	}
	return false
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
	approveScope    uint8
	frameIndex      int
	target          common.Address
	gasLimit        uint64
	gasRemaining    uint64
	prefixGasUsed   uint64
	failureClass    verifyFailureClass
	storageReads    []common.Hash
	codeReads       []common.Address
	legacyNonceRead bool
}

func (r verifyResult) frameGasUsed() uint64 {
	if r.gasRemaining > r.gasLimit {
		return 0
	}
	return r.gasLimit - r.gasRemaining
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

// validatePaymasterAccounting performs full post-simulation accounting: common
// payer solvency first, followed by the code-bearing non-canonical pending cap.
func (p *FramePool) validatePaymasterAccounting(tx *types.Transaction, meta frameTxMeta, replacement *types.Transaction) error {
	if err := p.validatePayerSolvency(tx, meta, replacement); err != nil {
		return err
	}
	if meta.nonCanonicalPaymaster {
		pending := p.nonCanonicalPendingExcluding(meta.payer, replacement)
		if pending >= maxPendingTxsUsingNonCanonicalPaymaster {
			return fmt.Errorf("%w: non-canonical paymaster %s has %d pending frame txs", txpool.ErrAccountLimitExceeded, meta.payer.Hex(), pending)
		}
	}
	return nil
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
	p.meta = make(map[common.Hash]frameTxMeta)
	p.paymasterReserved = make(map[common.Address]*big.Int)
	p.paymasterPending = make(map[common.Address]int)
}
