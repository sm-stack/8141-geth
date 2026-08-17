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
	"github.com/ethereum/go-ethereum/core/vm"
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
	canonicalPaymasters        map[common.Hash]common.Hash

	reserver txpool.Reserver

	validationMu   sync.Mutex
	mu             sync.RWMutex
	pending        map[common.Address][]*types.Transaction // sender → txs (up to maxFrameTxsPerAccount)
	all            map[common.Hash]*types.Transaction      // hash → tx
	meta           map[common.Hash]frameTxMeta             // hash → validation/accounting metadata
	stalePayerCode map[common.Hash]payerCodeIdentity       // hash → admission-time payer code identity

	paymasterReserved map[common.Address]*big.Int // payer → reserved pending max cost
	paymasterPending  map[common.Address]int      // non-canonical payer → pending count

	txFeed event.Feed
}

type frameTxMeta struct {
	payer                 common.Address
	usesPaymaster         bool
	canonicalPaymaster    bool
	nonCanonicalPaymaster bool
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
	storageValues  map[storageDependency]common.Hash
	codeHashes     map[common.Address]common.Hash
}

type payerCodeIdentity struct {
	payer    common.Address
	codeHash common.Hash
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
		canonicalPaymasters:        make(map[common.Hash]common.Hash),
		pending:                    make(map[common.Address][]*types.Transaction),
		all:                        make(map[common.Hash]*types.Transaction),
		meta:                       make(map[common.Hash]frameTxMeta),
		stalePayerCode:             make(map[common.Hash]payerCodeIdentity),
		slotProvider: func(head *types.Header) vm.SlotProvider {
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

	reinject := p.reorgTransactions(oldHead, newHead)
	statedb, err := p.chain.StateAt(newHead)
	if err != nil {
		log.Error("Failed to reset frame pool state", "err", err)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.currentHead = newHead
	p.currentState = statedb

	var txs []*types.Transaction
	seen := make(map[common.Hash]struct{})
	for _, senderTxs := range p.pending {
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
	resetCandidateMeter.Mark(int64(len(txs)))
	oldMeta := p.meta
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

	for _, tx := range txs {
		frameTx := tx.GetFrameTx()
		if frameTx == nil {
			continue
		}
		if err := p.ValidateTxBasics(tx); err != nil {
			continue
		}
		sender := frameTx.Sender
		if err := validateFrameNonce(frameTx, statedb); err != nil {
			continue
		}
		if err := p.validateRecentRootReferences(frameTx, statedb, newHead); err != nil {
			continue
		}
		if len(p.pending[sender]) >= maxFrameTxsPerAccount {
			continue
		}
		meta, metaOK := oldMeta[tx.Hash()]
		if metaOK && p.rejectChangedPayerCode(tx.Hash(), meta) {
			continue
		}
		if p.selectiveRevalidation {
			simulationTime := newHead.Time + params.SecondsPerSlot
			if _, err := p.validationPrefixPlan(frameTx, p.currentState, simulationTime); err != nil {
				continue
			}
			if metaOK && p.validationDependenciesUnchanged(frameTx, meta) {
				available := p.payerAvailableBalance(meta)
				// An increase cannot invalidate prior solvency, so only rebuild
				// reservations. A decrease needs the aggregate solvency check.
				if meta.payerAvailableBalance == nil || available.Cmp(meta.payerAvailableBalance) < 0 {
					if err := p.validatePayerSolvency(tx, meta, nil); err != nil {
						continue
					}
				}
				meta.payerAvailableBalance = available
				if len(p.pending[sender]) == 0 && p.reserver != nil {
					if err := p.reserver.Hold(sender); err != nil {
						continue
					}
				}
				p.pending[sender] = append(p.pending[sender], tx)
				p.all[tx.Hash()] = tx
				p.meta[tx.Hash()] = meta
				p.reserveTxAccounting(tx.Hash(), meta)
				reused++
				retained++
				continue
			}
			dependencyChanged++
		}
		if err := p.preflightPayerSolvency(tx, nil); err != nil {
			continue
		}
		revalidated++
		meta, err := p.simulateVerifyFrames(tx)
		if err != nil {
			continue
		}
		if err := p.validatePaymasterAccounting(tx, meta, nil); err != nil {
			continue
		}
		if len(p.pending[sender]) == 0 && p.reserver != nil {
			if err := p.reserver.Hold(sender); err != nil {
				continue
			}
		}
		p.pending[sender] = append(p.pending[sender], tx)
		p.all[tx.Hash()] = tx
		p.reserveTxAccounting(tx.Hash(), meta)
		retained++
	}
}

func (p *FramePool) reorgTransactions(oldHead, newHead *types.Header) types.Transactions {
	if oldHead == nil || newHead == nil || oldHead.Hash() == newHead.ParentHash {
		return nil
	}
	oldNum, newNum := oldHead.Number.Uint64(), newHead.Number.Uint64()
	var depth uint64
	if newNum > oldNum {
		depth = newNum - oldNum
	} else {
		depth = oldNum - newNum
	}
	if depth > 64 {
		return nil
	}
	rem := p.chain.GetBlock(oldHead.Hash(), oldNum)
	add := p.chain.GetBlock(newHead.Hash(), newNum)
	if rem == nil || add == nil {
		return nil
	}
	var discarded, included types.Transactions
	for rem.NumberU64() > add.NumberU64() {
		discarded = append(discarded, rem.Transactions()...)
		rem = p.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1)
		if rem == nil {
			return nil
		}
	}
	for add.NumberU64() > rem.NumberU64() {
		included = append(included, add.Transactions()...)
		add = p.chain.GetBlock(add.ParentHash(), add.NumberU64()-1)
		if add == nil {
			return nil
		}
	}
	for rem.Hash() != add.Hash() {
		discarded = append(discarded, rem.Transactions()...)
		included = append(included, add.Transactions()...)
		if rem.NumberU64() == 0 || add.NumberU64() == 0 {
			return nil
		}
		rem = p.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1)
		add = p.chain.GetBlock(add.ParentHash(), add.NumberU64()-1)
		if rem == nil || add == nil {
			return nil
		}
	}
	var lost types.Transactions
	for _, tx := range types.TxDifference(discarded, included) {
		if p.Filter(tx) && (tx.BlobGas() == 0 || tx.BlobTxSidecar() != nil) {
			lost = append(lost, tx)
		}
	}
	return lost
}

// SetGasTip updates the minimum gas tip and evicts underpriced transactions.
func (p *FramePool) SetGasTip(tip *big.Int) {
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
	opts := &txpool.ValidationOptions{
		Config:       p.chainconfig,
		Accept:       1 << types.FrameTxType,
		MaxSize:      txMaxSize,
		MaxBlobCount: params.BlobTxMaxBlobs,
		MinTip:       p.gasTip.ToBig(),
	}
	return txpool.ValidateTransaction(tx, p.currentHead, p.signer, opts)
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
		if err := p.validateAndAdd(tx); err != nil {
			errs[i] = err
			continue
		}
		added = append(added, tx)
	}
	if len(added) > 0 {
		p.txFeed.Send(core.NewTxsEvent{Txs: added})
	}
	return errs
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
		return check, fmt.Errorf("frame pool full")
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
func (p *FramePool) validateAndAdd(tx *types.Transaction) error {
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return fmt.Errorf("not a frame transaction")
	}
	p.validationMu.Lock()
	defer p.validationMu.Unlock()

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
	p.mu.Unlock()

	// Simulate the validation prefix.
	meta, err := p.simulateVerifyFramesWithSignatureGas(tx, signatureGas)
	if err != nil {
		if held && p.reserver != nil {
			p.reserver.Release(sender)
		}
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.validatePaymasterAccounting(tx, meta, replacement); err != nil {
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
		p.pending[sender][replacementIndex] = tx
	} else {
		p.pending[sender] = append(p.pending[sender], tx)
	}
	p.all[tx.Hash()] = tx
	p.reserveTxAccounting(tx.Hash(), meta)
	delete(p.stalePayerCode, tx.Hash())
	return nil
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
	return p.simulateVerifyFramesWithSignatureGas(tx, signatureGas)
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
	mergeDependencies := func(result verifyResult) {
		for _, slot := range result.storageReads {
			storageReads[slot] = struct{}{}
		}
		for _, addr := range result.codeReads {
			codeReads[addr] = struct{}{}
		}
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
		meta.validationDeps = p.snapshotValidationDependencies(frameTx, plan, meta, storageReads, codeReads)
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
	meta.validationDeps = p.snapshotValidationDependencies(frameTx, plan, meta, storageReads, codeReads)
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

// snapshotValidationDependencies records the mutable state that a successful
// public-mempool validation was permitted to observe. Transaction fields and
// signatures are immutable for a given hash; nonce and recent-root references
// are checked directly on every reset. The remaining reusable dependencies are
// sender storage, validation-reached code, sender code, and payer code.
func (p *FramePool) snapshotValidationDependencies(frameTx *types.FrameTx, plan validationPrefixPlan, meta frameTxMeta, storageReads map[common.Hash]struct{}, codeReads map[common.Address]struct{}) *validationDependencySnapshot {
	snapshot := &validationDependencySnapshot{
		senderCodeHash: p.currentState.GetCodeHash(frameTx.Sender),
		rules:          p.chainconfig.Rules(p.currentHead.Number, p.currentHead.Difficulty.Sign() == 0, p.currentHead.Time),
		storageValues:  make(map[storageDependency]common.Hash),
		codeHashes:     make(map[common.Address]common.Hash),
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
	approveScope  uint8
	frameIndex    int
	target        common.Address
	gasLimit      uint64
	gasRemaining  uint64
	prefixGasUsed uint64
	failureClass  verifyFailureClass
	storageReads  []common.Hash
	codeReads     []common.Address
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

func (p *FramePool) reserveTxAccounting(hash common.Hash, meta frameTxMeta) {
	if meta.maxCost == nil {
		meta.maxCost = new(big.Int)
	}
	meta.maxCost = new(big.Int).Set(meta.maxCost)
	if meta.payerAvailableBalance != nil {
		meta.payerAvailableBalance = new(big.Int).Set(meta.payerAvailableBalance)
	}
	p.meta[hash] = meta
	if p.paymasterReserved[meta.payer] == nil {
		p.paymasterReserved[meta.payer] = new(big.Int)
	}
	p.paymasterReserved[meta.payer].Add(p.paymasterReserved[meta.payer], meta.maxCost)
	if meta.nonCanonicalPaymaster {
		p.paymasterPending[meta.payer]++
	}
}

func (p *FramePool) releaseTxAccounting(hash common.Hash) {
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

// SubscribeTransactions subscribes to new transaction events.
func (p *FramePool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	return p.txFeed.Subscribe(ch)
}

// Nonce returns the next nonce for the given address.
func (p *FramePool) Nonce(addr common.Address) uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

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
