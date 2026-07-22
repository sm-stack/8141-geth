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
	"sync"

	"github.com/ethereum/go-ethereum/common"
	commonmath "github.com/ethereum/go-ethereum/common/math"
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
	MaxVerifyGas uint64
}

// DefaultConfig follows the EIP-8141 public-mempool constants.
var DefaultConfig = Config{MaxVerifyGas: maxVerifyGas}

var (
	// canonicalPaymasterCodeHash is keccak256(CanonicalPaymaster runtime bytecode),
	// compiled by contracts with the pinned EIP-8141 Solidity compiler.
	canonicalPaymasterCodeHash = common.HexToHash("0x6c30f5865065de960a498c71c875f58fc0817d3b5c93819def154c652ba80435")

	// CanonicalPaymaster fixes pending withdrawal amount at storage slot 1.
	canonicalPaymasterPendingWithdrawalSlot = common.Hash{31: 1}
)

// BlockChain defines the blockchain interface needed by the frame pool.
type BlockChain interface {
	Config() *params.ChainConfig
	CurrentBlock() *types.Header
	StateAt(header *types.Header) (*state.StateDB, error)
}

// FramePool is a transaction pool for EIP-8141 frame transactions.
// It validates VERIFY frames by simulating the EIP-8141 public-mempool
// validation prefix before accepting transactions into the pool.
type FramePool struct {
	chain       BlockChain
	chainconfig *params.ChainConfig
	signer      types.Signer

	gasTip       uint256.Int
	currentHead  *types.Header
	currentState *state.StateDB
	slotProvider func(*types.Header) vm.SlotProvider
	verifyGasCap uint64

	reserver txpool.Reserver

	mu      sync.RWMutex
	pending map[common.Address][]*types.Transaction // sender → txs (up to maxFrameTxsPerAccount)
	all     map[common.Hash]*types.Transaction      // hash → tx
	meta    map[common.Hash]frameTxMeta             // hash → validation/accounting metadata

	paymasterReserved map[common.Address]*big.Int // payer → reserved pending max cost
	paymasterPending  map[common.Address]int      // non-canonical payer → pending count

	txFeed event.Feed
}

type frameTxMeta struct {
	payer              common.Address
	usesPaymaster      bool
	canonicalPaymaster bool
	maxCost            *big.Int
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
		chain:        chain,
		chainconfig:  chain.Config(),
		signer:       types.LatestSigner(chain.Config()),
		verifyGasCap: config.MaxVerifyGas,
		pending:      make(map[common.Address][]*types.Transaction),
		all:          make(map[common.Hash]*types.Transaction),
		meta:         make(map[common.Hash]frameTxMeta),
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
	for _, senderTxs := range p.pending {
		txs = append(txs, senderTxs...)
	}
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
	}
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
func (p *FramePool) GetRLP(hash common.Hash) []byte {
	tx := p.Get(hash)
	if tx == nil {
		return nil
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
	return &txpool.TxMetadata{
		Type: tx.Type(),
		Size: tx.Size(),
	}
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

// validateAndAdd performs stateful validation (nonce, VERIFY simulation) and inserts.
func (p *FramePool) validateAndAdd(tx *types.Transaction) error {
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return fmt.Errorf("not a frame transaction")
	}
	p.mu.RLock()
	alreadyKnown := p.all[tx.Hash()] != nil
	p.mu.RUnlock()
	if alreadyKnown {
		return txpool.ErrAlreadyKnown
	}
	signatureGas, err := p.validateFrameSignatures(frameTx)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.all[tx.Hash()] != nil {
		return txpool.ErrAlreadyKnown
	}

	sender := frameTx.Sender

	if err := validateFrameNonce(frameTx, p.currentState); err != nil {
		return err
	}
	if err := p.validateRecentRootReferences(frameTx, p.currentState, p.currentHead); err != nil {
		return err
	}

	var (
		replacement      *types.Transaction
		replacementIndex = -1
	)
	if txs := p.pending[sender]; len(txs) > 0 {
		for index, pendingTx := range txs {
			oldFrameTx := pendingTx.GetFrameTx()
			if frameTx.NonceSeq == oldFrameTx.NonceSeq && frameTx.NonceKeySetEqual(oldFrameTx) {
				replacement = pendingTx
				replacementIndex = index
				break
			}
		}
		if replacement != nil {
			if !isFrameTxPriceBumped(tx, replacement) {
				return txpool.ErrReplaceUnderpriced
			}
		} else if len(txs) >= maxFrameTxsPerAccount {
			return fmt.Errorf("%w: sender %s has %d pending frame transactions", txpool.ErrAccountLimitExceeded, sender.Hex(), len(txs))
		}
	}
	if replacement == nil && len(p.all) >= maxFramePoolSize {
		return fmt.Errorf("frame pool full")
	}

	// Static frame ordering validation (pre-simulation, O(n)).
	if err := validateFrameOrdering(frameTx.Frames, sender); err != nil {
		return err
	}

	// Reserve address (if first tx for this sender).
	held := false
	if len(p.pending[sender]) == 0 {
		if p.reserver != nil {
			if err := p.reserver.Hold(sender); err != nil {
				return err
			}
		}
		held = true
	}

	// Simulate the validation prefix.
	meta, err := p.simulateVerifyFramesWithSignatureGas(tx, signatureGas)
	if err != nil {
		if held && p.reserver != nil {
			p.reserver.Release(sender)
		}
		return err
	}
	if err := p.validatePaymasterAccounting(tx, meta, replacement); err != nil {
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

func (p *FramePool) validateFrameSignatures(frameTx *types.FrameTx) (uint64, error) {
	signatureGas, err := frameTx.SignatureGas()
	if err != nil {
		return 0, err
	}
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
	meta, _, err := p.simulateVerifyFramesWithSignatureGasOutcome(tx, signatureGas)
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
		evm.FrameCtx = frameCtx
		frameCtx.FrameIndex = i
		baseState.Prepare(rules, frameTx.Sender, common.Address{}, &target, precompiles, nil)
		warmRecentRootReferences(baseState, frameTx.RecentRootRefs)
		_, _, vmerr := evm.Call(params.FrameEntryPointAddress, target, frame.Data, vm.NewGasBudget(frame.GasLimit, 0), new(uint256.Int))
		evm.FrameCtx = nil
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
	if err != nil {
		return frameTxMeta{}, senderResult, err
	}
	if senderResult.approveScope == vm.ApproveBoth {
		if err := p.validateNonceSurcharge(frameTx, senderResult.gasRemaining); err != nil {
			return frameTxMeta{}, senderResult, err
		}
		return frameTxMeta{
			payer:   frameTx.Sender,
			maxCost: tx.Cost(),
		}, senderResult, nil
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
	canonical := p.isCanonicalPaymaster(payTarget)
	payResult, err := p.simulateVerifyFrame(frameTx, frameCtx, blockCtx, rules, precompiles, baseState, plan.payVerifyIndex, !canonical)
	if err != nil {
		return frameTxMeta{}, payResult, err
	}
	if payResult.approveScope != vm.ApprovePayment {
		return frameTxMeta{}, payResult, fmt.Errorf("VERIFY frame %d approved scope %d, want payment approval 1", plan.payVerifyIndex, payResult.approveScope)
	}
	if err := p.validateNonceSurcharge(frameTx, payResult.gasRemaining); err != nil {
		return frameTxMeta{}, payResult, err
	}
	return frameTxMeta{
		payer:              payResult.target,
		usesPaymaster:      payResult.target != frameTx.Sender,
		canonicalPaymaster: canonical,
		maxCost:            tx.Cost(),
	}, payResult, nil
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
	evm.FrameCtx = frameCtx
	frameCtx.FrameIndex = index

	simState.Prepare(rules, frameTx.Sender, common.Address{}, &target, precompiles, nil)
	warmRecentRootReferences(simState, frameTx.RecentRootRefs)

	caller := params.FrameEntryPointAddress
	var (
		gasRemaining uint64
		vmerr        error
	)
	if hasNoCode(simState, target) {
		_, gasRemaining, vmerr = vm.ExecuteDefaultCode(evm, caller, target, frame.Data, frame.GasLimit, frame.Mode)
	} else {
		var result vm.GasBudget
		_, result, vmerr = evm.StaticCall(caller, target, frame.Data, vm.NewGasBudget(frame.GasLimit, 0))
		gasRemaining = result.RegularGas + result.StateGas
	}
	evm.FrameCtx = nil
	result := verifyResult{
		frameIndex:   index,
		target:       target,
		gasLimit:     frame.GasLimit,
		gasRemaining: gasRemaining,
	}
	if tracer != nil {
		if violation := tracer.Violation(); violation != nil {
			if violation.Rule == "OP-020" {
				result.failureClass = verifyFailureOutOfGas
			} else {
				result.failureClass = verifyFailureTracerViolation
			}
			return result, fmt.Errorf("VERIFY frame %d: %w", index, violation)
		}
	}
	scope := evm.ApproveScope
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

func (p *FramePool) isCanonicalPaymaster(addr common.Address) bool {
	return p.currentState.GetCodeHash(addr) == canonicalPaymasterCodeHash
}

func (p *FramePool) pendingCanonicalWithdrawal(addr common.Address) *big.Int {
	return p.currentState.GetState(addr, canonicalPaymasterPendingWithdrawalSlot).Big()
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
	approveScope uint8
	frameIndex   int
	target       common.Address
	gasLimit     uint64
	gasRemaining uint64
	failureClass verifyFailureClass
}

func (r verifyResult) gasUsed() uint64 {
	if r.gasRemaining > r.gasLimit {
		return 0
	}
	return r.gasLimit - r.gasRemaining
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

func (p *FramePool) validatePaymasterAccounting(tx *types.Transaction, meta frameTxMeta, replacement *types.Transaction) error {
	if meta.maxCost == nil {
		meta.maxCost = tx.Cost()
	}
	reserved := p.reservedExcluding(meta.payer, replacement)
	required := new(big.Int).Add(reserved, meta.maxCost)
	balance := p.currentState.GetBalance(meta.payer).ToBig()
	var pendingWithdrawal *big.Int
	if meta.usesPaymaster && meta.canonicalPaymaster {
		pendingWithdrawal = p.pendingCanonicalWithdrawal(meta.payer)
		balance.Sub(balance, pendingWithdrawal)
		if balance.Sign() < 0 {
			balance.SetInt64(0)
		}
	}
	if balance.Cmp(required) < 0 {
		return fmt.Errorf("%w: payer %s available balance %v, reserved %v, pending withdrawal %v, tx cost %v", core.ErrInsufficientFunds, meta.payer.Hex(), balance, reserved, pendingWithdrawal, meta.maxCost)
	}
	if meta.usesPaymaster && !meta.canonicalPaymaster {
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
	p.meta[hash] = meta
	if p.paymasterReserved[meta.payer] == nil {
		p.paymasterReserved[meta.payer] = new(big.Int)
	}
	p.paymasterReserved[meta.payer].Add(p.paymasterReserved[meta.payer], meta.maxCost)
	if meta.usesPaymaster && !meta.canonicalPaymaster {
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
	if meta.usesPaymaster && !meta.canonicalPaymaster {
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
		if meta, ok := p.meta[replacement.Hash()]; ok && meta.payer == payer && meta.usesPaymaster && !meta.canonicalPaymaster {
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
	if filter.BlobTxs {
		return nil, 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	pending := make(map[common.Address][]*txpool.LazyTransaction, len(p.pending))
	count := 0
	for addr, txs := range p.pending {
		lazies := make([]*txpool.LazyTransaction, len(txs))
		for i, tx := range txs {
			lazies[i] = &txpool.LazyTransaction{
				Pool:      p,
				Hash:      tx.Hash(),
				Tx:        tx,
				Time:      tx.Time(),
				GasFeeCap: uint256.MustFromBig(tx.GasFeeCap()),
				GasTipCap: uint256.MustFromBig(tx.GasTipCap()),
				Gas:       tx.Gas(),
				BlobGas:   tx.BlobGas(),
			}
		}
		pending[addr] = lazies
		count += len(lazies)
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
