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
// It validates VERIFY frames using ERC-7562-style opcode restriction rules.
package framepool

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
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
	// maxFrameTxsPerAccount is the ERC-7562 SAME_SENDER_MEMPOOL_COUNT.
	maxFrameTxsPerAccount = 4

	// maxFramePoolSize limits total pooled frame transactions.
	maxFramePoolSize = 256

	// verifyFrameGasCap is the ERC-7562 MAX_VERIFICATION_GAS.
	verifyFrameGasCap uint64 = 500_000

	// defaultFrameGasCap limits the gas spent pre-executing DEFAULT frames during
	// mempool simulation. Mirrors ERC-7562's MAX_VERIFICATION_GAS for factory ops.
	defaultFrameGasCap uint64 = 500_000

	// txMaxSize is the maximum frame transaction size.
	txMaxSize uint64 = 512 * 1024
)

// BlockChain defines the blockchain interface needed by the frame pool.
type BlockChain interface {
	Config() *params.ChainConfig
	CurrentBlock() *types.Header
	StateAt(root common.Hash) (*state.StateDB, error)
}

// FramePool is a transaction pool for EIP-8141 frame transactions.
// It validates VERIFY frames by simulating them with ERC-7562-style opcode
// restriction rules before accepting transactions into the pool.
type FramePool struct {
	chain       BlockChain
	chainconfig *params.ChainConfig
	signer      types.Signer

	gasTip       uint256.Int
	currentHead  *types.Header
	currentState *state.StateDB

	reserver txpool.Reserver

	mu      sync.RWMutex
	pending map[common.Address][]*types.Transaction // sender → txs (up to maxFrameTxsPerAccount)
	all     map[common.Hash]*types.Transaction      // hash → tx

	txFeed event.Feed
}

// New creates a new frame transaction pool.
func New(chain BlockChain) *FramePool {
	return &FramePool{
		chain:       chain,
		chainconfig: chain.Config(),
		signer:      types.LatestSigner(chain.Config()),
		pending:     make(map[common.Address][]*types.Transaction),
		all:         make(map[common.Hash]*types.Transaction),
	}
}

// Filter returns true for frame transactions.
func (p *FramePool) Filter(tx *types.Transaction) bool {
	return tx.Type() == types.FrameTxType
}

// Init initializes the frame pool.
func (p *FramePool) Init(gasTip uint64, head *types.Header, reserver txpool.Reserver) error {
	p.reserver = reserver
	p.gasTip = *uint256.NewInt(gasTip)

	statedb, err := p.chain.StateAt(head.Root)
	if err != nil {
		statedb, err = p.chain.StateAt(types.EmptyRootHash)
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
	statedb, err := p.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Failed to reset frame pool state", "err", err)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.currentHead = newHead
	p.currentState = statedb

	// Evict transactions with stale nonces.
	for addr, txs := range p.pending {
		nonce := statedb.GetNonce(addr)
		var valid []*types.Transaction
		for _, tx := range txs {
			if tx.Nonce() >= nonce {
				valid = append(valid, tx)
			} else {
				delete(p.all, tx.Hash())
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

// validateAndAdd performs stateful validation (nonce, VERIFY simulation) and inserts.
func (p *FramePool) validateAndAdd(tx *types.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.all[tx.Hash()] != nil {
		return fmt.Errorf("already known")
	}
	if len(p.all) >= maxFramePoolSize {
		return fmt.Errorf("frame pool full")
	}

	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return fmt.Errorf("not a frame transaction")
	}
	sender := frameTx.Sender

	// Check per-sender limit.
	if len(p.pending[sender]) >= maxFrameTxsPerAccount {
		return fmt.Errorf("sender %s has %d pending frame txs (max %d)", sender.Hex(), len(p.pending[sender]), maxFrameTxsPerAccount)
	}

	// Nonce check.
	stateNonce := p.currentState.GetNonce(sender)
	if tx.Nonce() < stateNonce {
		return fmt.Errorf("%w: tx nonce %d, state nonce %d", core.ErrNonceTooLow, tx.Nonce(), stateNonce)
	}

	// Static frame ordering validation (pre-simulation, O(n)).
	if err := validateFrameOrdering(frameTx.Frames, sender); err != nil {
		return err
	}

	// Reserve address (if first tx for this sender).
	if len(p.pending[sender]) == 0 {
		if err := p.reserver.Hold(sender); err != nil {
			return err
		}
	}

	// Simulate VERIFY frames.
	if err := p.simulateVerifyFrames(frameTx); err != nil {
		if len(p.pending[sender]) == 0 {
			p.reserver.Release(sender)
		}
		return err
	}

	// Insert into pool.
	p.pending[sender] = append(p.pending[sender], tx)
	p.all[tx.Hash()] = tx
	return nil
}

// simulateVerifyFrames runs the frame transaction through a two-phase EVM simulation
// to validate VERIFY frames under ERC-7562 opcode rules.
//
// Phase 1 (DEFAULT frames): pre-executes any DEFAULT frames against a shared base
// state copy, so that contracts deployed in DEFAULT frames exist when VERIFY frames
// run. This mirrors how ERC-7562 simulates factory (initCode) before validation.
//
// Phase 2 (VERIFY frames): runs each VERIFY frame against a fresh copy of the base
// state (which now includes DEFAULT frame side-effects) with the validation tracer
// attached, checking ERC-7562 opcode rules and APPROVE status.
func (p *FramePool) simulateVerifyFrames(frameTx *types.FrameTx) error {
	head := p.currentHead
	rules := p.chainconfig.Rules(head.Number, head.Difficulty.Sign() == 0, head.Time)
	precompiles := vm.ActivePrecompiles(rules)
	sigHash := frameTx.SigHash(p.chainconfig.ChainID)
	if err := types.ValidateFrameTxSignatures(frameTx, sigHash); err != nil {
		return err
	}

	// Build FrameContext (mirrors state_transition.go:806-821).
	frameCtx := &vm.FrameContext{
		Sender:       frameTx.Sender,
		Nonce:        frameTx.Nonce,
		Frames:       frameTx.Frames,
		Signatures:   frameTx.Signatures,
		GasTipCap:    new(uint256.Int).Set(frameTx.GasTipCap),
		GasFeeCap:    new(uint256.Int).Set(frameTx.GasFeeCap),
		GasLimit:     frameTx.TotalGas(),
		SigHash:      sigHash,
		FrameIndex:   0,
		FrameResults: make([]uint8, len(frameTx.Frames)),
	}
	if frameTx.BlobFeeCap != nil {
		frameCtx.BlobFeeCap = new(uint256.Int).Set(frameTx.BlobFeeCap)
	}
	if len(frameTx.BlobHashes) > 0 {
		frameCtx.BlobHashes = frameTx.BlobHashes
	}

	// Shared block context used for both simulation phases.
	random := common.Hash{}
	blockCtx := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		GasLimit:    head.GasLimit,
		BlockNumber: new(big.Int).Add(head.Number, big.NewInt(1)),
		Time:        head.Time + 12,
		Difficulty:  new(big.Int),
		BaseFee:     head.BaseFee,
		Random:      &random,
	}

	// Phase 1: pre-execute DEFAULT frames that appear before the first VERIFY frame.
	// These are deploy/setup frames (analogous to ERC-4337 initCode) whose side-effects
	// (e.g. deployed contracts) must be visible when VERIFY frames run.
	// DEFAULT frames that come after VERIFY frames (e.g. postOp) are execution-phase
	// frames that only make sense after SENDER frames run — skip them here.
	firstVerifyIdx := len(frameTx.Frames)
	for i, frame := range frameTx.Frames {
		if frame.Mode == types.FrameModeVerify {
			firstVerifyIdx = i
			break
		}
	}

	baseState := p.currentState.Copy()
	for i, frame := range frameTx.Frames[:firstVerifyIdx] {
		if frame.Mode != types.FrameModeDefault {
			continue
		}
		if frame.GasLimit > defaultFrameGasCap {
			return fmt.Errorf("DEFAULT frame %d gas %d exceeds cap %d", i, frame.GasLimit, defaultFrameGasCap)
		}
		target := frameTx.Sender
		if frame.Target != nil {
			target = *frame.Target
		}
		evm := vm.NewEVM(blockCtx, baseState, p.chainconfig, vm.Config{})
		evm.SetTxContext(vm.TxContext{
			Origin:   params.FrameEntryPointAddress,
			GasPrice: new(big.Int),
		})
		evm.FrameCtx = frameCtx
		frameCtx.FrameIndex = i
		baseState.Prepare(rules, frameTx.Sender, common.Address{}, &target, precompiles, nil)
		_, _, vmerr := evm.Call(params.FrameEntryPointAddress, target, frame.Data, frame.GasLimit, new(uint256.Int))
		evm.FrameCtx = nil
		if vmerr != nil {
			return fmt.Errorf("DEFAULT frame %d simulation failed: %v", i, vmerr)
		}
	}

	// Phase 2: simulate each VERIFY frame using a copy of baseState so that
	// DEFAULT frame side-effects (e.g. deployed contracts) are visible.
	var results []verifyResult
	for i, frame := range frameTx.Frames {
		if frame.Mode != types.FrameModeVerify {
			continue
		}

		// Gas cap check.
		if frame.GasLimit > verifyFrameGasCap {
			return fmt.Errorf("VERIFY frame %d gas %d exceeds cap %d", i, frame.GasLimit, verifyFrameGasCap)
		}

		// Use a copy of baseState (which includes DEFAULT frame effects) to avoid
		// polluting the pool's state and to isolate VERIFY frames from each other.
		simState := baseState.Copy()

		// Determine target.
		target := frameTx.Sender
		if frame.Target != nil {
			target = *frame.Target
		}

		// Create validation tracer.
		tracer := vm.NewFrameValidationTracer(simState, frameTx.Sender, target, precompiles)

		evmConfig := vm.Config{
			Tracer: tracer.Hooks(),
		}
		evm := vm.NewEVM(blockCtx, simState, p.chainconfig, evmConfig)
		evm.SetTxContext(vm.TxContext{
			Origin:   params.FrameEntryPointAddress,
			GasPrice: new(big.Int),
		})
		evm.FrameCtx = frameCtx
		frameCtx.FrameIndex = i

		// Prepare state.
		simState.Prepare(rules, frameTx.Sender, common.Address{}, &target, precompiles, nil)

		// Execute VERIFY: use default code for EOAs, StaticCall for contracts.
		// Follow EIP-7702 delegation designators when checking for code.
		caller := params.FrameEntryPointAddress
		var vmerr error
		if hasNoCode(simState, target) {
			_, _, vmerr = vm.ExecuteDefaultCode(evm, caller, target, frame.Data, frame.GasLimit, frame.Mode)
		} else {
			_, _, vmerr = evm.StaticCall(caller, target, frame.Data, frame.GasLimit)
		}

		// Check tracer violations first.
		if violation := tracer.Violation(); violation != nil {
			return fmt.Errorf("VERIFY frame %d: %w", i, violation)
		}

		// Check that APPROVE was called and record scope.
		scope := evm.ApproveScope
		if scope == vm.ApproveNone {
			if vmerr != nil {
				return fmt.Errorf("VERIFY frame %d execution failed: %v", i, vmerr)
			}
			return fmt.Errorf("VERIFY frame %d did not APPROVE", i)
		}
		results = append(results, verifyResult{
			frameIndex:   i,
			approveScope: scope,
			target:       target,
		})

		evm.FrameCtx = nil
	}
	// Post-simulation: validate approval scope ordering.
	return validateScopeOrdering(frameTx.Frames, frameTx.Sender, results)
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

// verifyResult records the approval scope and target of a simulated VERIFY frame.
type verifyResult struct {
	frameIndex   int
	approveScope uint8
	target       common.Address
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

// validateScopeOrdering checks that the VERIFY frame approval scopes follow valid
// ordering rules. This mirrors the approval state machine in state_transition.go.
func validateScopeOrdering(frames []types.Frame, sender common.Address, results []verifyResult) error {
	scopeMap := make(map[int]verifyResult, len(results))
	for _, r := range results {
		scopeMap[r.frameIndex] = r
	}

	var senderApproved, payerApproved bool
	for i, frame := range frames {
		// SENDER mode requires prior execution approval.
		if frame.Mode == types.FrameModeSender && !senderApproved {
			return fmt.Errorf("SENDER frame %d before execution approval", i)
		}

		result, isVerify := scopeMap[i]
		if !isVerify {
			continue
		}

		scope := result.approveScope
		target := result.target

		// Execution approval (mirrors state_transition.go).
		if scope&vm.ApproveExecution != 0 {
			if target == sender {
				if senderApproved {
					return fmt.Errorf("VERIFY frame %d: execution re-approval", i)
				}
				senderApproved = true
			}
		}

		// Payment approval (mirrors state_transition.go).
		if scope&vm.ApprovePayment != 0 {
			if !senderApproved {
				return fmt.Errorf("VERIFY frame %d: payment approval without prior execution approval", i)
			}
			if payerApproved {
				return fmt.Errorf("VERIFY frame %d: duplicate payer approval", i)
			}
			payerApproved = true
		}
	}
	if !payerApproved {
		return fmt.Errorf("no payer approved among VERIFY frames")
	}
	return nil
}

// Pending returns all processable frame transactions.
func (p *FramePool) Pending(filter txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction {
	if filter.BlobTxs {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	pending := make(map[common.Address][]*txpool.LazyTransaction, len(p.pending))
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
	}
	return pending
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
		// Find the highest nonce among pending txs.
		for _, tx := range txs {
			if tx.Nonce()+1 > nonce {
				nonce = tx.Nonce() + 1
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
}
