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
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// Approval scope bitmask values as returned by APPROVE.
const (
	ApproveNone      uint8 = 0 // No approval (normal RETURN or not set).
	ApprovePayment   uint8 = 1 // APPROVE(0x1): payer approved payment.
	ApproveExecution uint8 = 2 // APPROVE(0x2): sender approved execution.
	ApproveBoth      uint8 = 3 // APPROVE(0x3): both execution and payment.
)

// ChargeFrameTargetAccess charges the ordinary Amsterdam account-access cost
// for entering a frame. The target is warmed only after the frame budget can
// cover the access, so an exceptional halt does not perform an unpriced read.
func ChargeFrameTargetAccess(statedb StateDB, target common.Address, gas *GasBudget) bool {
	cost := params.ColdAccountAccessAmsterdam
	if statedb.AddressInAccessList(target) {
		cost = params.WarmAccountAccessAmsterdam
	}
	if _, ok := gas.ChargeExecution(cost); !ok {
		return false
	}
	statedb.AddAddressToAccessList(target)
	return true
}

// FrameContext holds the context for executing a frame transaction (EIP-8141).
// It is set on the EVM when processing a frame transaction and provides data
// needed by the frame transaction introspection opcodes. All fields are
// populated from the flattened Message during executeFrames().
type FrameContext struct {
	Sender         common.Address // tx.sender
	NonceKeys      []*uint256.Int // tx.nonce_keys
	NonceSeq       uint64         // tx.nonce_seq
	LegacyNonce    uint64         // sender account nonce before frame execution
	NonceKeysHash  common.Hash    // keccak256(bytes32(len(nonce_keys)) || nonce_keys...)
	Frames         []types.Frame  // tx.frames
	Signatures     []types.TxSignature
	GasTipCap      *uint256.Int  // max_priority_fee_per_gas
	GasFeeCap      *uint256.Int  // max_fee_per_gas
	BlobFeeCap     *uint256.Int  // max_fee_per_blob_gas
	BlobHashes     []common.Hash // blob_versioned_hashes
	GasLimit       uint64        // Total gas limit (intrinsic + calldata + sum(frame.gas_limit))
	SigHash        common.Hash   // Cached compute_sig_hash(tx).
	FrameIndex     int           // Currently executing frame index.
	FrameResults   []uint8       // Status of each completed frame (0=fail, 1=success, 2=skipped).
	FrameGasUsed   []types.FrameGasUsed
	RecentRootRefs []types.RecentRootRef
	stateGasOwners map[frameStateSlot]int
}

type frameStateSlot struct {
	address common.Address
	slot    common.Hash
}

// FrameContextSnapshot captures frame-local state-gas ownership across EVM snapshots.
type FrameContextSnapshot struct {
	owners       map[frameStateSlot]int
	frameGasUsed []types.FrameGasUsed
}

// Snapshot captures state-gas ownership and per-frame accounting.
func (fc *FrameContext) Snapshot() *FrameContextSnapshot {
	if fc == nil {
		return nil
	}
	snapshot := &FrameContextSnapshot{
		owners:       make(map[frameStateSlot]int, len(fc.stateGasOwners)),
		frameGasUsed: slices.Clone(fc.FrameGasUsed),
	}
	for slot, owner := range fc.stateGasOwners {
		snapshot.owners[slot] = owner
	}
	return snapshot
}

// Restore rolls frame-local accounting back to a prior snapshot.
func (fc *FrameContext) Restore(snapshot *FrameContextSnapshot) {
	if fc == nil || snapshot == nil {
		return
	}
	fc.stateGasOwners = snapshot.owners
	fc.FrameGasUsed = snapshot.frameGasUsed
}

func (fc *FrameContext) recordStateGas(address common.Address, slot common.Hash) {
	if fc.stateGasOwners == nil {
		fc.stateGasOwners = make(map[frameStateSlot]int)
	}
	fc.stateGasOwners[frameStateSlot{address: address, slot: slot}] = fc.FrameIndex
}

func (fc *FrameContext) refundStateGas(address common.Address, slot common.Hash, amount uint64, current *GasBudget) {
	key := frameStateSlot{address: address, slot: slot}
	owner, ok := fc.stateGasOwners[key]
	if !ok || owner == fc.FrameIndex {
		current.RefundState(amount)
	} else if owner >= 0 && owner < len(fc.FrameGasUsed) {
		fc.FrameGasUsed[owner].State -= min(fc.FrameGasUsed[owner].State, amount)
	}
	delete(fc.stateGasOwners, key)
}

// opApprove implements the APPROVE opcode (0xaa) as defined in EIP-8141.
// It behaves like RETURN but with an additional scope operand that signals
// approval status.
//
// Per EIP-8141, APPROVE enforces:
//   - Must be in a frame tx context (FrameCtx != nil).
//   - ADDRESS == frame.target: only the frame target contract can call APPROVE.
//     This prevents subcalls from issuing approvals. DELEGATECALL preserves
//     ADDRESS, so delegate patterns still work.
//   - scope must be a non-zero subset of frame.flags' allowed-scope bits.
//   - Scope with execution approval: frame.target must equal tx.sender, since
//     only the sender contract can approve execution.
//
// Stack: [offset, length, scope]
func opApprove(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	scopeVal := scope.Stack.pop()

	// Validate scope: must be a non-zero PAYMENT/EXECUTION bitmask.
	if !scopeVal.IsUint64() {
		return nil, ErrExecutionReverted
	}
	s := scopeVal.Uint64()
	if s == 0 || s > uint64(ApproveBoth) {
		return nil, ErrExecutionReverted
	}

	// Must be in a frame tx context.
	if evm.TxContext.FrameCtx == nil {
		return nil, &ErrInvalidOpCode{opcode: APPROVE}
	}

	// ADDRESS == frame.target: only the frame target can call APPROVE.
	currentFrame := evm.TxContext.FrameCtx.Frames[evm.TxContext.FrameCtx.FrameIndex]
	frameTarget := evm.TxContext.FrameCtx.Sender
	if currentFrame.Target != nil {
		frameTarget = *currentFrame.Target
	}
	if scope.Contract.Address() != frameTarget {
		return nil, ErrExecutionReverted
	}

	allowedScope := currentFrame.Flags & types.FrameFlagApproveScopeMask
	if uint8(s)&^allowedScope != 0 {
		return nil, ErrExecutionReverted
	}

	// Execution approval can only come from tx.sender.
	if uint8(s)&ApproveExecution != 0 && frameTarget != evm.TxContext.FrameCtx.Sender {
		return nil, ErrExecutionReverted
	}

	evm.TxContext.ApproveScope = uint8(s)

	ret := scope.Memory.GetCopy(offset.Uint64(), size.Uint64())
	return ret, errStopToken
}

// TXPARAM parameter selectors.
const (
	txParamTxType             = 0x00
	txParamNonce              = 0x01
	txParamSender             = 0x02
	txParamGasTipCap          = 0x03
	txParamGasFeeCap          = 0x04
	txParamBlobFeeCap         = 0x05
	txParamMaxCost            = 0x06
	txParamBlobHashLen        = 0x07
	txParamSigHash            = 0x08
	txParamFrameCount         = 0x09
	txParamFrameIndex         = 0x0a
	txParamSignatureCount     = 0x0b
	txParamStateGasLeft       = 0x0c
	txParamNonceKeyCount      = 0x0d
	txParamNonceKeysHash      = 0x0e
	txParamRecentRootRefCount = 0x0f
	txParamNonceKey0          = 0x10
	// EIP-8250 assigns 0x0c to the legacy nonce, but the current EIP-8141
	// assigns that selector to state_gas_left. Use the next free selector
	// until the draft specifications resolve the collision.
	txParamLegacyNonce = 0x11
)

// FRAMEPARAM parameter selectors.
const (
	frameParamTarget           = 0x00
	frameParamGasLimit         = 0x01
	frameParamMode             = 0x02
	frameParamFlags            = 0x03
	frameParamDataLen          = 0x04
	frameParamStatus           = 0x05
	frameParamAllowedScope     = 0x06
	frameParamAtomicBatch      = 0x07
	frameParamValue            = 0x08
	frameParamStateGasLimit    = 0x09
	frameParamExecutionGasUsed = 0x0a
	frameParamStateGasUsed     = 0x0b
)

// SIGPARAM parameter selectors.
const (
	sigParamSigner       = 0x00
	sigParamScheme       = 0x01
	sigParamMsg          = 0x02
	sigParamSignatureLen = 0x03
	sigParamSignature    = 0x04
)

func invalidFrameOpcode(op OpCode) error {
	return &ErrInvalidOpCode{opcode: op}
}

func frameSelector(v *uint256.Int, op OpCode) (uint64, error) {
	selector, overflow := v.Uint64WithOverflow()
	if overflow {
		return 0, invalidFrameOpcode(op)
	}
	return selector, nil
}

func requireFrameContext(evm *EVM, op OpCode) (*FrameContext, error) {
	if evm.TxContext.FrameCtx == nil {
		return nil, invalidFrameOpcode(op)
	}
	return evm.TxContext.FrameCtx, nil
}

func requireFrame(fc *FrameContext, frameIndex *uint256.Int, op OpCode) (*types.Frame, error) {
	idx, err := frameSelector(frameIndex, op)
	if err != nil {
		return nil, err
	}
	if idx >= uint64(len(fc.Frames)) {
		return nil, invalidFrameOpcode(op)
	}
	return &fc.Frames[int(idx)], nil
}

func setAddressWord(dst *uint256.Int, addr common.Address) {
	var buf [32]byte
	copy(buf[12:], addr[:])
	dst.SetBytes32(buf[:])
}

func setUint256(dst, src *uint256.Int) {
	if src == nil {
		dst.Clear()
		return
	}
	dst.Set(src)
}

func setMaxCost(dst *uint256.Int, evm *EVM, fc *FrameContext) {
	dst.Clear()
	if fc.GasFeeCap == nil {
		return
	}
	gasLimit := new(uint256.Int).SetUint64(fc.GasLimit)
	dst.Mul(gasLimit, fc.GasFeeCap)
	if len(fc.BlobHashes) == 0 || evm.Context.BlobBaseFee == nil {
		return
	}
	blobGas := new(uint256.Int).SetUint64(params.BlobTxBlobGasPerBlob * uint64(len(fc.BlobHashes)))
	blobCost := new(uint256.Int).Mul(blobGas, uint256.MustFromBig(evm.Context.BlobBaseFee))
	dst.Add(dst, blobCost)
}

func frameTarget(fc *FrameContext, frame *types.Frame) common.Address {
	if frame.Target != nil {
		return *frame.Target
	}
	return fc.Sender
}

// opTxParam implements TXPARAM (0xb0).
// Stack: [param] -> [value]
func opTxParam(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc, err := requireFrameContext(evm, TXPARAM)
	if err != nil {
		return nil, err
	}
	param := scope.Stack.peek()
	selector, err := frameSelector(param, TXPARAM)
	if err != nil {
		return nil, err
	}

	switch selector {
	case txParamTxType:
		param.SetUint64(uint64(types.FrameTxType))
	case txParamNonce:
		param.SetUint64(fc.NonceSeq)
	case txParamSender:
		setAddressWord(param, fc.Sender)
	case txParamGasTipCap:
		setUint256(param, fc.GasTipCap)
	case txParamGasFeeCap:
		setUint256(param, fc.GasFeeCap)
	case txParamBlobFeeCap:
		setUint256(param, fc.BlobFeeCap)
	case txParamMaxCost:
		setMaxCost(param, evm, fc)
	case txParamBlobHashLen:
		param.SetUint64(uint64(len(fc.BlobHashes)))
	case txParamSigHash:
		param.SetBytes32(fc.SigHash[:])
	case txParamFrameCount:
		param.SetUint64(uint64(len(fc.Frames)))
	case txParamFrameIndex:
		param.SetUint64(uint64(fc.FrameIndex))
	case txParamSignatureCount:
		param.SetUint64(uint64(len(fc.Signatures)))
	case txParamStateGasLeft:
		param.SetUint64(scope.Contract.Gas.StateGas)
	case txParamNonceKeyCount:
		param.SetUint64(uint64(len(fc.NonceKeys)))
	case txParamNonceKeysHash:
		param.SetBytes32(fc.NonceKeysHash[:])
	case txParamRecentRootRefCount:
		param.SetUint64(uint64(len(fc.RecentRootRefs)))
	case txParamNonceKey0:
		if len(fc.NonceKeys) == 0 || fc.NonceKeys[0] == nil {
			return nil, invalidFrameOpcode(TXPARAM)
		}
		param.Set(fc.NonceKeys[0])
	case txParamLegacyNonce:
		param.SetUint64(fc.LegacyNonce)
	default:
		return nil, invalidFrameOpcode(TXPARAM)
	}
	return nil, nil
}

// opRecentRootRefLoad implements RECENTROOTREFLOAD (0xb5).
// Stack: [index, field] -> [value], with field at the top of stack.
func opRecentRootRefLoad(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc, err := requireFrameContext(evm, RECENTROOTREFLOAD)
	if err != nil {
		return nil, err
	}
	fieldWord := scope.Stack.pop()
	indexWord := scope.Stack.peek()
	index, overflow := indexWord.Uint64WithOverflow()
	if overflow || index >= uint64(len(fc.RecentRootRefs)) {
		return nil, invalidFrameOpcode(RECENTROOTREFLOAD)
	}
	ref := fc.RecentRootRefs[index]
	field, overflow := fieldWord.Uint64WithOverflow()
	if overflow {
		return nil, invalidFrameOpcode(RECENTROOTREFLOAD)
	}
	switch field {
	case 0:
		indexWord.SetBytes32(ref.SourceID[:])
	case 1:
		indexWord.SetUint64(ref.Slot)
	case 2:
		indexWord.SetBytes32(ref.Root[:])
	default:
		return nil, invalidFrameOpcode(RECENTROOTREFLOAD)
	}
	return nil, nil
}

// opFrameDataLoad implements FRAMEDATALOAD (0xb1).
// Stack: [offset, frameIndex] -> [value]
func opFrameDataLoad(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc, err := requireFrameContext(evm, FRAMEDATALOAD)
	if err != nil {
		return nil, err
	}
	offset := scope.Stack.pop()
	frameIndex := scope.Stack.peek()
	frame, err := requireFrame(fc, frameIndex, FRAMEDATALOAD)
	if err != nil {
		return nil, err
	}
	if off, overflow := offset.Uint64WithOverflow(); !overflow {
		frameIndex.SetBytes(getData(frame.Data, off, 32))
	} else {
		frameIndex.Clear()
	}
	return nil, nil
}

// opFrameDataCopy implements FRAMEDATACOPY (0xb2).
// Stack: [memOffset, dataOffset, length, frameIndex]
func opFrameDataCopy(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc, err := requireFrameContext(evm, FRAMEDATACOPY)
	if err != nil {
		return nil, err
	}
	memOffset := scope.Stack.pop()
	dataOffset := scope.Stack.pop()
	length := scope.Stack.pop()
	frameIndex := scope.Stack.pop()
	frame, err := requireFrame(fc, &frameIndex, FRAMEDATACOPY)
	if err != nil {
		return nil, err
	}

	dataOffset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		dataOffset64 = ^uint64(0)
	}
	length64 := length.Uint64()
	scope.Memory.Set(memOffset.Uint64(), length64, getData(frame.Data, dataOffset64, length64))
	return nil, nil
}

// opFrameParam implements FRAMEPARAM (0xb3).
// Stack: [frameIndex, param] -> [value]
func opFrameParam(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc, err := requireFrameContext(evm, FRAMEPARAM)
	if err != nil {
		return nil, err
	}
	frameIndex := scope.Stack.pop()
	param := scope.Stack.peek()
	selector, err := frameSelector(param, FRAMEPARAM)
	if err != nil {
		return nil, err
	}
	frame, err := requireFrame(fc, &frameIndex, FRAMEPARAM)
	if err != nil {
		return nil, err
	}

	switch selector {
	case frameParamTarget:
		setAddressWord(param, frameTarget(fc, frame))
	case frameParamGasLimit:
		param.SetUint64(frame.GasLimit)
	case frameParamMode:
		param.SetUint64(uint64(frame.Mode))
	case frameParamFlags:
		param.SetUint64(uint64(frame.Flags))
	case frameParamDataLen:
		param.SetUint64(uint64(len(frame.Data)))
	case frameParamStatus:
		idx := int(frameIndex.Uint64())
		if idx >= fc.FrameIndex {
			return nil, invalidFrameOpcode(FRAMEPARAM)
		}
		if idx >= len(fc.FrameResults) {
			param.Clear()
		} else {
			param.SetUint64(uint64(fc.FrameResults[idx]))
		}
	case frameParamAllowedScope:
		param.SetUint64(uint64(frame.Flags & types.FrameFlagApproveScopeMask))
	case frameParamAtomicBatch:
		param.SetUint64(uint64((frame.Flags & types.FrameFlagAtomicBatch) >> 2))
	case frameParamValue:
		setUint256(param, frame.Value)
	case frameParamStateGasLimit:
		param.SetUint64(frame.StateGasLimit)
	case frameParamExecutionGasUsed, frameParamStateGasUsed:
		idx := int(frameIndex.Uint64())
		if idx >= fc.FrameIndex || idx >= len(fc.FrameGasUsed) {
			return nil, invalidFrameOpcode(FRAMEPARAM)
		}
		if selector == frameParamExecutionGasUsed {
			param.SetUint64(fc.FrameGasUsed[idx].Execution)
		} else {
			param.SetUint64(fc.FrameGasUsed[idx].State)
		}
	default:
		return nil, invalidFrameOpcode(FRAMEPARAM)
	}
	return nil, nil
}

// opSigParam implements SIGPARAM (0xb4).
// Stack: [signatureIndex, param] -> [value]
func opSigParam(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	fc, err := requireFrameContext(evm, SIGPARAM)
	if err != nil {
		return nil, err
	}
	signatureIndex := scope.Stack.pop()
	param := scope.Stack.peek()
	idx, err := frameSelector(&signatureIndex, SIGPARAM)
	if err != nil {
		return nil, err
	}
	selector, err := frameSelector(param, SIGPARAM)
	if err != nil {
		return nil, err
	}
	if idx >= uint64(len(fc.Signatures)) {
		return nil, invalidFrameOpcode(SIGPARAM)
	}
	sig := &fc.Signatures[int(idx)]
	switch selector {
	case sigParamSigner:
		if sig.Scheme == types.SignatureSchemeArbitrary {
			return nil, invalidFrameOpcode(SIGPARAM)
		}
		signer := types.ResolveTxSignatureSigner(*sig, fc.Sender)
		setAddressWord(param, signer)
	case sigParamScheme:
		param.SetUint64(uint64(sig.Scheme))
	case sigParamMsg:
		switch len(sig.Msg) {
		case 0:
			param.Clear()
		case common.HashLength:
			param.SetBytes32(sig.Msg)
		default:
			return nil, invalidFrameOpcode(SIGPARAM)
		}
	case sigParamSignatureLen:
		param.SetUint64(uint64(len(sig.Signature)))
	case sigParamSignature:
		if sig.Scheme != types.SignatureSchemeArbitrary || scope.Stack.len() < 4 {
			return nil, invalidFrameOpcode(SIGPARAM)
		}
		scope.Stack.pop() // selector
		length := scope.Stack.pop()
		dataOffset := scope.Stack.pop()
		memOffset := scope.Stack.pop()
		dataOffset64, overflow := dataOffset.Uint64WithOverflow()
		if overflow {
			dataOffset64 = ^uint64(0)
		}
		length64 := length.Uint64()
		scope.Memory.Set(memOffset.Uint64(), length64, getData(sig.Signature, dataOffset64, length64))
	default:
		return nil, invalidFrameOpcode(SIGPARAM)
	}
	return nil, nil
}

func memorySigParam(stack *Stack) (uint64, bool) {
	if stack.len() < 2 || stack.back(1).Uint64() != sigParamSignature {
		return 0, false
	}
	if stack.len() < 5 {
		return 0, true
	}
	return calcMemSize64(stack.back(4), stack.back(2))
}

func gasSigParam(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (GasCosts, error) {
	if stack.len() < 2 || stack.back(1).Uint64() != sigParamSignature {
		return GasCosts{}, nil
	}
	if stack.len() < 5 {
		return GasCosts{}, ErrGasUintOverflow
	}
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return GasCosts{}, err
	}
	words, overflow := stack.back(2).Uint64WithOverflow()
	if overflow {
		return GasCosts{}, ErrGasUintOverflow
	}
	words, overflow = math.SafeMul(toWordSize(words), params.CopyGas)
	if overflow {
		return GasCosts{}, ErrGasUintOverflow
	}
	gas, overflow = math.SafeAdd(gas, words)
	if overflow {
		return GasCosts{}, ErrGasUintOverflow
	}
	gas, overflow = math.SafeAdd(gas, 1)
	if overflow {
		return GasCosts{}, ErrGasUintOverflow
	}
	return GasCosts{ExecutionGas: gas}, nil
}

// memoryFrameDataCopy returns the memory size required for FRAMEDATACOPY.
// Stack layout: [memOffset, dataOffset, length, frameIndex].
func memoryFrameDataCopy(stack *Stack) (uint64, bool) {
	return calcMemSize64(stack.back(0), stack.back(2))
}

// gasFrameDataCopy calculates dynamic gas for FRAMEDATACOPY.
// Stack layout: [memOffset, dataOffset, length, frameIndex].
func gasFrameDataCopy(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (GasCosts, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return GasCosts{}, err
	}
	words, overflow := stack.back(2).Uint64WithOverflow()
	if overflow {
		return GasCosts{}, ErrGasUintOverflow
	}
	if words, overflow = math.SafeMul(toWordSize(words), params.CopyGas); overflow {
		return GasCosts{}, ErrGasUintOverflow
	}
	if gas, overflow = math.SafeAdd(gas, words); overflow {
		return GasCosts{}, ErrGasUintOverflow
	}
	return GasCosts{ExecutionGas: gas}, nil
}
