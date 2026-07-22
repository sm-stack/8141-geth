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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Gas costs for EOA default code operations.
const (
	// defaultCodeBaseGas is the base gas cost for default code execution.
	defaultCodeBaseGas uint64 = 100
)

// ExecuteDefaultCode implements the EIP-8141 "default code" behavior for EOAs
// (accounts with no code) when they are the target of a frame transaction.
//
// The function is called from executeFrames() when the frame target has no code.
// VERIFY approves the scope allowed by the current frame flags if a matching
// empty-msg transaction-level protocol-supported signature exists. SENDER and DEFAULT
// modes behave like a regular call to empty code and succeed without side effects.
//
// Returns the return data, leftover gas, and any error.
func ExecuteDefaultCode(evm *EVM, caller common.Address, target common.Address, input []byte, gas uint64, frameMode uint8) ([]byte, uint64, error) {
	switch frameMode {
	case types.FrameModeVerify:
		return executeDefaultVerify(evm, target, gas)
	case types.FrameModeSender, types.FrameModeDefault:
		return nil, gas, nil
	default:
		return nil, gas, ErrExecutionReverted
	}
}

// executeDefaultVerify implements the VERIFY mode of the EOA default code.
// Transaction-level signatures are validated before execution; this path only
// checks that a matching empty-msg protocol-supported signature is present.
func executeDefaultVerify(evm *EVM, target common.Address, gas uint64) ([]byte, uint64, error) {
	fc := evm.FrameCtx
	if fc == nil {
		return nil, gas, ErrExecutionReverted
	}

	approveScope, ok := defaultCodeTxSignatureApproveScope(fc, target)
	if !ok {
		return nil, gas, ErrExecutionReverted
	}

	if gas < defaultCodeBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= defaultCodeBaseGas
	return applyDefaultApprove(evm, target, approveScope, gas)
}

func defaultCodeTxSignatureApproveScope(fc *FrameContext, target common.Address) (uint8, bool) {
	if fc.FrameIndex < 0 || fc.FrameIndex >= len(fc.Frames) {
		return 0, false
	}
	allowedScope := fc.Frames[fc.FrameIndex].Flags & types.FrameFlagApproveScopeMask
	if allowedScope == ApproveNone {
		return 0, false
	}
	sigIndex := 1
	if allowedScope&ApproveExecution != 0 {
		sigIndex = 0
	}
	if sigIndex >= len(fc.Signatures) {
		return 0, false
	}
	sig := fc.Signatures[sigIndex]
	if sig.Scheme == types.SignatureSchemeSecp256k1 && types.ResolveTxSignatureSigner(sig, fc.Sender) == target && len(sig.Msg) == 0 {
		return allowedScope, true
	}
	return 0, false
}

// applyDefaultApprove sets the APPROVE status on the EVM, mirroring what
// the APPROVE opcode does but from the default code path.
func applyDefaultApprove(evm *EVM, target common.Address, scope uint8, gas uint64) ([]byte, uint64, error) {
	// Validate scope: must be a non-zero PAYMENT/EXECUTION bitmask.
	if scope == 0 || scope > ApproveBoth {
		return nil, gas, ErrExecutionReverted
	}

	fc := evm.FrameCtx
	if fc == nil {
		return nil, gas, ErrExecutionReverted
	}

	if scope&ApproveExecution != 0 && target != fc.Sender {
		return nil, gas, ErrExecutionReverted
	}

	evm.ApproveScope = scope
	return nil, gas, nil
}
