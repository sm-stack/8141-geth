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
	ret, budget, err := ExecuteDefaultCodeWithGasBudget(evm, caller, target, input, NewGasBudget(gas, 0), frameMode)
	return ret, budget.ExecutionGas, err
}

// ExecuteDefaultCodeWithGasBudget is the two-dimensional variant used by frame
// transaction execution.
func ExecuteDefaultCodeWithGasBudget(evm *EVM, caller common.Address, target common.Address, input []byte, gas GasBudget, frameMode uint8) ([]byte, GasBudget, error) {
	switch frameMode {
	case types.FrameModeVerify:
		fc := evm.TxContext.FrameCtx
		if fc == nil || fc.FrameIndex < 0 || fc.FrameIndex >= len(fc.Frames) {
			if !gas.ChargeExecutionOnly(defaultCodeBaseGas) {
				return nil, gas.ExitHalt(), ErrOutOfGas
			}
			return nil, gas.ExitRevert(), ErrExecutionReverted
		}
		approveScope, remaining, err := EvaluateDefaultCodeVerify(fc.Frames[fc.FrameIndex], fc.Signatures, fc.Sender, target, gas)
		if err != nil {
			return nil, remaining, err
		}
		if _, _, err := applyDefaultApprove(evm, target, approveScope, remaining.ExecutionGas); err != nil {
			return nil, remaining.ExitRevert(), err
		}
		return nil, remaining, nil
	case types.FrameModeSender, types.FrameModeDefault:
		return nil, gas, nil
	default:
		return nil, gas.ExitRevert(), ErrExecutionReverted
	}
}

// EvaluateDefaultCodeVerify evaluates the state-independent portion of an
// EIP-8141 default-code VERIFY frame. Protocol-signature cryptography must be
// validated separately before callers rely on the returned approval scope.
func EvaluateDefaultCodeVerify(frame types.Frame, signatures []types.TxSignature, sender, target common.Address, gas GasBudget) (uint8, GasBudget, error) {
	if frame.Mode != types.FrameModeVerify {
		return ApproveNone, gas.ExitRevert(), ErrExecutionReverted
	}
	if !gas.ChargeExecutionOnly(defaultCodeBaseGas) {
		return ApproveNone, gas.ExitHalt(), ErrOutOfGas
	}
	approveScope, ok := defaultCodeTxSignatureApproveScopeForFrame(frame, signatures, sender, target)
	if !ok || approveScope&ApproveExecution != 0 && target != sender {
		return ApproveNone, gas.ExitRevert(), ErrExecutionReverted
	}
	return approveScope, gas, nil
}

func defaultCodeTxSignatureApproveScopeForFrame(frame types.Frame, signatures []types.TxSignature, sender, target common.Address) (uint8, bool) {
	allowedScope := frame.Flags & types.FrameFlagApproveScopeMask
	if allowedScope == ApproveNone {
		return 0, false
	}
	sigIndex := 1
	if allowedScope&ApproveExecution != 0 {
		sigIndex = 0
	}
	if sigIndex >= len(signatures) {
		return 0, false
	}
	sig := signatures[sigIndex]
	if sig.Scheme == types.SignatureSchemeSecp256k1 && types.ResolveTxSignatureSigner(sig, sender) == target && len(sig.Msg) == 0 {
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

	fc := evm.TxContext.FrameCtx
	if fc == nil {
		return nil, gas, ErrExecutionReverted
	}

	if scope&ApproveExecution != 0 && target != fc.Sender {
		return nil, gas, ErrExecutionReverted
	}

	evm.TxContext.ApproveScope = scope
	return nil, gas, nil
}
