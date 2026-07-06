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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256r1"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// Signature types for EOA default code.
const (
	sigTypeSecp256k1 = 0x00
	sigTypeP256      = 0x01
)

// Gas costs for EOA default code operations.
const (
	// defaultCodeBaseGas is the base gas cost for default code execution.
	defaultCodeBaseGas uint64 = 100
)

// eoaCallRLP is the RLP-decodable form for calls in SENDER mode default code.
type eoaCallRLP struct {
	Target common.Address
	Value  *big.Int
	Data   []byte
}

// ExecuteDefaultCode implements the EIP-8141 "default code" behavior for EOAs
// (accounts with no code) when they are the target of a frame transaction.
//
// The function is called from executeFrames() when the frame target has no code.
// It interprets frame.data according to the frame mode and performs the
// appropriate action (signature verification, call execution, or revert).
//
// Returns the return data, leftover gas, and any error.
func ExecuteDefaultCode(evm *EVM, caller common.Address, target common.Address, input []byte, gas uint64, frameMode uint8) ([]byte, uint64, error) {
	if frameMode == types.FrameModeVerify {
		return executeDefaultVerify(evm, target, input, gas, 0)
	}
	if len(input) == 0 {
		return nil, gas, ErrExecutionReverted
	}

	firstByte := input[0]
	scope := (firstByte >> 4) & 0x0F // high nibble: APPROVE scope
	dataMode := firstByte & 0x0F     // low nibble: operation mode

	switch frameMode {
	case types.FrameModeSender:
		if dataMode != types.FrameModeSender {
			return nil, gas, ErrExecutionReverted
		}
		return executeDefaultSender(evm, target, input, gas, scope)
	case types.FrameModeDefault:
		return nil, gas, ErrExecutionReverted
	default:
		return nil, gas, ErrExecutionReverted
	}
}

// executeDefaultVerify implements the VERIFY mode of the EOA default code.
// It verifies a signature (secp256k1 or P256) against the transaction's
// signature hash and calls APPROVE on success.
func executeDefaultVerify(evm *EVM, target common.Address, input []byte, gas uint64, scope uint8) ([]byte, uint64, error) {
	fc := evm.FrameCtx
	if fc == nil {
		return nil, gas, ErrExecutionReverted
	}

	if approveScope, ok := defaultCodeTxSignatureApproveScope(fc, target); ok {
		if gas < defaultCodeBaseGas {
			return nil, 0, ErrOutOfGas
		}
		gas -= defaultCodeBaseGas
		return applyDefaultApprove(evm, target, approveScope, gas)
	}

	// frame.target must equal tx.sender for VERIFY default code.
	if target != fc.Sender {
		return nil, gas, ErrExecutionReverted
	}

	// Charge base gas.
	if gas < defaultCodeBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= defaultCodeBaseGas

	// Must have at least 2 bytes (first byte + signature_type).
	if len(input) < 2 {
		return nil, gas, ErrExecutionReverted
	}

	sigType := input[1]

	switch sigType {
	case sigTypeSecp256k1:
		return verifySecp256k1(evm, target, input, gas, scope)
	case sigTypeP256:
		return verifyP256(evm, target, input, gas, scope)
	default:
		return nil, gas, ErrExecutionReverted
	}
}

func defaultCodeTxSignatureApproveScope(fc *FrameContext, target common.Address) (uint8, bool) {
	if fc.FrameIndex < 0 || fc.FrameIndex >= len(fc.Frames) {
		return 0, false
	}
	allowedScope := fc.Frames[fc.FrameIndex].Flags & types.FrameFlagApproveScopeMask
	var approveScope uint8
	switch allowedScope {
	case 0x1: // payment
		approveScope = 1
	case 0x2: // execution
		approveScope = 0
	case 0x3: // execution + payment
		approveScope = 2
	default:
		return 0, false
	}
	for _, sig := range fc.Signatures {
		if sig.Scheme == types.SignatureSchemeSecp256k1 && sig.Signer == target && len(sig.Msg) == 0 {
			return approveScope, true
		}
	}
	return 0, false
}

// verifySecp256k1 verifies an ECDSA secp256k1 signature for EOA default code.
//
// Data layout: [byte0, 0x00, v(1), r(32), s(32)] = 67 bytes total
// hash = keccak256(sig_hash || data_without_signature)
// data_without_signature = input[:2] (the 2 header bytes)
func verifySecp256k1(evm *EVM, target common.Address, input []byte, gas uint64, scope uint8) ([]byte, uint64, error) {
	// Validate data length: 2 header + 65 signature = 67 bytes.
	if len(input) != 67 {
		return nil, gas, ErrExecutionReverted
	}

	// Charge ecrecover gas.
	if gas < params.EcrecoverGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= params.EcrecoverGas

	// Charge keccak gas: 30 base + 6 per word (sig_hash=32 + header=2 = 34 bytes = 2 words).
	keccakGas := params.Keccak256Gas + 2*params.Keccak256WordGas
	if gas < keccakGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= keccakGas

	fc := evm.FrameCtx
	sigHash := fc.SigHash

	v := input[2]
	r := input[3:35]
	s := input[35:67]
	dataWithoutSig := input[:2] // prefix before (v, r, s)

	// hash = keccak256(sig_hash || data_without_signature)
	hashInput := make([]byte, 32+len(dataWithoutSig))
	copy(hashInput, sigHash[:])
	copy(hashInput[32:], dataWithoutSig)
	hash := crypto.Keccak256(hashInput)

	// Build ecrecover input: (hash, v, r, s) each 32 bytes.
	// The precompile expects v as 27 or 28.
	var ecInput [128]byte
	copy(ecInput[0:32], hash)
	ecInput[63] = v + 27 // v: 0/1 → 27/28
	copy(ecInput[64:96], common.LeftPadBytes(r, 32))
	copy(ecInput[96:128], common.LeftPadBytes(s, 32))

	recovered, err := (&ecrecover{}).Run(ecInput[:])
	if err != nil || len(recovered) == 0 {
		return nil, gas, ErrExecutionReverted
	}

	// Compare recovered address with target.
	recoveredAddr := common.BytesToAddress(recovered)
	if recoveredAddr != target {
		return nil, gas, ErrExecutionReverted
	}

	// Set APPROVE.
	return applyDefaultApprove(evm, target, scope, gas)
}

// verifyP256 verifies a P256 (secp256r1) signature for EOA default code.
//
// Data layout: [byte0, 0x01, r(32), s(32), qx(32), qy(32)] = 130 bytes total
// hash = keccak256(sig_hash || data_without_signature)
// data_without_signature = input[:2] (the 2 header bytes)
// target must equal keccak256(qx || qy)[12:]
func verifyP256(evm *EVM, target common.Address, input []byte, gas uint64, scope uint8) ([]byte, uint64, error) {
	// Validate data length: 2 header + 128 signature = 130 bytes.
	if len(input) != 130 {
		return nil, gas, ErrExecutionReverted
	}

	// Charge P256 verify gas.
	if gas < params.P256VerifyGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= params.P256VerifyGas

	// Charge keccak gas: two keccak calls.
	// 1) hash = keccak256(sig_hash || data_without_sig): 34 bytes = 2 words
	// 2) addr = keccak256(qx || qy): 64 bytes = 2 words
	keccakGas := 2 * (params.Keccak256Gas + 2*params.Keccak256WordGas)
	if gas < keccakGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= keccakGas

	fc := evm.FrameCtx
	sigHash := fc.SigHash

	r := new(big.Int).SetBytes(input[2:34])
	s := new(big.Int).SetBytes(input[34:66])
	qx := new(big.Int).SetBytes(input[66:98])
	qy := new(big.Int).SetBytes(input[98:130])
	dataWithoutSig := input[:2] // prefix before (r, s, qx, qy)

	// Verify target == keccak256(qx || qy)[12:].
	pubKeyBytes := make([]byte, 64)
	copy(pubKeyBytes[0:32], input[66:98])
	copy(pubKeyBytes[32:64], input[98:130])
	addrHash := crypto.Keccak256(pubKeyBytes)
	derivedAddr := common.BytesToAddress(addrHash[12:])
	if derivedAddr != target {
		return nil, gas, ErrExecutionReverted
	}

	// hash = keccak256(sig_hash || data_without_signature)
	hashInput := make([]byte, 32+len(dataWithoutSig))
	copy(hashInput, sigHash[:])
	copy(hashInput[32:], dataWithoutSig)
	hash := crypto.Keccak256(hashInput)

	// Verify P256 signature.
	if !secp256r1.Verify(hash, r, s, qx, qy) {
		return nil, gas, ErrExecutionReverted
	}

	// Set APPROVE.
	return applyDefaultApprove(evm, target, scope, gas)
}

// applyDefaultApprove sets the APPROVE status on the EVM, mirroring what
// the APPROVE opcode does but from the default code path.
func applyDefaultApprove(evm *EVM, target common.Address, scope uint8, gas uint64) ([]byte, uint64, error) {
	// Validate scope: must be 0, 1, or 2.
	if scope > 2 {
		return nil, gas, ErrExecutionReverted
	}

	fc := evm.FrameCtx
	if fc == nil {
		return nil, gas, ErrExecutionReverted
	}

	// For scope 0x0/0x2 (execution approval): target must be tx.sender.
	if (scope == 0 || scope == 2) && target != fc.Sender {
		return nil, gas, ErrExecutionReverted
	}

	// Map scope operand to approval status code: scope + 2.
	evm.ApproveScope = scope + 2
	return nil, gas, nil
}

// executeDefaultSender implements the SENDER mode of the EOA default code.
// It decodes an RLP-encoded list of calls from frame.data[1:] and executes
// each one with msg.sender = tx.sender.
func executeDefaultSender(evm *EVM, target common.Address, input []byte, gas uint64, scope uint8) ([]byte, uint64, error) {
	fc := evm.FrameCtx
	if fc == nil {
		return nil, gas, ErrExecutionReverted
	}

	// High nibble (scope) must be 0 for SENDER mode.
	if scope != 0 {
		return nil, gas, ErrExecutionReverted
	}

	// frame.target must equal tx.sender.
	if target != fc.Sender {
		return nil, gas, ErrExecutionReverted
	}

	// Charge base gas.
	if gas < defaultCodeBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= defaultCodeBaseGas

	// Decode RLP calls from input[1:].
	if len(input) < 2 {
		return nil, gas, ErrExecutionReverted
	}

	var calls []eoaCallRLP
	if err := rlp.DecodeBytes(input[1:], &calls); err != nil {
		return nil, gas, ErrExecutionReverted
	}

	// Execute each call.
	for _, call := range calls {
		value, _ := uint256.FromBig(call.Value)
		if value == nil {
			value = new(uint256.Int)
		}

		ret, leftOver, err := evm.Call(fc.Sender, call.Target, call.Data, gas, value)
		gas = leftOver
		_ = ret

		if err != nil {
			// Any call revert causes the whole frame to revert.
			return nil, gas, ErrExecutionReverted
		}
	}

	return nil, gas, nil
}
