// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package framecorpus contains deterministic EIP-8141 validation workloads
// shared by unit tests and the devp2p benchmark harness.
package framecorpus

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

const (
	PairingPureFirst         = "pairing-pure-first"
	PairingStateFirst        = "pairing-state-first"
	PairingStateSelectsInput = "pairing-state-selects-input"
	CheapNowExpensiveLater   = "cheap-now-expensive-later"
	PureEVMBeforeState       = "pure-evm-before-state"
	PairingPureOnly          = "pairing-pure-only"

	PairingAddress   = byte(8)
	PairingPairs     = 4
	PairingInputSize = PairingPairs * 192
	PairingGas       = uint64(181_000)
	VerifyGas        = uint64(250_000)
)

var shapeNames = []string{
	PairingPureFirst,
	PairingStateFirst,
	PairingStateSelectsInput,
	CheapNowExpensiveLater,
	PureEVMBeforeState,
	PairingPureOnly,
}

// Workload is one validation program and its transaction-fixed input.
type Workload struct {
	Name       string
	Sender     common.Address
	Code       []byte
	Data       []byte
	VerifyGas  uint64
	PairingGas uint64
}

// Names returns the validation shape names accepted by WorkloadFor.
func Names() []string {
	return append([]string(nil), shapeNames...)
}

// PairingInput constructs four non-zero valid BN254 pairs. Each two-pair group
// is e(k*G1, G2) * e(-k*G1, G2), so the pairing result is true. The variant is
// committed to the points, making inputs different between transactions while
// remaining stable across head resets of the same transaction.
func PairingInput(variant uint64) []byte {
	if variant == 0 {
		variant = 1
	}
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1)).Marshal()
	result := make([]byte, 0, PairingInputSize)
	for offset := uint64(0); offset < 2; offset++ {
		scalar := new(big.Int).SetUint64(variant)
		scalar.Add(scalar, new(big.Int).SetUint64(offset))
		point := new(bn256.G1).ScalarBaseMult(scalar)
		negative := new(bn256.G1).Neg(point)
		result = append(result, point.Marshal()...)
		result = append(result, g2...)
		result = append(result, negative.Marshal()...)
		result = append(result, g2...)
	}
	return result
}

// WorkloadFor builds a named workload. Variant should be unique per
// transaction; it does not otherwise affect the validation program.
func WorkloadFor(name string, variant uint64) (Workload, error) {
	code, err := codeFor(name)
	if err != nil {
		return Workload{}, err
	}
	var data []byte
	switch name {
	case PairingPureFirst, PairingStateFirst, CheapNowExpensiveLater, PairingPureOnly:
		data = PairingInput(variant)
	case PairingStateSelectsInput:
		data = append(PairingInput(variant), PairingInput(variant+1)...)
	case PureEVMBeforeState:
	}
	return Workload{
		Name:       name,
		Sender:     senderFor(name),
		Code:       code,
		Data:       data,
		VerifyGas:  VerifyGas,
		PairingGas: PairingGas,
	}, nil
}

// GenesisCode returns independent copies of all corpus sender programs.
func GenesisCode() map[common.Address][]byte {
	result := make(map[common.Address][]byte, len(shapeNames))
	for _, name := range shapeNames {
		workload, err := WorkloadFor(name, 1)
		if err != nil {
			panic(err)
		}
		result[workload.Sender] = common.CopyBytes(workload.Code)
	}
	return result
}

func senderFor(name string) common.Address {
	for index, candidate := range shapeNames {
		if candidate == name {
			return common.BytesToAddress([]byte{0x81, 0x41, byte(index + 1)})
		}
	}
	return common.Address{}
}

func codeFor(name string) ([]byte, error) {
	var code []byte
	switch name {
	case PairingPureFirst:
		code = appendPairingCall(code, true)
		code = append(code, byte(vm.PUSH0), byte(vm.SLOAD), byte(vm.POP))
	case PairingStateFirst:
		code = append(code, byte(vm.PUSH0), byte(vm.SLOAD), byte(vm.POP))
		code = appendPairingCall(code, true)
	case PairingStateSelectsInput:
		code = append(code,
			byte(vm.PUSH0), byte(vm.SLOAD),
			byte(vm.PUSH2), byte(PairingInputSize>>8), byte(PairingInputSize&0xff), byte(vm.MUL),
			byte(vm.PUSH2), byte(PairingInputSize>>8), byte(PairingInputSize&0xff), byte(vm.SWAP1), byte(vm.PUSH0), byte(vm.CALLDATACOPY),
		)
		code = appendPairingCall(code, false)
	case CheapNowExpensiveLater:
		code = []byte{byte(vm.PUSH0), byte(vm.SLOAD), byte(vm.ISZERO), byte(vm.PUSH2), 0, 0, byte(vm.JUMPI)}
		approvePatch := 4
		code = appendPairingCall(code, true)
		approvePC := len(code)
		code = append(code, byte(vm.JUMPDEST))
		code = appendApproveBoth(code)
		code[approvePatch], code[approvePatch+1] = byte(approvePC>>8), byte(approvePC)
		return code, nil
	case PureEVMBeforeState:
		const iterations = 4_000
		code = []byte{byte(vm.PUSH2), byte(iterations >> 8), byte(iterations & 0xff)}
		loopPC := len(code)
		code = append(code,
			byte(vm.JUMPDEST), byte(vm.PUSH1), 1, byte(vm.SWAP1), byte(vm.SUB), byte(vm.DUP1),
			byte(vm.PUSH2), byte(loopPC>>8), byte(loopPC), byte(vm.JUMPI), byte(vm.POP),
			byte(vm.PUSH0), byte(vm.SLOAD), byte(vm.POP),
		)
	case PairingPureOnly:
		code = appendPairingCall(code, true)
	default:
		return nil, fmt.Errorf("unknown frame validation corpus %q", name)
	}
	return appendApproveBoth(code), nil
}

func appendPairingCall(code []byte, copyCalldata bool) []byte {
	if copyCalldata {
		code = append(code,
			byte(vm.PUSH2), byte(PairingInputSize>>8), byte(PairingInputSize&0xff),
			byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.CALLDATACOPY),
		)
	}
	code = append(code,
		byte(vm.PUSH1), 0x20,
		byte(vm.PUSH0),
		byte(vm.PUSH2), byte(PairingInputSize>>8), byte(PairingInputSize&0xff),
		byte(vm.PUSH0),
		byte(vm.PUSH1), PairingAddress,
		byte(vm.GAS), byte(vm.STATICCALL),
		byte(vm.ISZERO), byte(vm.PUSH2), 0, 0, byte(vm.JUMPI),
	)
	failurePatch := len(code) - 3
	code = append(code,
		byte(vm.PUSH0), byte(vm.MLOAD), byte(vm.ISZERO), byte(vm.PUSH2), 0, 0, byte(vm.JUMPI),
	)
	secondFailurePatch := len(code) - 3
	code = append(code, byte(vm.PUSH2), 0, 0, byte(vm.JUMP))
	endPatch := len(code) - 3
	failurePC := len(code)
	code = append(code, byte(vm.JUMPDEST), byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.REVERT))
	endPC := len(code)
	code = append(code, byte(vm.JUMPDEST))
	code[failurePatch], code[failurePatch+1] = byte(failurePC>>8), byte(failurePC)
	code[secondFailurePatch], code[secondFailurePatch+1] = byte(failurePC>>8), byte(failurePC)
	code[endPatch], code[endPatch+1] = byte(endPC>>8), byte(endPC)
	return code
}

func appendApproveBoth(code []byte) []byte {
	return append(code, byte(vm.PUSH1), vm.ApproveBoth, byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.APPROVE))
}
