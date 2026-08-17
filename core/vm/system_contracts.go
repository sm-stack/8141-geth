// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// nativeSystemContract implements fork-specific state transitions that are
// exposed through a system-contract address but are not ordinary EVM bytecode.
type nativeSystemContract interface {
	Run(evm *EVM, caller common.Address, input []byte, gas GasBudget, value *uint256.Int) ([]byte, GasBudget, error)
}

var bogotaNativeSystemContracts = map[common.Address]nativeSystemContract{
	params.RecentRootAddress: recentRootSystemContract{},
}

func activeNativeSystemContracts(rules params.Rules) map[common.Address]nativeSystemContract {
	if rules.IsBogota {
		return bogotaNativeSystemContracts
	}
	return nil
}

// recentRootSystemContract implements the EIP-8272 recent-root write contract.
type recentRootSystemContract struct{}

func (recentRootSystemContract) Run(evm *EVM, caller common.Address, input []byte, gas GasBudget, value *uint256.Int) ([]byte, GasBudget, error) {
	if evm.readOnly {
		return nil, gas, ErrWriteProtection
	}
	if len(input) != 64 || !value.IsZero() {
		return nil, gas, ErrExecutionReverted
	}
	const hashGas = 3*params.Keccak256Gas + 9*params.Keccak256WordGas
	if _, ok := gas.ChargeExecution(hashGas); !ok {
		return nil, gas.ExitHalt(), ErrOutOfGas
	}
	salt := common.BytesToHash(input[:32])
	root := common.BytesToHash(input[32:])
	sourceID := types.RecentRootSourceID(caller, salt)
	slot := evm.CurrentSlot()
	key := types.RecentRootStorageKey(sourceID, slot)
	entry := types.RecentRootEntryHash(sourceID, slot, root)

	stack := evm.arena.stack()
	defer stack.release()
	stack.push(new(uint256.Int).SetBytes(entry[:]))
	stack.push(new(uint256.Int).SetBytes(key[:]))
	contract := NewContract(caller, params.RecentRootAddress, value, gas, evm.jumpDests)
	cost, err := gasSStore8037And8038(evm, contract, stack, nil, 0)
	if err != nil {
		return nil, gas.ExitHalt(), ErrOutOfGas
	}
	gas = contract.Gas
	if _, ok := gas.Charge(cost); !ok {
		return nil, gas.ExitHalt(), ErrOutOfGas
	}
	current, original := evm.StateDB.GetStateAndCommittedState(params.RecentRootAddress, key)
	evm.StateDB.SetState(params.RecentRootAddress, key, entry)
	if evm.TxContext.FrameCtx != nil && original == (common.Hash{}) && current == (common.Hash{}) {
		evm.TxContext.FrameCtx.recordStateGas(params.RecentRootAddress, key)
	}
	return nil, gas, nil
}
