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

package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func newRecentRootEVM(t *testing.T, timestamp uint64) (*vm.EVM, *state.StateDB) {
	t.Helper()
	db, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatal(err)
	}
	db.CreateAccount(params.RecentRootAddress)
	db.SetCode(params.RecentRootAddress, params.RecentRootCode, 0)
	random := common.Hash{1}
	ctx := vm.BlockContext{CanTransfer: CanTransfer, Transfer: Transfer, GetHash: func(uint64) common.Hash { return common.Hash{} }, BlockNumber: big.NewInt(1), Time: timestamp, BaseFee: big.NewInt(1), BlobBaseFee: big.NewInt(1), Difficulty: big.NewInt(0), Random: &random}
	return vm.NewEVM(ctx, db, params.MergedTestChainConfig, vm.Config{}), db
}

func TestRecentRootNativeWriteLastWriteWins(t *testing.T) {
	evm, db := newRecentRootEVM(t, 120)
	source := common.HexToAddress("0x1234")
	salt := common.HexToHash("0x55")
	root1 := common.HexToHash("0x01")
	root2 := common.HexToHash("0x02")
	for i, root := range []common.Hash{root1, root2} {
		input := append(bytes.Clone(salt[:]), root[:]...)
		_, remaining, err := evm.Call(source, params.RecentRootAddress, input, 100_000, new(uint256.Int))
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}
		wantUsed := uint64(22_244)
		if i == 1 {
			wantUsed = 244
		}
		if got := uint64(100_000) - remaining; got != wantUsed {
			t.Fatalf("write %d gas = %d, want %d", i, got, wantUsed)
		}
	}
	sourceID := types.RecentRootSourceID(source, salt)
	key := types.RecentRootStorageKey(sourceID, 10)
	if got, want := db.GetState(params.RecentRootAddress, key), types.RecentRootEntryHash(sourceID, 10, root2); got != want {
		t.Fatalf("entry = %s, want %s", got, want)
	}
}

func TestRecentRootNativeWriteRejectsInvalidCalls(t *testing.T) {
	evm, db := newRecentRootEVM(t, 120)
	source := common.HexToAddress("0x1234")
	valid := make([]byte, 64)
	if _, _, err := evm.Call(source, params.RecentRootAddress, valid[:63], 100_000, new(uint256.Int)); err == nil {
		t.Fatal("short calldata accepted")
	}
	if _, _, err := evm.Call(source, params.RecentRootAddress, valid, 100_000, uint256.NewInt(1)); err == nil {
		t.Fatal("nonzero value accepted")
	}
	if _, _, err := evm.StaticCall(source, params.RecentRootAddress, valid, 100_000); err == nil {
		t.Fatal("static write accepted")
	}
	if _, _, err := evm.CallCode(source, params.RecentRootAddress, valid, 100_000, new(uint256.Int)); err == nil {
		t.Fatal("CALLCODE write accepted")
	}
	if _, _, err := evm.DelegateCall(source, source, params.RecentRootAddress, valid, 100_000, new(uint256.Int)); err == nil {
		t.Fatal("DELEGATECALL write accepted")
	}
	if _, _, err := evm.Call(source, params.RecentRootAddress, valid, 100, new(uint256.Int)); err == nil {
		t.Fatal("underfunded write accepted")
	}
	if got := db.GetState(params.RecentRootAddress, common.Hash{}); got != (common.Hash{}) {
		t.Fatalf("storage changed: %s", got)
	}
}
