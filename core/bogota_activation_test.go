// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func newBogotaActivationEnv(t *testing.T) (*params.ChainConfig, *types.Header, *vm.EVM, *state.StateDB) {
	t.Helper()
	config := *params.MergedTestChainConfig
	amsterdam, bogota := uint64(0), uint64(10)
	config.AmsterdamTime = &amsterdam
	config.BogotaTime = &bogota
	parent := &types.Header{Number: big.NewInt(1), Time: bogota - 1}
	db, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatal(err)
	}
	random := common.Hash{1}
	ctx := vm.BlockContext{BlockNumber: big.NewInt(2), Time: bogota, Difficulty: new(big.Int), Random: &random}
	return &config, parent, vm.NewEVM(ctx, db, &config, vm.Config{}), db
}

func TestBogotaSystemContractActivation(t *testing.T) {
	config, parent, evm, db := newBogotaActivationEnv(t)
	balance := uint256.NewInt(123)
	db.AddBalance(params.NonceManagerAddress, balance, tracing.BalanceChangeUnspecified)
	if _, err := PreExecution(context.Background(), nil, parent, config, evm, big.NewInt(2), 10); err != nil {
		t.Fatal(err)
	}
	for _, contract := range []struct {
		address common.Address
		code    []byte
	}{
		{params.FrameExpiryVerifierAddress, params.FrameExpiryVerifierCode},
		{params.NonceManagerAddress, params.NonceManagerCode},
		{params.RecentRootAddress, params.RecentRootCode},
	} {
		if got := db.GetCode(contract.address); !bytes.Equal(got, contract.code) {
			t.Fatalf("contract %s code = %x, want %x", contract.address, got, contract.code)
		}
		if nonce := db.GetNonce(contract.address); nonce != 1 {
			t.Fatalf("contract %s nonce = %d, want 1", contract.address, nonce)
		}
	}
	if got := db.GetBalance(params.NonceManagerAddress); got.Cmp(balance) != 0 {
		t.Fatalf("nonce manager balance = %s, want %s", got, balance)
	}
}

func TestBogotaSystemContractActivationRejectsOccupiedAddress(t *testing.T) {
	config, parent, evm, db := newBogotaActivationEnv(t)
	db.SetCode(params.NonceManagerAddress, []byte{byte(vm.STOP)}, tracing.CodeChangeUnspecified)
	if _, err := PreExecution(context.Background(), nil, parent, config, evm, big.NewInt(2), 10); err == nil {
		t.Fatal("Bogota activation accepted an occupied system-contract address")
	}
	if code := db.GetCode(params.FrameExpiryVerifierAddress); len(code) != 0 {
		t.Fatalf("partial activation installed expiry verifier code %x", code)
	}
}

func TestBogotaSystemContractActivationRejectsOccupiedStorage(t *testing.T) {
	config, parent, evm, db := newBogotaActivationEnv(t)
	db.SetState(params.NonceManagerAddress, common.Hash{1}, common.Hash{2})
	if _, err := PreExecution(context.Background(), nil, parent, config, evm, big.NewInt(2), 10); err == nil {
		t.Fatal("Bogota activation accepted occupied system-contract storage")
	}
}
