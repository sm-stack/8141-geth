// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func TestFramePoolRejectsDelegatedDeployFactoryBeforeValidation(t *testing.T) {
	pool, statedb, config := newTestEnv()
	factory := common.HexToAddress("0x2222222222222222222222222222222222222222")
	delegate := common.HexToAddress("0x3333333333333333333333333333333333333333")
	statedb.CreateAccount(factory)
	statedb.SetNonce(factory, 1, tracing.NonceChangeUnspecified)
	statedb.SetCode(factory, types.AddressToDelegation(delegate), tracing.CodeChangeUnspecified)
	statedb.CreateAccount(delegate)
	statedb.SetCode(delegate, createFactoryCode(approveBothCode), tracing.CodeChangeUnspecified)
	sender := crypto.CreateAddress(factory, statedb.GetNonce(factory))
	tx := newDeployFactoryTestTx(statedb, config, sender, factory, nil)

	signatureBefore := signatureRunMeter.Snapshot().Count()
	verifyBefore := verifyRunMeter.Snapshot().Count()
	senderVerifyBefore := senderVerifyRunMeter.Snapshot().Count()
	err := pool.Add([]*types.Transaction{tx}, false)[0]
	if !errors.Is(err, core.ErrFrameTxInvalid) {
		t.Fatalf("delegated factory admission error: have %v want %v", err, core.ErrFrameTxInvalid)
	}
	if !strings.Contains(err.Error(), factory.Hex()) || !strings.Contains(err.Error(), delegate.Hex()) {
		t.Fatalf("delegated factory admission error omits factory or delegate: %v", err)
	}
	if pending, _ := pool.Stats(); pending != 0 {
		t.Fatalf("pending delegated-factory transactions: have %d want 0", pending)
	}
	if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
		t.Fatalf("delegated factory signature runs: have %d want 0", delta)
	}
	if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
		t.Fatalf("delegated factory validation-prefix runs: have %d want 0", delta)
	}
	if delta := senderVerifyRunMeter.Snapshot().Count() - senderVerifyBefore; delta != 0 {
		t.Fatalf("delegated factory sender VERIFY runs: have %d want 0", delta)
	}
}

func TestFramePoolResetEvictsDelegatedDeployFactoryBeforeValidation(t *testing.T) {
	for _, test := range []struct {
		name      string
		selective bool
	}{
		{name: "full"},
		{name: "selective", selective: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, statedb, config := newTestEnv()
			pool.selectiveRevalidation = test.selective
			factory := common.HexToAddress("0x2222222222222222222222222222222222222222")
			delegate := common.HexToAddress("0x3333333333333333333333333333333333333333")
			factoryCode := createFactoryCode(approveBothCode)
			statedb.CreateAccount(factory)
			statedb.SetCode(factory, factoryCode, tracing.CodeChangeUnspecified)
			sender := crypto.CreateAddress(factory, statedb.GetNonce(factory))
			tx := newDeployFactoryTestTx(statedb, config, sender, factory, nil)
			if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
				t.Fatalf("initial stable-factory admission failed: %v", err)
			}

			resetRevalidatedBefore := resetRevalidatedMeter.Snapshot().Count()
			signatureBefore := signatureRunMeter.Snapshot().Count()
			verifyBefore := verifyRunMeter.Snapshot().Count()
			senderVerifyBefore := senderVerifyRunMeter.Snapshot().Count()
			chain := pool.chain.(*testChain)
			resetWithStateChange(pool, chain, func(nextState *state.StateDB) {
				nextState.CreateAccount(delegate)
				nextState.SetCode(delegate, factoryCode, tracing.CodeChangeUnspecified)
				nextState.SetCode(factory, types.AddressToDelegation(delegate), tracing.CodeChangeUnspecified)
			})

			if pending, _ := pool.Stats(); pending != 0 {
				t.Fatalf("pending after delegated factory reset: have %d want 0", pending)
			}
			if delta := resetRevalidatedMeter.Snapshot().Count() - resetRevalidatedBefore; delta != 0 {
				t.Fatalf("delegated factory full revalidations: have %d want 0", delta)
			}
			if delta := signatureRunMeter.Snapshot().Count() - signatureBefore; delta != 0 {
				t.Fatalf("delegated factory reset signature runs: have %d want 0", delta)
			}
			if delta := verifyRunMeter.Snapshot().Count() - verifyBefore; delta != 0 {
				t.Fatalf("delegated factory reset validation-prefix runs: have %d want 0", delta)
			}
			if delta := senderVerifyRunMeter.Snapshot().Count() - senderVerifyBefore; delta != 0 {
				t.Fatalf("delegated factory reset sender VERIFY runs: have %d want 0", delta)
			}
		})
	}
}

func TestFramePoolAllowsStableDeployFactories(t *testing.T) {
	t.Run("custom immutable factory", func(t *testing.T) {
		pool, statedb, config := newTestEnv()
		factory := common.HexToAddress("0x2222222222222222222222222222222222222222")
		statedb.CreateAccount(factory)
		statedb.SetCode(factory, createFactoryCode(approveBothCode), tracing.CodeChangeUnspecified)
		sender := crypto.CreateAddress(factory, statedb.GetNonce(factory))
		tx := newDeployFactoryTestTx(statedb, config, sender, factory, nil)
		if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
			t.Fatalf("custom immutable factory admission failed: %v", err)
		}
	})

	t.Run("EIP-7997 factory", func(t *testing.T) {
		pool, statedb, config := newTestEnv()
		factory := params.DeterministicFactoryAddress
		statedb.CreateAccount(factory)
		statedb.SetNonce(factory, 1, tracing.NonceChangeUnspecified)
		statedb.SetCode(factory, params.DeterministicFactoryCode, tracing.CodeChangeUnspecified)
		initCode := deployFactoryTestInitCode(approveBothCode)
		salt := common.HexToHash("0x8141")
		data := append(append([]byte(nil), salt[:]...), initCode...)
		sender := crypto.CreateAddress2(factory, [32]byte(salt), crypto.Keccak256(initCode))
		tx := newDeployFactoryTestTx(statedb, config, sender, factory, data)
		if err := pool.Add([]*types.Transaction{tx}, false)[0]; err != nil {
			t.Fatalf("EIP-7997 factory admission failed: %v", err)
		}
	})
}

func newDeployFactoryTestTx(statedb *state.StateDB, config *params.ChainConfig, sender, factory common.Address, data []byte) *types.Transaction {
	statedb.CreateAccount(sender)
	statedb.SetBalance(sender, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	frameTx := baseFTX(sender, 0, config)
	frameTx.Frames = []types.Frame{
		{Mode: types.FrameModeDefault, Target: &factory, GasLimit: 60_000, Data: data},
		{Mode: types.FrameModeVerify, Flags: types.FrameFlagApproveScopeMask, GasLimit: 30_000},
	}
	return makeFrameTx(frameTx)
}

func deployFactoryTestInitCode(runtime []byte) []byte {
	initCode := append([]byte{byte(vm.PUSH1) + byte(len(runtime)) - 1}, runtime...)
	return append(initCode,
		byte(vm.PUSH1), 0x00, byte(vm.MSTORE),
		byte(vm.PUSH1), byte(len(runtime)), byte(vm.PUSH1), byte(32-len(runtime)), byte(vm.RETURN),
	)
}
