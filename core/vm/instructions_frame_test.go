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
	"bytes"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func TestFrameOpcodeNames(t *testing.T) {
	tests := map[OpCode]string{
		TXPARAM:       "TXPARAM",
		FRAMEDATALOAD: "FRAMEDATALOAD",
		FRAMEDATACOPY: "FRAMEDATACOPY",
		FRAMEPARAM:    "FRAMEPARAM",
		SIGPARAM:      "SIGPARAM",
	}
	for op, name := range tests {
		if got := op.String(); got != name {
			t.Fatalf("%#x String() = %q, want %q", byte(op), got, name)
		}
		if got, ok := stringToOp[name]; !ok || got != op {
			t.Fatalf("stringToOp[%q] = %v, %t; want %v, true", name, got, ok, op)
		}
	}
	for _, old := range []string{"TXPARAMLOAD", "TXPARAMSIZE", "TXPARAMCOPY"} {
		if op, ok := stringToOp[old]; ok {
			t.Fatalf("old opcode %s still registered as %v", old, op)
		}
	}
}

func TestSigParamWithoutSignaturesHalts(t *testing.T) {
	evm := NewEVM(BlockContext{}, nil, params.TestChainConfig, Config{})
	evm.FrameCtx = &FrameContext{}

	stack := newStackForTesting()
	defer stack.release()
	stack.push(new(uint256.Int).SetUint64(sigParamSigner))
	stack.push(new(uint256.Int).SetUint64(0))

	pc := uint64(0)
	_, err := opSigParam(&pc, evm, &ScopeContext{Memory: NewMemory(), Stack: stack})

	var invalid *ErrInvalidOpCode
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidOpCode, got %v", err)
	}
	if invalid.opcode != SIGPARAM {
		t.Fatalf("invalid opcode: got %s, want %s", invalid.opcode, SIGPARAM)
	}
}

func TestFrameParamStatusOnlyPastFrames(t *testing.T) {
	run := func(frameIndex, currentIndex uint64, results []uint8) (uint256.Int, error) {
		evm := NewEVM(BlockContext{}, nil, params.TestChainConfig, Config{})
		evm.FrameCtx = &FrameContext{
			Frames:       make([]types.Frame, 3),
			FrameIndex:   int(currentIndex),
			FrameResults: results,
		}
		stack := newStackForTesting()
		defer stack.release()
		stack.push(new(uint256.Int).SetUint64(frameParamStatus))
		stack.push(new(uint256.Int).SetUint64(frameIndex))

		pc := uint64(0)
		_, err := opFrameParam(&pc, evm, &ScopeContext{Memory: NewMemory(), Stack: stack})
		if err != nil {
			return uint256.Int{}, err
		}
		return stack.pop(), nil
	}

	got, err := run(0, 2, []uint8{types.FrameReceiptStatusSuccessful, types.FrameReceiptStatusSkipped})
	if err != nil {
		t.Fatalf("past successful status failed: %v", err)
	}
	if !got.Eq(uint256.NewInt(1)) {
		t.Fatalf("past successful status = %d, want 1", got.Uint64())
	}
	got, err = run(1, 2, []uint8{types.FrameReceiptStatusSuccessful, types.FrameReceiptStatusSkipped})
	if err != nil {
		t.Fatalf("past skipped status failed: %v", err)
	}
	if !got.Eq(uint256.NewInt(uint64(types.FrameReceiptStatusSkipped))) {
		t.Fatalf("past skipped status = %d, want %d", got.Uint64(), types.FrameReceiptStatusSkipped)
	}
	for _, tt := range []struct {
		name         string
		frameIndex   uint64
		currentIndex uint64
	}{
		{"current", 1, 1},
		{"future", 2, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := run(tt.frameIndex, tt.currentIndex, []uint8{types.FrameReceiptStatusSuccessful})
			var invalid *ErrInvalidOpCode
			if !errors.As(err, &invalid) {
				t.Fatalf("expected ErrInvalidOpCode, got %v", err)
			}
			if invalid.opcode != FRAMEPARAM {
				t.Fatalf("invalid opcode: got %s, want %s", invalid.opcode, FRAMEPARAM)
			}
		})
	}
}

func TestTxParamKeyedNonceSelectors(t *testing.T) {
	keys := []*uint256.Int{uint256.NewInt(7), uint256.NewInt(11)}
	fc := &FrameContext{
		NonceKeys:     keys,
		NonceSeq:      3,
		LegacyNonce:   19,
		NonceKeysHash: types.ComputeNonceKeysHash(keys),
	}
	if want := common.HexToHash("0x1c206b1cab1a56015ca8c444c1039f73077b99134d3ad0130c05afe9813b586d"); fc.NonceKeysHash != want {
		t.Fatalf("nonce keys hash = %s, want %s", fc.NonceKeysHash, want)
	}
	tests := []struct {
		selector uint64
		want     *uint256.Int
	}{
		{txParamNonce, uint256.NewInt(3)},
		{txParamNonceKey0, uint256.NewInt(7)},
		{txParamLegacyNonce, uint256.NewInt(19)},
		{txParamNonceKeyCount, uint256.NewInt(2)},
		{txParamNonceKeysHash, new(uint256.Int).SetBytes(fc.NonceKeysHash[:])},
	}
	for _, tt := range tests {
		evm := NewEVM(BlockContext{}, nil, params.TestChainConfig, Config{})
		evm.FrameCtx = fc
		stack := newStackForTesting()
		stack.push(new(uint256.Int).SetUint64(tt.selector))
		pc := uint64(0)
		_, err := opTxParam(&pc, evm, &ScopeContext{Memory: NewMemory(), Stack: stack})
		if err != nil {
			stack.release()
			t.Fatalf("TXPARAM(%#x) failed: %v", tt.selector, err)
		}
		got := stack.pop()
		stack.release()
		if !got.Eq(tt.want) {
			t.Fatalf("TXPARAM(%#x) = %x, want %x", tt.selector, got.Bytes32(), tt.want.Bytes32())
		}
	}
}

func TestRecentRootIntrospection(t *testing.T) {
	if RECENTROOTREFLOAD != 0xb5 || RECENTROOTREFLOAD.String() != "RECENTROOTREFLOAD" {
		t.Fatalf("unexpected recent-root opcode assignment: %#x %s", RECENTROOTREFLOAD, RECENTROOTREFLOAD)
	}
	if op := pragueInstructionSet[RECENTROOTREFLOAD]; op == nil || op.undefined || op.constantGas != GasQuickStep {
		t.Fatalf("recent-root opcode not enabled with gas 3: %#v", op)
	}
	ref := types.RecentRootRef{SourceID: common.HexToHash("0x1234"), Slot: 77, Root: common.HexToHash("0x5678")}
	fc := &FrameContext{RecentRootRefs: []types.RecentRootRef{ref}}
	evm := NewEVM(BlockContext{}, nil, params.TestChainConfig, Config{})
	evm.FrameCtx = fc

	stack := newStackForTesting()
	stack.push(uint256.NewInt(txParamRecentRootRefCount))
	pc := uint64(0)
	if _, err := opTxParam(&pc, evm, &ScopeContext{Memory: NewMemory(), Stack: stack}); err != nil {
		t.Fatal(err)
	}
	gotCount := stack.pop()
	if got := gotCount.Uint64(); got != 1 {
		t.Fatalf("reference count = %d, want 1", got)
	}
	stack.release()

	fields := []struct {
		field uint64
		want  *uint256.Int
	}{
		{0, new(uint256.Int).SetBytes(ref.SourceID[:])},
		{1, uint256.NewInt(ref.Slot)},
		{2, new(uint256.Int).SetBytes(ref.Root[:])},
	}
	for _, tt := range fields {
		stack := newStackForTesting()
		stack.push(uint256.NewInt(tt.field))
		stack.push(uint256.NewInt(0))
		if _, err := opRecentRootRefLoad(&pc, evm, &ScopeContext{Memory: NewMemory(), Stack: stack}); err != nil {
			stack.release()
			t.Fatalf("field %d: %v", tt.field, err)
		}
		if got := stack.pop(); !got.Eq(tt.want) {
			stack.release()
			t.Fatalf("field %d = %x, want %x", tt.field, got.Bytes32(), tt.want.Bytes32())
		}
		stack.release()
	}
	for _, pair := range [][2]uint64{{1, 0}, {0, 3}} {
		stack := newStackForTesting()
		stack.push(uint256.NewInt(pair[1]))
		stack.push(uint256.NewInt(pair[0]))
		_, err := opRecentRootRefLoad(&pc, evm, &ScopeContext{Memory: NewMemory(), Stack: stack})
		stack.release()
		if err == nil {
			t.Fatalf("index/field %v accepted", pair)
		}
	}
}

func TestSigParamReturnsSignatureMetadata(t *testing.T) {
	signer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	msg := common.HexToHash("0x1234").Bytes()
	sigBytes := make([]byte, 65)
	evm := NewEVM(BlockContext{}, nil, params.TestChainConfig, Config{})
	evm.FrameCtx = &FrameContext{
		Signatures: []types.TxSignature{
			{
				Scheme:    types.SignatureSchemeSecp256k1,
				Signer:    signer,
				Msg:       msg,
				Signature: sigBytes,
			},
		},
	}

	tests := []struct {
		name  string
		param uint64
		want  *uint256.Int
	}{
		{"signer", sigParamSigner, new(uint256.Int).SetBytes(signer.Bytes())},
		{"scheme", sigParamScheme, new(uint256.Int).SetUint64(uint64(types.SignatureSchemeSecp256k1))},
		{"msg", sigParamMsg, new(uint256.Int).SetBytes(msg)},
		{"signature_len", sigParamSignatureLen, new(uint256.Int).SetUint64(uint64(len(sigBytes)))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stack := newStackForTesting()
			defer stack.release()
			stack.push(new(uint256.Int).SetUint64(tt.param))
			stack.push(new(uint256.Int).SetUint64(0))

			pc := uint64(0)
			if _, err := opSigParam(&pc, evm, &ScopeContext{Memory: NewMemory(), Stack: stack}); err != nil {
				t.Fatalf("opSigParam failed: %v", err)
			}
			if got := stack.pop(); !got.Eq(tt.want) {
				t.Fatalf("got %x, want %x", got.Bytes32(), tt.want.Bytes32())
			}
		})
	}
}

func TestSigParamArbitrarySignatureCopy(t *testing.T) {
	evm := NewEVM(BlockContext{}, nil, params.TestChainConfig, Config{})
	evm.FrameCtx = &FrameContext{Signatures: []types.TxSignature{{
		Scheme:    types.SignatureSchemeArbitrary,
		Signature: []byte{0x11, 0x22, 0x33},
	}}}
	stack := newStackForTesting()
	defer stack.release()
	stack.push(uint256.NewInt(0))
	stack.push(uint256.NewInt(1))
	stack.push(uint256.NewInt(4))
	stack.push(uint256.NewInt(sigParamSignature))
	stack.push(uint256.NewInt(0))
	memory := NewMemory()
	memory.Resize(4)
	pc := uint64(0)
	if _, err := opSigParam(&pc, evm, &ScopeContext{Memory: memory, Stack: stack}); err != nil {
		t.Fatalf("arbitrary signature copy failed: %v", err)
	}
	if got := memory.GetCopy(0, 4); !bytes.Equal(got, []byte{0x22, 0x33, 0x00, 0x00}) {
		t.Fatalf("copied bytes %x", got)
	}
}

func TestSigParamArbitrarySignerHalts(t *testing.T) {
	evm := NewEVM(BlockContext{}, nil, params.TestChainConfig, Config{})
	evm.FrameCtx = &FrameContext{Signatures: []types.TxSignature{{Scheme: types.SignatureSchemeArbitrary}}}
	stack := newStackForTesting()
	defer stack.release()
	stack.push(uint256.NewInt(sigParamSigner))
	stack.push(uint256.NewInt(0))
	pc := uint64(0)
	if _, err := opSigParam(&pc, evm, &ScopeContext{Memory: NewMemory(), Stack: stack}); err == nil {
		t.Fatal("arbitrary signer introspection succeeded")
	}
}
