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
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func TestSigParamWithoutSignaturesHalts(t *testing.T) {
	evm := NewEVM(BlockContext{}, nil, params.TestChainConfig, Config{})
	evm.FrameCtx = &FrameContext{}

	stack := newstack()
	defer returnStack(stack)
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
