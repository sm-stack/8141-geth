// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framecorpus

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

func TestPairingQualification(t *testing.T) {
	input := PairingInput(1)
	if len(input) != PairingInputSize {
		t.Fatalf("pairing input length = %d, want %d", len(input), PairingInputSize)
	}
	precompile := vm.PrecompiledContractsOsaka[common.BytesToAddress([]byte{PairingAddress})]
	if gas := precompile.RequiredGas(input); gas != PairingGas {
		t.Fatalf("four-pair gas = %d, want %d", gas, PairingGas)
	}
	output, err := precompile.Run(input)
	if err != nil || !bytes.Equal(output, common.LeftPadBytes([]byte{1}, 32)) {
		t.Fatalf("four-pair output = %x, %v", output, err)
	}
	if bytes.Equal(input, PairingInput(2)) {
		t.Fatal("transaction variants produced identical pairing inputs")
	}
}

func TestPureFirstCorpus(t *testing.T) {
	assertOpcodeOrder(t, PairingPureFirst, vm.STATICCALL, vm.SLOAD)
}

func TestStateFirstCorpus(t *testing.T) {
	assertOpcodeOrder(t, PairingStateFirst, vm.SLOAD, vm.STATICCALL)
}

func TestLateBranchCorpus(t *testing.T) {
	assertOpcodeOrder(t, CheapNowExpensiveLater, vm.SLOAD, vm.STATICCALL)
}

func TestCorpusQualification(t *testing.T) {
	genesis := GenesisCode()
	for _, name := range Names() {
		workload, err := WorkloadFor(name, 7)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if workload.Sender == (common.Address{}) || len(workload.Code) == 0 || !bytes.Equal(genesis[workload.Sender], workload.Code) {
			t.Fatalf("%s: incomplete or mismatched genesis workload", name)
		}
		if name == PairingStateSelectsInput && len(workload.Data) != 2*PairingInputSize {
			t.Fatalf("%s calldata length = %d", name, len(workload.Data))
		}
		if name != PureEVMBeforeState && name != PairingStateSelectsInput && len(workload.Data) != PairingInputSize {
			t.Fatalf("%s calldata length = %d", name, len(workload.Data))
		}
	}
	if _, err := WorkloadFor("unknown", 1); err == nil {
		t.Fatal("unknown corpus accepted")
	}
}

func assertOpcodeOrder(t *testing.T, name string, first, second vm.OpCode) {
	t.Helper()
	workload, err := WorkloadFor(name, 1)
	if err != nil {
		t.Fatal(err)
	}
	firstPC := bytes.IndexByte(workload.Code, byte(first))
	secondPC := bytes.IndexByte(workload.Code, byte(second))
	if firstPC < 0 || secondPC < 0 || firstPC >= secondPC {
		t.Fatalf("%s opcode order: %s at %d, %s at %d", name, first, firstPC, second, secondPC)
	}
}
