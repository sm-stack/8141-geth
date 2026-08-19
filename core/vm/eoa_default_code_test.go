package vm

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestEvaluateDefaultCodeVerify(t *testing.T) {
	target := common.HexToAddress("0x1234")
	frame := types.Frame{Mode: types.FrameModeVerify, Flags: ApproveBoth}
	signatures := []types.TxSignature{{Scheme: types.SignatureSchemeSecp256k1, Signer: target}}

	scope, remaining, err := EvaluateDefaultCodeVerify(frame, signatures, target, target, NewFrameGasBudget(defaultCodeBaseGas, 0))
	if err != nil || scope != ApproveBoth || remaining.ExecutionGas != 0 {
		t.Fatalf("default-code evaluation: scope %d, remaining %d, error %v", scope, remaining.ExecutionGas, err)
	}
	evm := new(EVM)
	evm.TxContext.FrameCtx = &FrameContext{Sender: target, Frames: []types.Frame{frame}, Signatures: signatures}
	if _, executed, err := ExecuteDefaultCodeWithGasBudget(evm, common.Address{}, target, nil, NewFrameGasBudget(defaultCodeBaseGas, 0), types.FrameModeVerify); err != nil || executed != remaining || evm.TxContext.ApproveScope != scope {
		t.Fatalf("default-code execution differs from direct evaluation: scope %d, remaining %v, error %v", evm.TxContext.ApproveScope, executed, err)
	}
	if _, remaining, err = EvaluateDefaultCodeVerify(frame, signatures, target, target, NewFrameGasBudget(defaultCodeBaseGas-1, 0)); !errors.Is(err, ErrOutOfGas) || remaining.ExecutionGas != 0 {
		t.Fatalf("underfunded default-code evaluation: remaining %d, error %v", remaining.ExecutionGas, err)
	}
}

func TestDefaultCodeUsesFixedSecp256k1SignatureIndex(t *testing.T) {
	target := common.HexToAddress("0x1234")
	fc := &FrameContext{
		Sender:     target,
		Frames:     []types.Frame{{Mode: types.FrameModeVerify, Flags: 3}},
		Signatures: []types.TxSignature{{Scheme: types.SignatureSchemeSecp256k1, Signer: target}},
		FrameIndex: 0,
	}
	if scope, ok := defaultCodeTxSignatureApproveScopeForFrame(fc.Frames[0], fc.Signatures, fc.Sender, target); !ok || scope != ApproveBoth {
		t.Fatalf("self-pay signature rejected: scope %d, ok %v", scope, ok)
	}

	fc.Frames[0].Flags = 1
	fc.Signatures = append(fc.Signatures, types.TxSignature{Scheme: types.SignatureSchemeSecp256k1, Signer: target})
	if scope, ok := defaultCodeTxSignatureApproveScopeForFrame(fc.Frames[0], fc.Signatures, fc.Sender, target); !ok || scope != ApprovePayment {
		t.Fatalf("payment signature at index 1 rejected: scope %d, ok %v", scope, ok)
	}
	fc.Signatures[1].Scheme = types.SignatureSchemeP256
	if _, ok := defaultCodeTxSignatureApproveScopeForFrame(fc.Frames[0], fc.Signatures, fc.Sender, target); ok {
		t.Fatal("P256 signature accepted by default code")
	}
}

func TestDefaultCodeRejectsUnsupportedSignatureScheme(t *testing.T) {
	target := common.HexToAddress("0x1234")
	fc := &FrameContext{
		Sender:     target,
		Frames:     []types.Frame{{Mode: types.FrameModeVerify, Flags: 3}},
		Signatures: []types.TxSignature{{Scheme: types.SignatureSchemeArbitrary}},
		FrameIndex: 0,
	}
	if _, ok := defaultCodeTxSignatureApproveScopeForFrame(fc.Frames[0], fc.Signatures, fc.Sender, target); ok {
		t.Fatal("unsupported signature scheme accepted")
	}
}
