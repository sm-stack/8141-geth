package vm

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestDefaultCodeUsesFixedSecp256k1SignatureIndex(t *testing.T) {
	target := common.HexToAddress("0x1234")
	fc := &FrameContext{
		Sender:     target,
		Frames:     []types.Frame{{Mode: types.FrameModeVerify, Flags: 3}},
		Signatures: []types.TxSignature{{Scheme: types.SignatureSchemeSecp256k1, Signer: target}},
		FrameIndex: 0,
	}
	if scope, ok := defaultCodeTxSignatureApproveScope(fc, target); !ok || scope != ApproveBoth {
		t.Fatalf("self-pay signature rejected: scope %d, ok %v", scope, ok)
	}

	fc.Frames[0].Flags = 1
	fc.Signatures = append(fc.Signatures, types.TxSignature{Scheme: types.SignatureSchemeSecp256k1, Signer: target})
	if scope, ok := defaultCodeTxSignatureApproveScope(fc, target); !ok || scope != ApprovePayment {
		t.Fatalf("payment signature at index 1 rejected: scope %d, ok %v", scope, ok)
	}
	fc.Signatures[1].Scheme = types.SignatureSchemeP256
	if _, ok := defaultCodeTxSignatureApproveScope(fc, target); ok {
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
	if _, ok := defaultCodeTxSignatureApproveScope(fc, target); ok {
		t.Fatal("unsupported signature scheme accepted")
	}
}
