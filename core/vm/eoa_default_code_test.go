package vm

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestDefaultCodeAcceptsProtocolSupportedSignatures(t *testing.T) {
	target := common.HexToAddress("0x1234")
	for _, scheme := range []uint8{types.SignatureSchemeSecp256k1, types.SignatureSchemeP256} {
		fc := &FrameContext{
			Sender:     target,
			Frames:     []types.Frame{{Mode: types.FrameModeVerify, Flags: 3}},
			Signatures: []types.TxSignature{{Scheme: scheme, Signer: target}},
			FrameIndex: 0,
		}
		if scope, ok := defaultCodeTxSignatureApproveScope(fc, target); !ok || scope != ApproveBoth {
			t.Fatalf("scheme %d rejected: scope %d, ok %v", scheme, scope, ok)
		}
	}
}

func TestDefaultCodeRejectsUnsupportedSignatureScheme(t *testing.T) {
	target := common.HexToAddress("0x1234")
	fc := &FrameContext{
		Sender:     target,
		Frames:     []types.Frame{{Mode: types.FrameModeVerify, Flags: 3}},
		Signatures: []types.TxSignature{{Scheme: 2, Signer: target}},
		FrameIndex: 0,
	}
	if _, ok := defaultCodeTxSignatureApproveScope(fc, target); ok {
		t.Fatal("unsupported signature scheme accepted")
	}
}
