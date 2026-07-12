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

package types

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// testFrameTx returns a FrameTx with some default test values.
func testFrameTx() *FrameTx {
	target := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	signer := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	explicitMsg := common.Hash{0x01}.Bytes()
	return &FrameTx{
		ChainID:    uint256.NewInt(1),
		NonceKeys:  []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:   42,
		Sender:     common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		GasTipCap:  uint256.NewInt(1_000_000_000),  // 1 gwei
		GasFeeCap:  uint256.NewInt(30_000_000_000), // 30 gwei
		BlobFeeCap: uint256.NewInt(0),
		BlobHashes: []common.Hash{},
		Frames: []Frame{
			{Mode: FrameModeVerify, Target: nil, GasLimit: 100_000, Data: []byte("signature")},
			{Mode: FrameModeSender, Flags: 1, Target: &target, GasLimit: 200_000, Value: uint256.NewInt(123), Data: []byte("calldata")},
		},
		Signatures: []TxSignature{
			{Scheme: SignatureSchemeSecp256k1, Signer: signer, Msg: nil, Signature: bytes.Repeat([]byte{0x11}, 65)},
			{Scheme: SignatureSchemeP256, Signer: signer, Msg: explicitMsg, Signature: bytes.Repeat([]byte{0x22}, 128)},
		},
		RecentRootRefs: []RecentRootRef{{
			SourceID: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			Slot:     9,
			Root:     common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		}},
	}
}

func testAddressPtr(addr common.Address) *common.Address {
	return &addr
}

func testVRS(sig []byte) []byte {
	vrs := make([]byte, signatureLengthSecp256k1)
	vrs[0] = sig[64]
	copy(vrs[1:33], sig[0:32])
	copy(vrs[33:65], sig[32:64])
	return vrs
}

func testFrameTxSigHashVector() *FrameTx {
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	return &FrameTx{
		ChainID:    uint256.NewInt(1),
		NonceKeys:  []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:   7,
		Sender:     common.HexToAddress("0x1111111111111111111111111111111111111111"),
		GasTipCap:  uint256.NewInt(3),
		GasFeeCap:  uint256.NewInt(100),
		BlobFeeCap: uint256.NewInt(0),
		BlobHashes: []common.Hash{common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")},
		Frames: []Frame{
			{Mode: FrameModeVerify, Flags: 3, GasLimit: 50000, Data: []byte{0xaa, 0xbb}},
			{Mode: FrameModeSender, Flags: FrameFlagAtomicBatch, Target: &target, GasLimit: 70000, Value: uint256.NewInt(12345), Data: []byte{0xcc, 0xdd, 0xee}},
			{Mode: FrameModeDefault, Target: &target, GasLimit: 30000, Data: []byte{0x99}},
		},
		Signatures: []TxSignature{
			{
				Scheme:    SignatureSchemeSecp256k1,
				Signer:    common.HexToAddress("0x3333333333333333333333333333333333333333"),
				Signature: common.Hex2Bytes("0011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222"),
			},
			{
				Scheme:    SignatureSchemeP256,
				Signer:    common.HexToAddress("0x4444444444444444444444444444444444444444"),
				Msg:       common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").Bytes(),
				Signature: common.Hex2Bytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
			},
		},
		RecentRootRefs: []RecentRootRef{{
			SourceID: common.HexToHash("0x0101010101010101010101010101010101010101010101010101010101010101"),
			Slot:     9,
			Root:     common.HexToHash("0x0202020202020202020202020202020202020202020202020202020202020202"),
		}},
	}
}

func expectedFrameTxCalldataGas(ftx *FrameTx) uint64 {
	var tokens uint64
	for _, chunk := range [][]byte{ftx.rlpFramesData(), ftx.rlpRecentRootRefsData(), ftx.rlpSignaturesData()} {
		for _, b := range chunk {
			if b == 0 {
				tokens++
			} else {
				tokens += params.TxTokenPerNonZeroByte
			}
		}
	}
	return tokens * params.TxCostFloorPerToken
}

func expectedFrameTxSignatureGas(t *testing.T, ftx *FrameTx) uint64 {
	t.Helper()
	var gas uint64
	for _, sig := range ftx.Signatures {
		switch sig.Scheme {
		case SignatureSchemeSecp256k1:
			gas += params.SigGasSecp256k1
		case SignatureSchemeP256:
			gas += params.SigGasP256
		default:
			t.Fatalf("unsupported signature scheme %d", sig.Scheme)
		}
	}
	return gas
}

func expectedFrameTxIntrinsicGas(t *testing.T, ftx *FrameTx) uint64 {
	t.Helper()
	gas := params.TxGasEIP8141 +
		uint64(len(ftx.Frames))*params.FrameTxPerFrameGas +
		expectedFrameTxCalldataGas(ftx) +
		expectedFrameTxSignatureGas(t, ftx)
	if len(ftx.RecentRootRefs) > 0 {
		gas += params.RecentRootBaseGas + uint64(len(ftx.RecentRootRefs))*params.RecentRootPerRefGas
	}
	return gas
}

func TestFrameTxType(t *testing.T) {
	ftx := testFrameTx()
	if ftx.txType() != FrameTxType {
		t.Errorf("txType() = %d, want %d", ftx.txType(), FrameTxType)
	}
	if FrameTxType != 0x06 {
		t.Errorf("FrameTxType = %d, want 0x06", FrameTxType)
	}
}

func TestFrameTxTotalGas(t *testing.T) {
	ftx := testFrameTx()
	want := expectedFrameTxIntrinsicGas(t, ftx)
	for _, frame := range ftx.Frames {
		want += frame.GasLimit
	}
	if got := ftx.TotalGas(); got != want {
		t.Errorf("TotalGas() = %d, want %d", got, want)
	}
}

func TestFrameTxAccessors(t *testing.T) {
	ftx := testFrameTx()
	if ftx.chainID().Uint64() != 1 {
		t.Errorf("chainID() = %d, want 1", ftx.chainID().Uint64())
	}
	if ftx.nonce() != 42 {
		t.Errorf("nonce() = %d, want 42", ftx.nonce())
	}
	if ftx.accessList() != nil {
		t.Error("accessList() should be nil")
	}
	if ftx.data() != nil {
		t.Error("data() should be nil")
	}
	if ftx.to() != nil {
		t.Error("to() should be nil")
	}
	if ftx.value().Sign() != 0 {
		t.Error("value() should be zero")
	}
	if ftx.gas() != ftx.TotalGas() {
		t.Errorf("gas() = %d, want %d", ftx.gas(), ftx.TotalGas())
	}
	if ftx.gasFeeCap().Uint64() != 30_000_000_000 {
		t.Errorf("gasFeeCap() = %d, want 30000000000", ftx.gasFeeCap().Uint64())
	}
	if ftx.gasTipCap().Uint64() != 1_000_000_000 {
		t.Errorf("gasTipCap() = %d, want 1000000000", ftx.gasTipCap().Uint64())
	}
}

func TestFrameTxSignatureIsZero(t *testing.T) {
	ftx := testFrameTx()
	v, r, s := ftx.rawSignatureValues()
	if v.Sign() != 0 || r.Sign() != 0 || s.Sign() != 0 {
		t.Error("rawSignatureValues() should return zero values for frame tx")
	}
}

func TestFrameTxCopy(t *testing.T) {
	ftx := testFrameTx()
	cpy := ftx.copy().(*FrameTx)

	// Verify deep copy independence.
	cpy.NonceSeq = 99
	if ftx.NonceSeq == cpy.NonceSeq {
		t.Error("copy() did not deep copy Nonce")
	}
	cpy.NonceKeys[0].SetUint64(9)
	if ftx.NonceKeys[0].Eq(cpy.NonceKeys[0]) {
		t.Error("copy() did not deep copy NonceKeys")
	}

	cpy.Frames[0].Data[0] = 0xff
	if ftx.Frames[0].Data[0] == 0xff {
		t.Error("copy() did not deep copy frame Data")
	}

	cpy.Frames[1].Value.SetUint64(999)
	if ftx.Frames[1].Value.Uint64() == 999 {
		t.Error("copy() did not deep copy frame Value")
	}

	cpy.Signatures[0].Signature[0] = 0xff
	if ftx.Signatures[0].Signature[0] == 0xff {
		t.Error("copy() did not deep copy signature bytes")
	}

	cpy.Signatures[1].Msg[0] = 0xff
	if ftx.Signatures[1].Msg[0] == 0xff {
		t.Error("copy() did not deep copy signature msg")
	}

	cpy.ChainID.SetUint64(999)
	if ftx.ChainID.Uint64() == 999 {
		t.Error("copy() did not deep copy ChainID")
	}
}

func TestFrameTxSigHashCommitsVerifyDataAndElidesEmptySignatureData(t *testing.T) {
	ftx := testFrameTx()
	hash1 := ftx.sigHash(ftx.chainID())

	// VERIFY frame data is now committed by the signature hash.
	ftx2 := testFrameTx()
	ftx2.Frames[0].Data = []byte("different_signature")
	hash2 := ftx2.sigHash(ftx2.chainID())
	if hash1 == hash2 {
		t.Error("sigHash should differ when VERIFY frame data changes")
	}

	// Empty-msg signatures elide raw signature bytes.
	ftx3 := testFrameTx()
	ftx3.Signatures[0].Signature = bytes.Repeat([]byte{0x33}, 65)
	hash3 := ftx3.sigHash(ftx3.chainID())
	if hash1 != hash3 {
		t.Error("sigHash should be identical when only empty-msg raw signature bytes differ")
	}

	// Explicit-msg signatures commit raw signature bytes.
	ftx4 := testFrameTx()
	ftx4.Signatures[1].Signature = bytes.Repeat([]byte{0x44}, 128)
	hash4 := ftx4.sigHash(ftx4.chainID())
	if hash1 == hash4 {
		t.Error("sigHash should differ when explicit-msg raw signature bytes change")
	}
}

func TestFrameTxSignatureGasConstants(t *testing.T) {
	if params.FrameTxPerFrameGas != 475 {
		t.Fatalf("FrameTxPerFrameGas = %d, want 475", params.FrameTxPerFrameGas)
	}
	if params.SigGasSecp256k1 != 2800 {
		t.Fatalf("SigGasSecp256k1 = %d, want 2800", params.SigGasSecp256k1)
	}
	if params.SigGasP256 != 6700 {
		t.Fatalf("SigGasP256 = %d, want 6700", params.SigGasP256)
	}
}

func TestFrameTxSignatureGas(t *testing.T) {
	ftx := testFrameTx()
	want := expectedFrameTxSignatureGas(t, ftx)
	got, err := ftx.SignatureGas()
	if err != nil {
		t.Fatalf("SignatureGas() unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("SignatureGas() = %d, want %d", got, want)
	}

	ftx.Signatures = append(ftx.Signatures, TxSignature{Scheme: 0xff})
	if _, err := ftx.SignatureGas(); err == nil {
		t.Fatal("SignatureGas() accepted unsupported scheme")
	}
}

func TestFrameTxSigHashVector(t *testing.T) {
	const (
		wantSigHash = "0xc0aeaa116efe492bd25f0648a49964062170aa3f911dbcdb61cb888945a1bde4"
		wantRawTx   = "0x06f901ed01c18007941111111111111111111111111111111111111111f84cca01038082c3508082aabbe202049422222222222222222222222222222222222222228301117082303983ccddeedd8080942222222222222222222222222222222222222222827530808199f90117f85a8094333333333333333333333333333333333333333380b8410011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222f8b901944444444444444444444444444444444444444444a0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab880bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee036480e1a00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20f845f843a0010101010101010101010101010101010101010101010101010101010101010109a00202020202020202020202020202020202020202020202020202020202020202"
	)
	tx := testFrameTxSigHashVector()
	if got, want := tx.SigHash(tx.chainID()).Hex(), wantSigHash; got != want {
		t.Fatalf("SigHash = %s, want %s", got, want)
	}
	typed, err := NewTx(tx).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if got, want := hexutil.Encode(typed), wantRawTx; got != want {
		t.Fatalf("raw typed tx = %s, want %s", got, want)
	}
}

func TestFrameTxRLPRoundTrip(t *testing.T) {
	ftx := testFrameTx()
	tx := NewTx(ftx)

	// Encode.
	var buf bytes.Buffer
	if err := tx.EncodeRLP(&buf); err != nil {
		t.Fatalf("EncodeRLP failed: %v", err)
	}

	// Decode.
	var decoded Transaction
	if err := rlp.DecodeBytes(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("DecodeRLP failed: %v", err)
	}

	// Verify type.
	if decoded.Type() != FrameTxType {
		t.Errorf("decoded type = %d, want %d", decoded.Type(), FrameTxType)
	}
	// Verify nonce.
	if decoded.Nonce() != 42 {
		t.Errorf("decoded nonce = %d, want 42", decoded.Nonce())
	}
	// Verify sender.
	if decoded.FrameSender() != ftx.Sender {
		t.Errorf("decoded sender = %s, want %s", decoded.FrameSender(), ftx.Sender)
	}
	// Verify frames.
	frames := decoded.Frames()
	if len(frames) != 2 {
		t.Fatalf("decoded frames = %d, want 2", len(frames))
	}
	if frames[0].Mode != FrameModeVerify {
		t.Errorf("frame[0].Mode = %d, want %d", frames[0].Mode, FrameModeVerify)
	}
	if frames[1].Mode != FrameModeSender {
		t.Errorf("frame[1].Mode = %d, want %d", frames[1].Mode, FrameModeSender)
	}
	if frames[1].Flags != 1 {
		t.Errorf("frame[1].Flags = %d, want 1", frames[1].Flags)
	}
	if frames[1].Value == nil || frames[1].Value.Uint64() != 123 {
		t.Errorf("frame[1].Value = %v, want 123", frames[1].Value)
	}
	if !bytes.Equal(frames[1].Data, []byte("calldata")) {
		t.Errorf("frame[1].Data = %x, want 'calldata'", frames[1].Data)
	}
	ftxDecoded := decoded.GetFrameTx()
	if len(ftxDecoded.Signatures) != 2 {
		t.Fatalf("decoded signatures = %d, want 2", len(ftxDecoded.Signatures))
	}
	if ftxDecoded.Signatures[0].Scheme != SignatureSchemeSecp256k1 {
		t.Errorf("signature[0].Scheme = %d, want %d", ftxDecoded.Signatures[0].Scheme, SignatureSchemeSecp256k1)
	}
	if !bytes.Equal(ftxDecoded.Signatures[1].Msg, ftx.Signatures[1].Msg) {
		t.Errorf("signature[1].Msg = %x, want %x", ftxDecoded.Signatures[1].Msg, ftx.Signatures[1].Msg)
	}
}

func TestFrameTxMarshalBinaryRoundTrip(t *testing.T) {
	ftx := testFrameTx()
	tx := NewTx(ftx)

	// MarshalBinary.
	enc, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// First byte should be FrameTxType.
	if enc[0] != FrameTxType {
		t.Errorf("first byte = 0x%02x, want 0x%02x", enc[0], FrameTxType)
	}

	// UnmarshalBinary.
	var decoded Transaction
	if err := decoded.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if decoded.Type() != FrameTxType {
		t.Errorf("decoded type = %d, want %d", decoded.Type(), FrameTxType)
	}
	if decoded.Nonce() != 42 {
		t.Errorf("decoded nonce = %d, want 42", decoded.Nonce())
	}
}

func TestFrameTxBlobFields(t *testing.T) {
	ftx := testFrameTx()
	ftx.BlobFeeCap = uint256.NewInt(100)
	ftx.BlobHashes = []common.Hash{
		common.HexToHash("0x01"),
		common.HexToHash("0x02"),
	}

	tx := NewTx(ftx)

	if tx.BlobGasFeeCap().Uint64() != 100 {
		t.Errorf("BlobGasFeeCap = %d, want 100", tx.BlobGasFeeCap().Uint64())
	}
	if len(tx.BlobHashes()) != 2 {
		t.Errorf("BlobHashes len = %d, want 2", len(tx.BlobHashes()))
	}
	wantBlobGas := uint64(2 * params.BlobTxBlobGasPerBlob)
	if tx.BlobGas() != wantBlobGas {
		t.Errorf("BlobGas = %d, want %d", tx.BlobGas(), wantBlobGas)
	}
}

func TestFrameTxNilTarget(t *testing.T) {
	ftx := testFrameTx()
	// First frame has nil target (meaning tx.sender).
	if ftx.Frames[0].Target != nil {
		t.Error("frame[0].Target should be nil")
	}

	// Verify deep copy preserves nil target.
	cpy := ftx.copy().(*FrameTx)
	if cpy.Frames[0].Target != nil {
		t.Error("copy frame[0].Target should still be nil")
	}
}

func TestFrameTxTransactionAccessors(t *testing.T) {
	ftx := testFrameTx()
	tx := NewTx(ftx)

	// Frame-specific accessors.
	if tx.FrameSender() != ftx.Sender {
		t.Errorf("FrameSender() = %s, want %s", tx.FrameSender(), ftx.Sender)
	}
	if len(tx.Frames()) != 2 {
		t.Errorf("Frames() len = %d, want 2", len(tx.Frames()))
	}

	// Generic accessors.
	if tx.To() != nil {
		t.Error("To() should be nil for frame tx")
	}
	if tx.Value().Sign() != 0 {
		t.Error("Value() should be zero for frame tx")
	}
	if tx.Gas() != ftx.TotalGas() {
		t.Errorf("Gas() = %d, want %d", tx.Gas(), ftx.TotalGas())
	}

	// Non-frame tx should return zero FrameSender.
	legacyTx := NewTx(&LegacyTx{Nonce: 1})
	if (legacyTx.FrameSender() != common.Address{}) {
		t.Error("FrameSender() on legacy tx should be zero address")
	}
	if legacyTx.Frames() != nil {
		t.Error("Frames() on legacy tx should be nil")
	}
}

func TestFrameTxSigner(t *testing.T) {
	ftx := testFrameTx()
	tx := NewTx(ftx)
	signer := NewPragueSigner(ftx.chainID())

	// Sender should return the explicit sender from the tx.
	sender, err := Sender(signer, tx)
	if err != nil {
		t.Fatalf("Sender failed: %v", err)
	}
	if sender != ftx.Sender {
		t.Errorf("Sender = %s, want %s", sender, ftx.Sender)
	}

	// Hash should work.
	hash := signer.Hash(tx)
	if hash == (common.Hash{}) {
		t.Error("Hash should not be zero")
	}

	// SignatureValues should return zero values.
	r, s, v, err := signer.SignatureValues(tx, nil)
	if err != nil {
		t.Fatalf("SignatureValues failed: %v", err)
	}
	if r.Sign() != 0 || s.Sign() != 0 || v.Sign() != 0 {
		t.Error("SignatureValues should return zeros for frame tx")
	}
}

func TestFrameDecodeRLPRejectsInvalidTargetLength(t *testing.T) {
	tests := []int{1, common.AddressLength - 1, common.AddressLength + 1, 32}
	for _, n := range tests {
		payload, err := rlp.EncodeToBytes([]any{
			uint8(FrameModeDefault),
			uint8(0),
			bytes.Repeat([]byte{0x11}, n),
			uint64(1),
			uint256.NewInt(0),
			[]byte{0x01},
		})
		if err != nil {
			t.Fatalf("failed to encode frame with target len %d: %v", n, err)
		}
		var frame Frame
		err = rlp.DecodeBytes(payload, &frame)
		if err == nil {
			t.Fatalf("expected decode error for target len %d, got nil", n)
		}
		if !strings.Contains(err.Error(), "invalid frame target length") {
			t.Fatalf("unexpected error for target len %d: %v", n, err)
		}
	}
}

func TestFrameDecodeRLPResetsNilTarget(t *testing.T) {
	target := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	frame := Frame{Target: &target}

	payload, err := rlp.EncodeToBytes([]any{
		uint8(FrameModeVerify),
		uint8(0),
		[]byte{},
		uint64(100),
		uint256.NewInt(0),
		[]byte("sig"),
	})
	if err != nil {
		t.Fatalf("failed to encode frame payload: %v", err)
	}
	if err := rlp.DecodeBytes(payload, &frame); err != nil {
		t.Fatalf("failed to decode frame payload: %v", err)
	}
	if frame.Target != nil {
		t.Fatalf("expected nil target, got %v", *frame.Target)
	}
}

// TestFrameTxTotalGasOverflow verifies that TotalGas() clamps to math.MaxUint64
// rather than wrapping around when the sum of frame gas limits overflows uint64.
func TestFrameTxTotalGasOverflow(t *testing.T) {
	// Frame 1: MaxUint64 - 100, Frame 2: 200 → sum overflows uint64.
	ftx := &FrameTx{
		ChainID:    uint256.NewInt(1),
		Sender:     common.Address{},
		GasTipCap:  uint256.NewInt(0),
		GasFeeCap:  uint256.NewInt(0),
		BlobFeeCap: uint256.NewInt(0),
		Frames: []Frame{
			{Mode: FrameModeDefault, GasLimit: math.MaxUint64 - 100},
			{Mode: FrameModeDefault, GasLimit: 200},
		},
	}
	if got := ftx.TotalGas(); got != math.MaxUint64 {
		t.Errorf("TotalGas() with overflow = %d, want math.MaxUint64 (%d)", got, uint64(math.MaxUint64))
	}
}

func TestFrameTxIntrinsicGas(t *testing.T) {
	ftx := testFrameTx()
	want := expectedFrameTxIntrinsicGas(t, ftx)
	got, err := ftx.IntrinsicGas()
	if err != nil {
		t.Fatalf("IntrinsicGas() unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("IntrinsicGas() = %d, want %d", got, want)
	}
}

func TestFrameTxRecentRootIntrinsicGas(t *testing.T) {
	withRef := testFrameTx()
	withoutRef := withRef.copy().(*FrameTx)
	withoutRef.RecentRootRefs = nil
	withFixed, err := withRef.fixedGas()
	if err != nil {
		t.Fatal(err)
	}
	withoutFixed, err := withoutRef.fixedGas()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := withFixed-withoutFixed, params.RecentRootBaseGas+params.RecentRootPerRefGas; got != want {
		t.Fatalf("one-reference fixed gas delta = %d, want %d", got, want)
	}
	second := withRef.RecentRootRefs[0]
	second.Slot++
	withRef.RecentRootRefs = append(withRef.RecentRootRefs, second)
	twoFixed, err := withRef.fixedGas()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := twoFixed-withFixed, params.RecentRootPerRefGas; got != want {
		t.Fatalf("second-reference fixed gas delta = %d, want %d", got, want)
	}
}

// TestFrameTxCalldataGas verifies CalldataGas() returns the EIP-7623 token cost
// of the RLP-encoded frames and signatures.
func TestFrameTxCalldataGas(t *testing.T) {
	// Normal tx with frame data: should return a positive gas value with no error.
	ftx := testFrameTx()
	gas, err := ftx.CalldataGas()
	if err != nil {
		t.Fatalf("CalldataGas() unexpected error: %v", err)
	}
	if gas == 0 {
		t.Error("CalldataGas() returned 0 for a tx with non-empty frame data")
	}
	if want := expectedFrameTxCalldataGas(ftx); gas != want {
		t.Fatalf("CalldataGas() = %d, want %d", gas, want)
	}
	ftxNoSignatures := ftx.copy().(*FrameTx)
	ftxNoSignatures.Signatures = nil
	noSigGas, err := ftxNoSignatures.CalldataGas()
	if err != nil {
		t.Fatalf("CalldataGas() without signatures unexpected error: %v", err)
	}
	if gas <= noSigGas {
		t.Errorf("CalldataGas() with signatures = %d, want > without signatures %d", gas, noSigGas)
	}

	// Empty frames list: should still return (value, nil).
	ftxEmpty := &FrameTx{
		ChainID:    uint256.NewInt(1),
		Sender:     common.Address{},
		GasTipCap:  uint256.NewInt(0),
		GasFeeCap:  uint256.NewInt(0),
		BlobFeeCap: uint256.NewInt(0),
	}
	gasEmpty, err := ftxEmpty.CalldataGas()
	if err != nil {
		t.Fatalf("CalldataGas() for empty frames unexpected error: %v", err)
	}
	if want := expectedFrameTxCalldataGas(ftxEmpty); gasEmpty != want {
		t.Fatalf("CalldataGas() empty = %d, want %d", gasEmpty, want)
	}
	// Empty frame list RLP is minimal; gas from non-empty frames should be higher.
	if gasEmpty >= gas {
		t.Errorf("empty frames CalldataGas %d should be < non-empty frames CalldataGas %d", gasEmpty, gas)
	}
}

// TestFrameTxFloorDataGas verifies FloorDataGas() returns the full EIP-8141
// intrinsic metadata cost for a frame transaction.
func TestFrameTxFloorDataGas(t *testing.T) {
	ftx := testFrameTx()
	floor, err := ftx.FloorDataGas()
	if err != nil {
		t.Fatalf("FloorDataGas() unexpected error: %v", err)
	}
	if want := expectedFrameTxIntrinsicGas(t, ftx); floor != want {
		t.Errorf("FloorDataGas() = %d, want %d", floor, want)
	}
	ftxNoSignatures := ftx.copy().(*FrameTx)
	ftxNoSignatures.Signatures = nil
	noSigFloor, err := ftxNoSignatures.FloorDataGas()
	if err != nil {
		t.Fatalf("FloorDataGas() without signatures unexpected error: %v", err)
	}
	if floor <= noSigFloor {
		t.Errorf("FloorDataGas() with signatures = %d, want > without signatures %d", floor, noSigFloor)
	}

	// Empty frames: floor still includes base gas and minimal RLP list costs.
	ftxEmpty := &FrameTx{
		ChainID:    uint256.NewInt(1),
		Sender:     common.Address{},
		GasTipCap:  uint256.NewInt(0),
		GasFeeCap:  uint256.NewInt(0),
		BlobFeeCap: uint256.NewInt(0),
	}
	floorEmpty, err := ftxEmpty.FloorDataGas()
	if err != nil {
		t.Fatalf("FloorDataGas() for empty frames unexpected error: %v", err)
	}
	if want := expectedFrameTxIntrinsicGas(t, ftxEmpty); floorEmpty != want {
		t.Errorf("FloorDataGas() empty = %d, want %d", floorEmpty, want)
	}
}

func TestFrameTxUnmarshalBinaryRejectsInvalidTargetLength(t *testing.T) {
	type rawFrame struct {
		Mode     uint8
		Flags    uint8
		Target   []byte
		GasLimit uint64
		Value    *uint256.Int
		Data     []byte
	}
	type rawSignature struct {
		Scheme    uint8
		Signer    []byte
		Msg       []byte
		Signature []byte
	}
	type rawFrameTx struct {
		ChainID        *uint256.Int
		NonceKeys      []*uint256.Int
		NonceSeq       uint64
		Sender         common.Address
		Frames         []rawFrame
		Signatures     []rawSignature
		GasTipCap      *uint256.Int
		GasFeeCap      *uint256.Int
		BlobFeeCap     *uint256.Int
		BlobHashes     []common.Hash
		RecentRootRefs []RecentRootRef
	}

	raw := rawFrameTx{
		ChainID:   uint256.NewInt(1),
		NonceKeys: []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:  1,
		Sender:    common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Frames: []rawFrame{
			{
				Mode:     FrameModeVerify,
				Flags:    0,
				Target:   bytes.Repeat([]byte{0x01}, common.AddressLength-1),
				GasLimit: 100000,
				Value:    uint256.NewInt(0),
				Data:     []byte("signature"),
			},
		},
		Signatures:     nil,
		GasTipCap:      uint256.NewInt(1),
		GasFeeCap:      uint256.NewInt(1),
		BlobFeeCap:     uint256.NewInt(0),
		BlobHashes:     nil,
		RecentRootRefs: nil,
	}
	payload, err := rlp.EncodeToBytes(raw)
	if err != nil {
		t.Fatalf("failed to encode malformed frame tx: %v", err)
	}
	rawTx := append([]byte{FrameTxType}, payload...)

	var tx Transaction
	err = tx.UnmarshalBinary(rawTx)
	if err == nil {
		t.Fatal("expected UnmarshalBinary to fail for invalid frame target length")
	}
	if !strings.Contains(err.Error(), "invalid frame target length") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFrameTxUnmarshalBinaryRejectsInvalidRecentRootReference(t *testing.T) {
	type rawRef struct {
		SourceID []byte
		Slot     uint64
		Root     []byte
	}
	base := testFrameTxSigHashVector()
	for _, ref := range []rawRef{
		{SourceID: make([]byte, 31), Slot: 1, Root: make([]byte, 32)},
		{SourceID: make([]byte, 32), Slot: 1, Root: make([]byte, 31)},
	} {
		raw := struct {
			ChainID                          *uint256.Int
			NonceKeys                        []*uint256.Int
			NonceSeq                         uint64
			Sender                           common.Address
			Frames                           []Frame
			Signatures                       []TxSignature
			GasTipCap, GasFeeCap, BlobFeeCap *uint256.Int
			BlobHashes                       []common.Hash
			RecentRootRefs                   []rawRef
		}{base.ChainID, base.NonceKeys, base.NonceSeq, base.Sender, base.Frames, base.Signatures, base.GasTipCap, base.GasFeeCap, base.BlobFeeCap, base.BlobHashes, []rawRef{ref}}
		payload, err := rlp.EncodeToBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Transaction
		if err := decoded.UnmarshalBinary(append([]byte{FrameTxType}, payload...)); err == nil {
			t.Fatal("invalid recent root reference accepted")
		}
	}
}

func TestFrameTxUnmarshalBinaryRejectsLegacyNineFieldPayload(t *testing.T) {
	legacy := struct {
		ChainID    *uint256.Int
		Nonce      uint64
		Sender     common.Address
		Frames     []Frame
		Signatures []TxSignature
		GasTipCap  *uint256.Int
		GasFeeCap  *uint256.Int
		BlobFeeCap *uint256.Int
		BlobHashes []common.Hash
	}{
		ChainID: uint256.NewInt(1), Nonce: 0, Sender: common.HexToAddress("0x01"),
		Frames:    []Frame{{Mode: FrameModeDefault, GasLimit: 1, Value: new(uint256.Int)}},
		GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(1), BlobFeeCap: new(uint256.Int),
	}
	payload, err := rlp.EncodeToBytes(&legacy)
	if err != nil {
		t.Fatal(err)
	}
	var tx Transaction
	if err := tx.UnmarshalBinary(append([]byte{FrameTxType}, payload...)); err == nil {
		t.Fatal("legacy nine-field frame transaction was accepted")
	}
}

func TestFrameTxUnmarshalBinaryRejectsLegacyTenFieldPayload(t *testing.T) {
	tx := testFrameTxSigHashVector()
	legacy := frameTxRLP{
		ChainID: tx.ChainID, NonceKeys: tx.NonceKeys, NonceSeq: tx.NonceSeq, Sender: tx.Sender,
		Frames: tx.Frames, Signatures: tx.Signatures, GasTipCap: tx.GasTipCap, GasFeeCap: tx.GasFeeCap,
		BlobFeeCap: tx.BlobFeeCap, BlobHashes: tx.BlobHashes,
	}
	payload, err := rlp.EncodeToBytes(struct {
		ChainID                          *uint256.Int
		NonceKeys                        []*uint256.Int
		NonceSeq                         uint64
		Sender                           common.Address
		Frames                           []Frame
		Signatures                       []TxSignature
		GasTipCap, GasFeeCap, BlobFeeCap *uint256.Int
		BlobHashes                       []common.Hash
	}{legacy.ChainID, legacy.NonceKeys, legacy.NonceSeq, legacy.Sender, legacy.Frames, legacy.Signatures, legacy.GasTipCap, legacy.GasFeeCap, legacy.BlobFeeCap, legacy.BlobHashes})
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(append([]byte{FrameTxType}, payload...)); err == nil {
		t.Fatal("legacy ten-field frame transaction was accepted")
	}
}

func TestFrameTxValidateRejectsStaticConstraintViolations(t *testing.T) {
	valid := func() *FrameTx {
		return testFrameTx().copy().(*FrameTx)
	}
	tests := []struct {
		name string
		mut  func(*FrameTx)
	}{
		{name: "no nonce keys", mut: func(tx *FrameTx) { tx.NonceKeys = nil }},
		{name: "too many nonce keys", mut: func(tx *FrameTx) {
			tx.NonceKeys = make([]*uint256.Int, MaxNonceKeys+1)
			for i := range tx.NonceKeys {
				tx.NonceKeys[i] = uint256.NewInt(uint64(i + 1))
			}
		}},
		{name: "nil nonce key", mut: func(tx *FrameTx) { tx.NonceKeys = []*uint256.Int{nil} }},
		{name: "duplicate nonce keys", mut: func(tx *FrameTx) { tx.NonceKeys = []*uint256.Int{uint256.NewInt(1), uint256.NewInt(1)} }},
		{name: "descending nonce keys", mut: func(tx *FrameTx) { tx.NonceKeys = []*uint256.Int{uint256.NewInt(2), uint256.NewInt(1)} }},
		{name: "zero with another nonce key", mut: func(tx *FrameTx) { tx.NonceKeys = []*uint256.Int{uint256.NewInt(0), uint256.NewInt(1)} }},
		{name: "too many recent root references", mut: func(tx *FrameTx) { tx.RecentRootRefs = make([]RecentRootRef, params.MaxRecentRootReferences+1) }},
		{
			name: "no frames",
			mut:  func(tx *FrameTx) { tx.Frames = nil },
		},
		{
			name: "too many frames",
			mut: func(tx *FrameTx) {
				tx.Frames = make([]Frame, params.MaxFrames+1)
				for i := range tx.Frames {
					tx.Frames[i].Mode = FrameModeDefault
				}
			},
		},
		{
			name: "invalid mode",
			mut:  func(tx *FrameTx) { tx.Frames[0].Mode = 3 },
		},
		{
			name: "invalid flags",
			mut:  func(tx *FrameTx) { tx.Frames[0].Flags = 8 },
		},
		{
			name: "non sender value",
			mut:  func(tx *FrameTx) { tx.Frames[0].Value = uint256.NewInt(1) },
		},
		{
			name: "atomic last frame",
			mut:  func(tx *FrameTx) { tx.Frames[len(tx.Frames)-1].Flags = FrameFlagAtomicBatch },
		},
		{
			name: "frame gas overflow",
			mut: func(tx *FrameTx) {
				tx.Frames = []Frame{
					{Mode: FrameModeDefault, GasLimit: math.MaxUint64},
					{Mode: FrameModeDefault, GasLimit: 1},
				}
			},
		},
		{
			name: "unsupported signature scheme",
			mut:  func(tx *FrameTx) { tx.Signatures[0].Scheme = 2 },
		},
		{
			name: "bad secp256k1 signature length",
			mut:  func(tx *FrameTx) { tx.Signatures[0].Signature = bytes.Repeat([]byte{1}, 64) },
		},
		{
			name: "bad p256 signature length",
			mut:  func(tx *FrameTx) { tx.Signatures[1].Signature = bytes.Repeat([]byte{1}, 127) },
		},
		{
			name: "bad signature msg length",
			mut:  func(tx *FrameTx) { tx.Signatures[0].Msg = []byte{1} },
		},
		{
			name: "zero explicit signature msg",
			mut:  func(tx *FrameTx) { tx.Signatures[0].Msg = make([]byte, common.HashLength) },
		},
		{
			name: "expiry flags",
			mut: func(tx *FrameTx) {
				tx.Frames[0].Target = testAddressPtr(params.FrameExpiryVerifierAddress)
				tx.Frames[0].Data = make([]byte, 8)
				tx.Frames[0].Flags = 1
			},
		},
		{
			name: "expiry value",
			mut: func(tx *FrameTx) {
				tx.Frames[0].Target = testAddressPtr(params.FrameExpiryVerifierAddress)
				tx.Frames[0].Data = make([]byte, 8)
				tx.Frames[0].Value = uint256.NewInt(1)
			},
		},
		{
			name: "expiry data length",
			mut: func(tx *FrameTx) {
				tx.Frames[0].Target = testAddressPtr(params.FrameExpiryVerifierAddress)
			},
		},
		{
			name: "multiple expiry frames",
			mut: func(tx *FrameTx) {
				expiry := params.FrameExpiryVerifierAddress
				tx.Frames = []Frame{
					{Mode: FrameModeVerify, Target: &expiry, GasLimit: 1, Data: make([]byte, 8)},
					{Mode: FrameModeVerify, Target: &expiry, GasLimit: 1, Data: make([]byte, 8)},
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := valid()
			tt.mut(tx)
			if err := tx.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateFrameTxSignaturesSecp256k1(t *testing.T) {
	key, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tx := testFrameTx().copy().(*FrameTx)
	tx.Signatures = []TxSignature{{
		Scheme: SignatureSchemeSecp256k1,
		Signer: gethcrypto.PubkeyToAddress(key.PublicKey),
	}}
	sigHash := tx.SigHash(tx.chainID())
	sig, err := gethcrypto.Sign(sigHash[:], key)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	tx.Signatures[0].Signature = testVRS(sig)
	if err := ValidateFrameTxSignatures(tx, sigHash); err != nil {
		t.Fatalf("ValidateFrameTxSignatures failed: %v", err)
	}
	tx.Signatures[0].Signature[10] ^= 0x01
	if err := ValidateFrameTxSignatures(tx, sigHash); err == nil {
		t.Fatal("expected mutated secp256k1 signature to fail")
	}
}

func TestValidateFrameTxSignaturesExplicitMsg(t *testing.T) {
	key, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	msg := common.Hash{0x99}.Bytes()
	sig, err := gethcrypto.Sign(msg, key)
	if err != nil {
		t.Fatalf("failed to sign explicit msg: %v", err)
	}
	tx := testFrameTx().copy().(*FrameTx)
	tx.Signatures = []TxSignature{{
		Scheme:    SignatureSchemeSecp256k1,
		Signer:    gethcrypto.PubkeyToAddress(key.PublicKey),
		Msg:       msg,
		Signature: testVRS(sig),
	}}
	if err := ValidateFrameTxSignatures(tx, tx.SigHash(tx.chainID())); err != nil {
		t.Fatalf("ValidateFrameTxSignatures explicit msg failed: %v", err)
	}
	tx.Signatures[0].Msg[0] ^= 0x01
	if err := ValidateFrameTxSignatures(tx, tx.SigHash(tx.chainID())); err == nil {
		t.Fatal("expected mutated explicit msg to fail")
	}
}

func TestValidateFrameTxSignaturesP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate p256 key: %v", err)
	}
	msg := common.Hash{0x42}.Bytes()
	r, s, err := ecdsa.Sign(rand.Reader, key, msg)
	if err != nil {
		t.Fatalf("failed to sign p256 msg: %v", err)
	}
	sig := make([]byte, signatureLengthP256)
	copy(sig[0:32], common.LeftPadBytes(r.Bytes(), 32))
	copy(sig[32:64], common.LeftPadBytes(s.Bytes(), 32))
	copy(sig[64:96], common.LeftPadBytes(key.PublicKey.X.Bytes(), 32))
	copy(sig[96:128], common.LeftPadBytes(key.PublicKey.Y.Bytes(), 32))
	addrHash := gethcrypto.Keccak256(sig[64:128])

	tx := testFrameTx().copy().(*FrameTx)
	tx.Signatures = []TxSignature{{
		Scheme:    SignatureSchemeP256,
		Signer:    common.BytesToAddress(addrHash[12:]),
		Msg:       msg,
		Signature: sig,
	}}
	if err := ValidateFrameTxSignatures(tx, tx.SigHash(tx.chainID())); err != nil {
		t.Fatalf("ValidateFrameTxSignatures p256 failed: %v", err)
	}
	tx.Signatures[0].Signature[0] ^= 0x01
	if err := ValidateFrameTxSignatures(tx, tx.SigHash(tx.chainID())); err == nil {
		t.Fatal("expected mutated p256 signature to fail")
	}
}
