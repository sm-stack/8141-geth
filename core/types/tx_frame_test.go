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
	"encoding/json"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
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
	}
}

func TestFrameTxBlobSidecarRoundTrip(t *testing.T) {
	sidecar := NewBlobTxSidecar(BlobSidecarVersion0,
		[]kzg4844.Blob{*emptyBlob},
		[]kzg4844.Commitment{emptyBlobCommit},
		[]kzg4844.Proof{emptyBlobProof},
	)
	inner := testFrameTx()
	inner.BlobFeeCap = uint256.NewInt(1)
	inner.BlobHashes = sidecar.BlobHashes()
	inner.Sidecar = sidecar
	tx := NewTx(inner)

	encoded, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatal(err)
	}
	if decoded.BlobTxSidecar() == nil {
		t.Fatal("decoded frame transaction has no blob sidecar")
	}
	if err := decoded.BlobTxSidecar().ValidateBlobCommitmentHashes(decoded.BlobHashes()); err != nil {
		t.Fatal(err)
	}
	if decoded.Hash() != tx.Hash() || tx.WithoutBlobTxSidecar().Hash() != tx.Hash() {
		t.Fatal("blob sidecar changed frame transaction hash")
	}
	if decoded.WithoutBlobTxSidecar().BlobTxSidecar() != nil {
		t.Fatal("WithoutBlobTxSidecar retained frame sidecar")
	}
}

func TestFrameTxAccessorsDoNotExposeMutablePayload(t *testing.T) {
	tx := NewTx(testFrameTx())
	hash := tx.Hash()
	payload := tx.GetFrameTx()
	payload.NonceSeq++
	payload.Frames[0].Data[0] ^= 0xff
	frames := tx.Frames()
	frames[0].GasLimit++

	if tx.Hash() != hash {
		t.Fatal("mutating accessor result changed cached transaction hash")
	}
	fresh := tx.GetFrameTx()
	if fresh.NonceSeq != 42 || fresh.Frames[0].GasLimit != 100_000 || bytes.Equal(fresh.Frames[0].Data, payload.Frames[0].Data) {
		t.Fatalf("frame transaction payload was mutated through an accessor: %#v", fresh)
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

type storedFrameTxVector struct {
	Transaction struct {
		ChainID    string   `json:"chainId"`
		NonceKeys  []string `json:"nonceKeys"`
		NonceSeq   string   `json:"nonceSeq"`
		Sender     string   `json:"sender"`
		GasTipCap  string   `json:"maxPriorityFeePerGas"`
		GasFeeCap  string   `json:"maxFeePerGas"`
		BlobFeeCap string   `json:"maxFeePerBlobGas"`
		BlobHashes []string `json:"blobVersionedHashes"`
		Frames     []struct {
			Mode     string  `json:"mode"`
			Flags    uint8   `json:"flags"`
			Target   *string `json:"target"`
			GasLimit string  `json:"gasLimit"`
			Value    string  `json:"value"`
			Data     string  `json:"data"`
		} `json:"frames"`
		Signatures []struct {
			Scheme    uint8  `json:"scheme"`
			Signer    string `json:"signer"`
			Msg       string `json:"msg"`
			Signature string `json:"signature"`
		} `json:"signatures"`
		RecentRootRefs []struct {
			SourceID string `json:"sourceId"`
			Slot     string `json:"slot"`
			Root     string `json:"root"`
		} `json:"recentRootReferences"`
	} `json:"transaction"`
	SigHash        string `json:"sigHash"`
	RawTransaction string `json:"rawTransaction"`
}

func loadFrameTxVector(t *testing.T) (*FrameTx, storedFrameTxVector) {
	t.Helper()
	path := os.Getenv("EIP8141_VECTOR_PATH")
	if path == "" {
		dir, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		for {
			candidate := filepath.Join(dir, ".context", "test-vectors", "frame-transaction-v1.json")
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				path = filepath.Join("testdata", "frame-transaction-v1.json")
				break
			}
			dir = parent
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored storedFrameTxVector
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	parseU64 := func(value string) uint64 {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	parseU256 := func(value string) *uint256.Int {
		parsed, err := uint256.FromDecimal(value)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	decode := func(value string) []byte {
		parsed, err := hexutil.Decode(value)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	tx := &FrameTx{
		ChainID:    parseU256(stored.Transaction.ChainID),
		NonceSeq:   parseU64(stored.Transaction.NonceSeq),
		Sender:     common.HexToAddress(stored.Transaction.Sender),
		GasTipCap:  parseU256(stored.Transaction.GasTipCap),
		GasFeeCap:  parseU256(stored.Transaction.GasFeeCap),
		BlobFeeCap: parseU256(stored.Transaction.BlobFeeCap),
	}
	for _, key := range stored.Transaction.NonceKeys {
		tx.NonceKeys = append(tx.NonceKeys, parseU256(key))
	}
	for _, hash := range stored.Transaction.BlobHashes {
		tx.BlobHashes = append(tx.BlobHashes, common.HexToHash(hash))
	}
	modes := map[string]uint8{"default": FrameModeDefault, "verify": FrameModeVerify, "sender": FrameModeSender}
	for _, frame := range stored.Transaction.Frames {
		converted := Frame{Mode: modes[frame.Mode], Flags: frame.Flags, GasLimit: parseU64(frame.GasLimit), Value: parseU256(frame.Value), Data: decode(frame.Data)}
		if frame.Target != nil {
			target := common.HexToAddress(*frame.Target)
			converted.Target = &target
		}
		tx.Frames = append(tx.Frames, converted)
	}
	for _, signature := range stored.Transaction.Signatures {
		tx.Signatures = append(tx.Signatures, TxSignature{Scheme: signature.Scheme, Signer: common.HexToAddress(signature.Signer), Msg: decode(signature.Msg), Signature: decode(signature.Signature)})
	}
	return tx, stored
}

func expectedFrameTxCalldataGas(ftx *FrameTx) uint64 {
	var tokens uint64
	for _, chunk := range ftx.frameTxCalldataBytes() {
		for _, b := range chunk {
			if b == 0 {
				tokens++
			} else {
				tokens += params.TxTokenPerNonZeroByte
			}
		}
	}
	return tokens * params.TxDataZeroGas
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
	for _, frame := range ftx.Frames {
		if frame.Value != nil && !frame.Value.IsZero() && frame.Target != nil && *frame.Target != ftx.Sender {
			gas += params.TxValueCost2780
		}
	}
	return gas
}

func expectedFrameTxFloorGas(t *testing.T, ftx *FrameTx) uint64 {
	t.Helper()
	fixed, err := ftx.fixedGas()
	if err != nil {
		t.Fatal(err)
	}
	var tokens uint64
	for _, chunk := range ftx.frameTxCalldataBytes() {
		for _, b := range chunk {
			if b == 0 {
				tokens++
			} else {
				tokens += params.TxTokenPerNonZeroByte
			}
		}
	}
	return fixed + tokens*params.TxCostFloorPerToken7976
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
	tx := testFrameTx()
	wantHash := tx.SigHash(tx.chainID())
	typed, err := NewTx(tx).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	var decoded Transaction
	if err := decoded.UnmarshalBinary(typed); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if got := decoded.GetFrameTx().SigHash(tx.chainID()); got != wantHash {
		t.Fatalf("round-trip SigHash = %s, want %s", got, wantHash)
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
			FrameModeDefault,
			uint8(0),
			bytes.Repeat([]byte{0x11}, n),
			frameGasLimits{Execution: 1},
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
		FrameModeVerify,
		uint8(0),
		[]byte{},
		frameGasLimits{Execution: 100},
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

func TestFrameTxValueTransferIntrinsicGas(t *testing.T) {
	withValue := testFrameTx()
	withoutValue := withValue.copy().(*FrameTx)
	withoutValue.Frames[1].Value.Clear()
	withGas, err := withValue.IntrinsicGas()
	if err != nil {
		t.Fatal(err)
	}
	withoutGas, err := withoutValue.IntrinsicGas()
	if err != nil {
		t.Fatal(err)
	}
	if got := withGas - withoutGas; got != params.TxValueCost2780 {
		t.Fatalf("value transfer intrinsic delta = %d, want %d", got, params.TxValueCost2780)
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
	if want := expectedFrameTxFloorGas(t, ftx); floor != want {
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
	if want := expectedFrameTxFloorGas(t, ftxEmpty); floorEmpty != want {
		t.Errorf("FloorDataGas() empty = %d, want %d", floorEmpty, want)
	}
}

func TestFrameTxUnmarshalBinaryRejectsInvalidTargetLength(t *testing.T) {
	type rawFrame struct {
		Mode   uint8
		Flags  uint8
		Target []byte
		Limits frameGasLimits
		Value  *uint256.Int
		Data   []byte
	}
	type rawSignature struct {
		Scheme    uint8
		Signer    []byte
		Msg       []byte
		Signature []byte
	}
	type rawFrameTx struct {
		ChainID    *uint256.Int
		NonceKeys  []*uint256.Int
		NonceSeq   uint64
		Sender     common.Address
		Frames     []rawFrame
		Signatures []rawSignature
		Fees       frameTxFees
		BlobHashes []common.Hash
	}

	raw := rawFrameTx{
		ChainID:   uint256.NewInt(1),
		NonceKeys: []*uint256.Int{new(uint256.Int)},
		NonceSeq:  1,
		Sender:    common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Frames: []rawFrame{
			{
				Mode:   FrameModeVerify,
				Flags:  0,
				Target: bytes.Repeat([]byte{0x01}, common.AddressLength-1),
				Limits: frameGasLimits{Execution: 100000},
				Value:  uint256.NewInt(0),
				Data:   []byte("signature"),
			},
		},
		Signatures: nil,
		Fees: frameTxFees{
			GasTipCap:  uint256.NewInt(1),
			GasFeeCap:  uint256.NewInt(1),
			BlobFeeCap: uint256.NewInt(0),
		},
		BlobHashes: nil,
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
	base, _ := loadFrameTxVector(t)
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
	tx, _ := loadFrameTxVector(t)
	payload, err := rlp.EncodeToBytes(struct {
		ChainID                          *uint256.Int
		NonceKeys                        []*uint256.Int
		NonceSeq                         uint64
		Sender                           common.Address
		Frames                           []Frame
		Signatures                       []TxSignature
		GasTipCap, GasFeeCap, BlobFeeCap *uint256.Int
		BlobHashes                       []common.Hash
	}{tx.ChainID, tx.NonceKeys, tx.NonceSeq, tx.Sender, tx.Frames, tx.Signatures, tx.GasTipCap, tx.GasFeeCap, tx.BlobFeeCap, tx.BlobHashes})
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
			name: "atomic before verify frame",
			mut: func(tx *FrameTx) {
				tx.Frames = []Frame{{Mode: FrameModeSender, Flags: FrameFlagAtomicBatch}, {Mode: FrameModeVerify}}
			},
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
			name: "VERIFY frame starts atomic batch",
			mut: func(tx *FrameTx) {
				tx.Frames = []Frame{
					{Mode: FrameModeVerify, Flags: FrameFlagAtomicBatch},
					{Mode: FrameModeSender},
				}
			},
		},
		{
			name: "execution approval targets third party",
			mut: func(tx *FrameTx) {
				target := common.HexToAddress("0x1234")
				tx.Frames[0].Target = &target
				tx.Frames[0].Flags = 2
			},
		},
		{
			name: "unsupported signature scheme",
			mut:  func(tx *FrameTx) { tx.Signatures[0].Scheme = 3 },
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

func TestValidateFrameTxSignaturesArbitrary(t *testing.T) {
	tx := testFrameTx().copy().(*FrameTx)
	tx.Signatures = []TxSignature{{
		Scheme:    SignatureSchemeArbitrary,
		Signature: []byte{0x01, 0x02, 0x03},
	}}
	if err := ValidateFrameTxSignatures(tx, tx.SigHash(tx.chainID())); err != nil {
		t.Fatalf("arbitrary signature rejected: %v", err)
	}
	gas, err := tx.SignatureGas()
	if err != nil {
		t.Fatal(err)
	}
	if gas != params.SigGasArbitrary {
		t.Fatalf("arbitrary signature gas %d, want %d", gas, params.SigGasArbitrary)
	}
	tx.Signatures[0].Signer = common.HexToAddress("0x1234")
	if err := ValidateFrameTxSignatures(tx, tx.SigHash(tx.chainID())); err == nil {
		t.Fatal("arbitrary signature with signer accepted")
	}
}

func TestTxSignatureOptionalSignerRLP(t *testing.T) {
	sig := TxSignature{Scheme: SignatureSchemeArbitrary, Signature: []byte{0x01}}
	encoded, err := rlp.EncodeToBytes(sig)
	if err != nil {
		t.Fatal(err)
	}
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 4 || !bytes.Equal(fields[1], []byte{0x80}) {
		t.Fatalf("optional signer encoding %x", encoded)
	}
	var decoded TxSignature
	if err := rlp.DecodeBytes(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Signer != (common.Address{}) {
		t.Fatalf("decoded signer %s", decoded.Signer)
	}
	if decoded.signerPresent {
		t.Fatal("omitted signer decoded as present")
	}

	explicitZero := TxSignature{Scheme: SignatureSchemeSecp256k1, signerPresent: true}
	explicitEncoded, err := rlp.EncodeToBytes(explicitZero)
	if err != nil {
		t.Fatal(err)
	}
	if err := rlp.DecodeBytes(explicitEncoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.signerPresent || decoded.Signer != (common.Address{}) {
		t.Fatal("explicit zero signer was not preserved")
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
	halfN := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
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
	highS := new(big.Int).Sub(elliptic.P256().Params().N, s)
	copy(tx.Signatures[0].Signature[32:64], common.LeftPadBytes(highS.Bytes(), 32))
	if err := ValidateFrameTxSignatures(tx, tx.SigHash(tx.chainID())); err == nil {
		t.Fatal("expected high-s p256 signature to fail")
	}
	copy(tx.Signatures[0].Signature[32:64], common.LeftPadBytes(s.Bytes(), 32))
	tx.Signatures[0].Signature[0] ^= 0x01
	if err := ValidateFrameTxSignatures(tx, tx.SigHash(tx.chainID())); err == nil {
		t.Fatal("expected mutated p256 signature to fail")
	}
}
