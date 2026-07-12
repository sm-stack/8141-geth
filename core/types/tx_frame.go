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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	commonmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// errFrameGasUintOverflow is returned when a gas calculation overflows uint64.
var errFrameGasUintOverflow = errors.New("gas uint64 overflow")

const MaxNonceKeys = 16

// Frame mode constants as defined in EIP-8141.
const (
	FrameModeDefault uint8 = 0 // Execute as ENTRY_POINT caller.
	FrameModeVerify  uint8 = 1 // Validation frame (static, must APPROVE).
	FrameModeSender  uint8 = 2 // Execute as tx.sender caller.
)

// Frame flag constants as defined in EIP-8141.
const (
	FrameFlagApproveScopeMask uint8 = 0x03
	FrameFlagAtomicBatch      uint8 = 0x04
)

// IsFrameExpiryVerifier reports whether the frame is the canonical expiry verifier
// VERIFY frame after target resolution.
func IsFrameExpiryVerifier(frame Frame, resolvedTarget common.Address) bool {
	return frame.Mode == FrameModeVerify && resolvedTarget == params.FrameExpiryVerifierAddress
}

// DecodeFrameExpiryDeadline decodes the expiry verifier's 8-byte big-endian
// deadline calldata.
func DecodeFrameExpiryDeadline(data []byte) (uint64, bool) {
	if len(data) != params.FrameExpiryDataLength {
		return 0, false
	}
	return binary.BigEndian.Uint64(data), true
}

// Transaction signature scheme constants as defined in EIP-8141.
const (
	SignatureSchemeSecp256k1 uint8 = 0
	SignatureSchemeP256      uint8 = 1
)

// Frame represents a single execution frame in a frame transaction (EIP-8141).
//
// RLP encoding: [mode, flags, target, gas_limit, value, data]
// When target is nil, it resolves to tx.sender at execution time.
type Frame struct {
	Mode     uint8
	Flags    uint8
	Target   *common.Address // nil means tx.sender
	GasLimit uint64
	Value    *uint256.Int
	Data     []byte
}

// EncodeRLP implements rlp.Encoder for Frame.
// Nil target is encoded as empty bytes.
func (f *Frame) EncodeRLP(w io.Writer) error {
	var target []byte
	if f.Target != nil {
		target = f.Target.Bytes()
	}
	value := f.Value
	if value == nil {
		value = new(uint256.Int)
	}
	return rlp.Encode(w, []any{f.Mode, f.Flags, target, f.GasLimit, value, f.Data})
}

// DecodeRLP implements rlp.Decoder for Frame.
func (f *Frame) DecodeRLP(s *rlp.Stream) error {
	var dec struct {
		Mode     uint8
		Flags    uint8
		Target   []byte
		GasLimit uint64
		Value    *uint256.Int
		Data     []byte
	}
	if err := s.Decode(&dec); err != nil {
		return err
	}
	f.Mode = dec.Mode
	f.Flags = dec.Flags
	f.GasLimit = dec.GasLimit
	f.Data = dec.Data
	f.Value = new(uint256.Int)
	if dec.Value != nil {
		f.Value.Set(dec.Value)
	}
	f.Target = nil
	if len(dec.Target) > 0 {
		if len(dec.Target) != common.AddressLength {
			return fmt.Errorf("invalid frame target length %d", len(dec.Target))
		}
		addr := common.BytesToAddress(dec.Target)
		f.Target = &addr
	}
	return nil
}

// TxSignature represents one transaction-level signature exposed by EIP-8141.
//
// RLP encoding: [scheme, signer, msg, signature]
type TxSignature struct {
	Scheme    uint8
	Signer    common.Address
	Msg       []byte
	Signature []byte
}

// FrameTx implements the EIP-8141 frame transaction.
//
// RLP encoding:
// [chain_id, nonce_keys, nonce_seq, sender, frames, signatures, max_priority_fee_per_gas, max_fee_per_gas,
//
//	max_fee_per_blob_gas, blob_versioned_hashes]
type FrameTx struct {
	ChainID    *uint256.Int
	NonceKeys  []*uint256.Int
	NonceSeq   uint64
	Sender     common.Address
	Frames     []Frame
	Signatures []TxSignature
	GasTipCap  *uint256.Int  // max_priority_fee_per_gas
	GasFeeCap  *uint256.Int  // max_fee_per_gas
	BlobFeeCap *uint256.Int  // max_fee_per_blob_gas
	BlobHashes []common.Hash // blob_versioned_hashes
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *FrameTx) copy() TxData {
	cpy := &FrameTx{
		NonceKeys:  make([]*uint256.Int, len(tx.NonceKeys)),
		NonceSeq:   tx.NonceSeq,
		Sender:     tx.Sender,
		Frames:     make([]Frame, len(tx.Frames)),
		Signatures: make([]TxSignature, len(tx.Signatures)),
		BlobHashes: make([]common.Hash, len(tx.BlobHashes)),
		ChainID:    new(uint256.Int),
		GasTipCap:  new(uint256.Int),
		GasFeeCap:  new(uint256.Int),
		BlobFeeCap: new(uint256.Int),
	}
	for i, key := range tx.NonceKeys {
		if key != nil {
			cpy.NonceKeys[i] = new(uint256.Int).Set(key)
		}
	}
	// Deep copy frames.
	for i, f := range tx.Frames {
		cpy.Frames[i] = Frame{
			Mode:     f.Mode,
			Flags:    f.Flags,
			GasLimit: f.GasLimit,
			Value:    new(uint256.Int),
			Data:     common.CopyBytes(f.Data),
		}
		if f.Value != nil {
			cpy.Frames[i].Value.Set(f.Value)
		}
		if f.Target != nil {
			target := *f.Target
			cpy.Frames[i].Target = &target
		}
	}
	for i, sig := range tx.Signatures {
		cpy.Signatures[i] = TxSignature{
			Scheme:    sig.Scheme,
			Signer:    sig.Signer,
			Msg:       common.CopyBytes(sig.Msg),
			Signature: common.CopyBytes(sig.Signature),
		}
	}
	copy(cpy.BlobHashes, tx.BlobHashes)
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	if tx.BlobFeeCap != nil {
		cpy.BlobFeeCap.Set(tx.BlobFeeCap)
	}
	return cpy
}

// accessors for innerTx.
func (tx *FrameTx) txType() byte           { return FrameTxType }
func (tx *FrameTx) chainID() *big.Int      { return tx.ChainID.ToBig() }
func (tx *FrameTx) accessList() AccessList { return nil }
func (tx *FrameTx) data() []byte           { return nil }
func (tx *FrameTx) gas() uint64            { return tx.TotalGas() }
func (tx *FrameTx) gasFeeCap() *big.Int    { return tx.GasFeeCap.ToBig() }
func (tx *FrameTx) gasTipCap() *big.Int    { return tx.GasTipCap.ToBig() }
func (tx *FrameTx) gasPrice() *big.Int     { return tx.GasFeeCap.ToBig() }
func (tx *FrameTx) value() *big.Int        { return new(big.Int) }
func (tx *FrameTx) nonce() uint64          { return tx.NonceSeq }
func (tx *FrameTx) to() *common.Address    { return nil }
func (tx *FrameTx) blobGas() uint64        { return params.BlobTxBlobGasPerBlob * uint64(len(tx.BlobHashes)) }
func (tx *FrameTx) BlobGas() uint64        { return tx.blobGas() }

func (tx *FrameTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap.ToBig())
	}
	tip := dst.Sub(tx.GasFeeCap.ToBig(), baseFee)
	if tip.Cmp(tx.GasTipCap.ToBig()) > 0 {
		tip.Set(tx.GasTipCap.ToBig())
	}
	return tip.Add(tip, baseFee)
}

// rawSignatureValues returns zero values since frame transactions do not use
// ECDSA signatures. Authentication is performed via VERIFY frames.
func (tx *FrameTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues is a no-op for frame transactions.
func (tx *FrameTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *FrameTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, &frameTxRLP{
		ChainID: tx.ChainID, NonceKeys: tx.NonceKeys, NonceSeq: tx.NonceSeq,
		Sender: tx.Sender, Frames: tx.Frames, Signatures: tx.Signatures,
		GasTipCap: tx.GasTipCap, GasFeeCap: tx.GasFeeCap,
		BlobFeeCap: tx.BlobFeeCap, BlobHashes: tx.BlobHashes,
	})
}

func (tx *FrameTx) decode(input []byte) error {
	var dec frameTxRLP
	if err := rlp.DecodeBytes(input, &dec); err != nil {
		return err
	}
	tx.ChainID, tx.NonceKeys, tx.NonceSeq = dec.ChainID, dec.NonceKeys, dec.NonceSeq
	tx.Sender, tx.Frames, tx.Signatures = dec.Sender, dec.Frames, dec.Signatures
	tx.GasTipCap, tx.GasFeeCap = dec.GasTipCap, dec.GasFeeCap
	tx.BlobFeeCap, tx.BlobHashes = dec.BlobFeeCap, dec.BlobHashes
	return tx.Validate()
}

type frameTxRLP struct {
	ChainID    *uint256.Int
	NonceKeys  []*uint256.Int
	NonceSeq   uint64
	Sender     common.Address
	Frames     []Frame
	Signatures []TxSignature
	GasTipCap  *uint256.Int
	GasFeeCap  *uint256.Int
	BlobFeeCap *uint256.Int
	BlobHashes []common.Hash
}

// rlpFramesData returns the RLP-encoded frames as a byte slice.
func (tx *FrameTx) rlpFramesData() []byte {
	var buf bytes.Buffer
	rlp.Encode(&buf, tx.Frames)
	return buf.Bytes()
}

// rlpSignaturesData returns the RLP-encoded signatures as a byte slice.
func (tx *FrameTx) rlpSignaturesData() []byte {
	var buf bytes.Buffer
	rlp.Encode(&buf, tx.Signatures)
	return buf.Bytes()
}

// frameTxCalldataBytes returns the byte blobs charged as frame tx data.
func (tx *FrameTx) frameTxCalldataBytes() [][]byte {
	return [][]byte{tx.rlpFramesData(), tx.rlpSignaturesData()}
}

func countZeroNonZero(chunks ...[]byte) (uint64, uint64) {
	var z, nz uint64
	for _, data := range chunks {
		zeros := uint64(bytes.Count(data, []byte{0}))
		z += zeros
		nz += uint64(len(data)) - zeros
	}
	return z, nz
}

// SignatureGas returns the transaction-level signature verification gas.
func (tx *FrameTx) SignatureGas() (uint64, error) {
	var total uint64
	for _, sig := range tx.Signatures {
		var gas uint64
		switch sig.Scheme {
		case SignatureSchemeSecp256k1:
			gas = params.SigGasSecp256k1
		case SignatureSchemeP256:
			gas = params.SigGasP256
		default:
			return 0, fmt.Errorf("unsupported signature scheme %d", sig.Scheme)
		}
		var overflow bool
		if total, overflow = commonmath.SafeAdd(total, gas); overflow {
			return 0, errFrameGasUintOverflow
		}
	}
	return total, nil
}

func (tx *FrameTx) fixedGas() (uint64, error) {
	total := params.TxGasEIP8141
	frameGas, overflow := commonmath.SafeMul(uint64(len(tx.Frames)), params.FrameTxPerFrameGas)
	if overflow {
		return 0, errFrameGasUintOverflow
	}
	if total, overflow = commonmath.SafeAdd(total, frameGas); overflow {
		return 0, errFrameGasUintOverflow
	}
	signatureGas, err := tx.SignatureGas()
	if err != nil {
		return 0, err
	}
	if total, overflow = commonmath.SafeAdd(total, signatureGas); overflow {
		return 0, errFrameGasUintOverflow
	}
	return total, nil
}

// CalldataGas returns the EIP-7623 calldata cost of the RLP-encoded frames and
// signatures.
//
// Per EIP-8141:
//
//	calldata_cost(rlp(tx.frames)) + calldata_cost(rlp(tx.signatures))
//
// Returns errFrameGasUintOverflow if the result would exceed uint64.
func (tx *FrameTx) CalldataGas() (uint64, error) {
	z, nz := countZeroNonZero(tx.frameTxCalldataBytes()...)
	if nz > 0 && (math.MaxUint64/params.TxTokenPerNonZeroByte) < nz {
		return 0, errFrameGasUintOverflow
	}
	nzTokens := nz * params.TxTokenPerNonZeroByte
	if z > math.MaxUint64-nzTokens {
		return 0, errFrameGasUintOverflow
	}
	tokens := nzTokens + z
	if tokens > 0 && (math.MaxUint64/params.TxCostFloorPerToken) < tokens {
		return 0, errFrameGasUintOverflow
	}
	return tokens * params.TxCostFloorPerToken, nil
}

// IntrinsicGas returns the non-frame-execution gas charged by a frame
// transaction:
//
//	FRAME_TX_INTRINSIC_COST
//	+ len(frames) * FRAME_TX_PER_FRAME_COST
//	+ calldata_cost(rlp(signatures))
//	+ calldata_cost(rlp(frames))
//	+ signature_verification_cost
func (tx *FrameTx) IntrinsicGas() (uint64, error) {
	total, err := tx.fixedGas()
	if err != nil {
		return 0, err
	}
	calldataGas, err := tx.CalldataGas()
	if err != nil {
		return 0, err
	}
	var overflow bool
	if total, overflow = commonmath.SafeAdd(total, calldataGas); overflow {
		return 0, errFrameGasUintOverflow
	}
	return total, nil
}

// TotalGas returns the total gas limit of the frame transaction as defined in
// EIP-8141:
//
//	FRAME_TX_INTRINSIC_COST
//	+ len(frames) * FRAME_TX_PER_FRAME_COST
//	+ calldata_cost(rlp(signatures))
//	+ calldata_cost(rlp(frames))
//	+ signature_verification_cost
//	+ sum(frame.gas_limit)
//
// On overflow, math.MaxUint64 is returned; callers relying on this value for
// gas pool or block limit checks will reject the transaction appropriately.
func (tx *FrameTx) TotalGas() uint64 {
	total, err := tx.IntrinsicGas()
	if err != nil {
		return math.MaxUint64
	}
	for _, f := range tx.Frames {
		var overflow bool
		if total, overflow = commonmath.SafeAdd(total, f.GasLimit); overflow {
			return math.MaxUint64
		}
	}
	return total
}

// FloorDataGas returns the EIP-7623 floor data gas for a frame transaction.
// EIP-8141 charges frame calldata with EIP-7623 rules up front, so the floor
// matches the full intrinsic metadata gas.
func (tx *FrameTx) FloorDataGas() (uint64, error) {
	return tx.IntrinsicGas()
}

// SigHash returns the exported signature hash for the frame transaction.
func (tx *FrameTx) SigHash(chainID *big.Int) common.Hash {
	return tx.sigHash(chainID)
}

// sigHash returns the signature hash for the frame transaction.
// Per EIP-8141, empty-message signatures have their raw signature bytes elided.
func (tx *FrameTx) sigHash(chainID *big.Int) common.Hash {
	hashTx := tx.copy().(*FrameTx)
	if chainID != nil {
		hashTx.ChainID.SetFromBig(chainID)
	}
	for i := range hashTx.Signatures {
		if len(hashTx.Signatures[i].Msg) == 0 {
			hashTx.Signatures[i].Signature = nil
		}
	}
	return prefixedRlpHash(FrameTxType, hashTx)
}

// ValidateNonceKeys checks the canonical EIP-8250 nonce domain constraints.
func ValidateNonceKeys(keys []*uint256.Int) error {
	if len(keys) == 0 || len(keys) > MaxNonceKeys {
		return fmt.Errorf("frame tx has %d nonce keys, want 1..%d", len(keys), MaxNonceKeys)
	}
	for i, key := range keys {
		if key == nil {
			return fmt.Errorf("frame tx nonce key %d is nil", i)
		}
		if i > 0 && keys[i-1].Cmp(key) >= 0 {
			return errors.New("frame tx nonce keys are not strictly increasing")
		}
		if key.IsZero() && (len(keys) != 1 || i != 0) {
			return errors.New("zero nonce key is only valid as singleton [0]")
		}
	}
	return nil
}

// Validate checks statically-decidable EIP-8141 frame transaction constraints.
func (tx *FrameTx) Validate() error {
	if tx.ChainID == nil {
		return errors.New("frame tx missing chain_id")
	}
	if tx.GasTipCap == nil {
		return errors.New("frame tx missing max_priority_fee_per_gas")
	}
	if tx.GasFeeCap == nil {
		return errors.New("frame tx missing max_fee_per_gas")
	}
	if tx.BlobFeeCap == nil {
		return errors.New("frame tx missing max_fee_per_blob_gas")
	}
	if err := ValidateNonceKeys(tx.NonceKeys); err != nil {
		return err
	}
	if len(tx.Frames) == 0 {
		return errors.New("frame tx has no frames")
	}
	if len(tx.Frames) > params.MaxFrames {
		return fmt.Errorf("frame tx has %d frames, max %d", len(tx.Frames), params.MaxFrames)
	}
	for i, sig := range tx.Signatures {
		if err := validateTxSignature(sig); err != nil {
			return fmt.Errorf("invalid signature %d: %w", i, err)
		}
	}
	var (
		totalFrameGas uint64
		expiryFrames  int
	)
	for i, frame := range tx.Frames {
		if frame.Mode > FrameModeSender {
			return fmt.Errorf("frame %d has invalid mode %d", i, frame.Mode)
		}
		if frame.Flags >= 8 {
			return fmt.Errorf("frame %d has invalid flags %d", i, frame.Flags)
		}
		value := frame.Value
		if value == nil {
			value = new(uint256.Int)
		}
		if frame.Mode != FrameModeSender && !value.IsZero() {
			return fmt.Errorf("frame %d has nonzero value outside SENDER mode", i)
		}
		if frame.Flags&FrameFlagAtomicBatch != 0 && i+1 == len(tx.Frames) {
			return fmt.Errorf("frame %d has atomic batch flag without following frame", i)
		}
		var overflow bool
		if totalFrameGas, overflow = commonmath.SafeAdd(totalFrameGas, frame.GasLimit); overflow {
			return errFrameGasUintOverflow
		}
		target := tx.Sender
		if frame.Target != nil {
			target = *frame.Target
		}
		if IsFrameExpiryVerifier(frame, target) {
			expiryFrames++
			if frame.Flags != 0 {
				return fmt.Errorf("expiry verifier frame %d has nonzero flags", i)
			}
			if !value.IsZero() {
				return fmt.Errorf("expiry verifier frame %d has nonzero value", i)
			}
			if len(frame.Data) != params.FrameExpiryDataLength {
				return fmt.Errorf("expiry verifier frame %d has data length %d, want %d", i, len(frame.Data), params.FrameExpiryDataLength)
			}
			if expiryFrames > 1 {
				return errors.New("frame tx has multiple expiry verifier frames")
			}
		}
	}
	return nil
}

func (tx *FrameTx) UsesLegacyNonce() bool {
	return len(tx.NonceKeys) == 1 && tx.NonceKeys[0] != nil && tx.NonceKeys[0].IsZero()
}

func (tx *FrameTx) NonceKeySetEqual(other *FrameTx) bool {
	if other == nil || len(tx.NonceKeys) != len(other.NonceKeys) {
		return false
	}
	for i := range tx.NonceKeys {
		if tx.NonceKeys[i] == nil || other.NonceKeys[i] == nil || !tx.NonceKeys[i].Eq(other.NonceKeys[i]) {
			return false
		}
	}
	return true
}

func (tx *FrameTx) NonceKeysHash() common.Hash {
	return ComputeNonceKeysHash(tx.NonceKeys)
}

func ComputeNonceKeysHash(keys []*uint256.Int) common.Hash {
	data := make([]byte, 32*(len(keys)+1))
	new(uint256.Int).SetUint64(uint64(len(keys))).WriteToSlice(data[:32])
	for i, key := range keys {
		if key != nil {
			key.WriteToSlice(data[32*(i+1) : 32*(i+2)])
		}
	}
	return common.BytesToHash(crypto.Keccak256(data))
}

func NonceManagerSlot(sender common.Address, key *uint256.Int) common.Hash {
	data := make([]byte, 64)
	copy(data[12:32], sender[:])
	if key != nil {
		key.WriteToSlice(data[32:])
	}
	return crypto.Keccak256Hash(data)
}
