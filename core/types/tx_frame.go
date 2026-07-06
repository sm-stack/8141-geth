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
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	commonmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// errFrameGasUintOverflow is returned when a gas calculation overflows uint64.
var errFrameGasUintOverflow = errors.New("gas uint64 overflow")

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
// [chain_id, nonce, sender, frames, signatures, max_priority_fee_per_gas, max_fee_per_gas,
//
//	max_fee_per_blob_gas, blob_versioned_hashes]
type FrameTx struct {
	ChainID    *uint256.Int
	Nonce      uint64
	Sender     common.Address
	Frames     []Frame
	Signatures []TxSignature
	GasTipCap  *uint256.Int  // max_priority_fee_per_gas
	GasFeeCap  *uint256.Int  // max_fee_per_gas
	BlobFeeCap *uint256.Int  // max_fee_per_blob_gas
	BlobHashes []common.Hash // blob_versioned_hashes
}

// TotalGas returns the total gas limit of the frame transaction as defined in
// EIP-8141: FRAME_TX_INTRINSIC_COST + calldata_cost(rlp(frames)) + sum(frame.gas_limit).
// The calldata cost is not included here as it requires the encoded frame data;
// this method returns the sum of frame gas limits plus intrinsic cost.
// On overflow, math.MaxUint64 is returned; callers relying on this value for
// gas pool or block limit checks will reject the transaction appropriately.
func (tx *FrameTx) TotalGas() uint64 {
	total := uint64(params.TxGasEIP8141)
	for _, f := range tx.Frames {
		if f.GasLimit > math.MaxUint64-total {
			return math.MaxUint64
		}
		total += f.GasLimit
	}
	return total
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *FrameTx) copy() TxData {
	cpy := &FrameTx{
		Nonce:      tx.Nonce,
		Sender:     tx.Sender,
		Frames:     make([]Frame, len(tx.Frames)),
		Signatures: make([]TxSignature, len(tx.Signatures)),
		BlobHashes: make([]common.Hash, len(tx.BlobHashes)),
		ChainID:    new(uint256.Int),
		GasTipCap:  new(uint256.Int),
		GasFeeCap:  new(uint256.Int),
		BlobFeeCap: new(uint256.Int),
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
func (tx *FrameTx) nonce() uint64          { return tx.Nonce }
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
	return rlp.Encode(b, tx)
}

func (tx *FrameTx) decode(input []byte) error {
	if err := rlp.DecodeBytes(input, tx); err != nil {
		return err
	}
	return tx.Validate()
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

// CalldataGas returns the calldata cost of the RLP-encoded frames and signatures.
// Per EIP-8141: calldata_cost(rlp(tx.frames)) + calldata_cost(rlp(tx.signatures)).
// Returns errFrameGasUintOverflow if the result would exceed uint64.
func (tx *FrameTx) CalldataGas() (uint64, error) {
	z, nz := countZeroNonZero(tx.frameTxCalldataBytes()...)
	if nz > 0 && (math.MaxUint64/params.TxDataNonZeroGasEIP2028) < nz {
		return 0, errFrameGasUintOverflow
	}
	nzGas := nz * params.TxDataNonZeroGasEIP2028
	if z > 0 && (math.MaxUint64-nzGas)/params.TxDataZeroGas < z {
		return 0, errFrameGasUintOverflow
	}
	return nzGas + z*params.TxDataZeroGas, nil
}

// FloorDataGas returns the EIP-7623 floor data gas for a frame transaction.
// floor = TxGasEIP8141 + tokens * TxCostFloorPerToken
// Returns errFrameGasUintOverflow if the result would exceed uint64.
func (tx *FrameTx) FloorDataGas() (uint64, error) {
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
	floorGas := tokens * params.TxCostFloorPerToken
	if floorGas > math.MaxUint64-params.TxGasEIP8141 {
		return 0, errFrameGasUintOverflow
	}
	return params.TxGasEIP8141 + floorGas, nil
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
		if frame.Target != nil && *frame.Target == params.FrameExpiryVerifierAddress && frame.Mode == FrameModeVerify {
			expiryFrames++
			if frame.Flags != 0 {
				return fmt.Errorf("expiry verifier frame %d has nonzero flags", i)
			}
			if !value.IsZero() {
				return fmt.Errorf("expiry verifier frame %d has nonzero value", i)
			}
			if len(frame.Data) != 8 {
				return fmt.Errorf("expiry verifier frame %d has data length %d, want 8", i, len(frame.Data))
			}
			if expiryFrames > 1 {
				return errors.New("frame tx has multiple expiry verifier frames")
			}
		}
	}
	return nil
}
