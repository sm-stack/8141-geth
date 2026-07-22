// Copyright 2014 The go-ethereum Authors
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
	"math/big"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

//go:generate go run github.com/fjl/gencodec -type Receipt -field-override receiptMarshaling -out gen_receipt_json.go

var (
	receiptStatusFailedRLP     = []byte{}
	receiptStatusSuccessfulRLP = []byte{0x01}
)

var errShortTypedReceipt = errors.New("typed receipt too short")

const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	ReceiptStatusFailed = uint64(0)

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	ReceiptStatusSuccessful = uint64(1)
)

const (
	// FrameReceiptStatusFailed means frame execution reverted.
	FrameReceiptStatusFailed = uint8(0)

	// FrameReceiptStatusSuccessful means frame execution completed successfully.
	FrameReceiptStatusSuccessful = uint8(1)

	// FrameReceiptStatusSkipped means frame execution was skipped by atomic batch rollback.
	FrameReceiptStatusSkipped = uint8(2)
)

func validFrameReceiptStatus(status uint64) bool {
	return status == uint64(FrameReceiptStatusFailed) ||
		status == uint64(FrameReceiptStatusSuccessful) ||
		status == uint64(FrameReceiptStatusSkipped)
}

// Receipt represents the results of a transaction.
type Receipt struct {
	// Consensus fields: These fields are defined by the Yellow Paper
	Type              uint8          `json:"type,omitempty"`
	PostState         []byte         `json:"root"`
	Status            uint64         `json:"status"`
	CumulativeGasUsed uint64         `json:"cumulativeGasUsed" gencodec:"required"`
	Bloom             Bloom          `json:"logsBloom"         gencodec:"required"`
	Logs              []*Log         `json:"logs"              gencodec:"required"`
	Payer             common.Address `json:"payer,omitempty"`
	FrameReceipts     []FrameReceipt `json:"frameReceipts,omitempty"`

	// Implementation fields: These fields are added by geth when processing a transaction.
	TxHash            common.Hash    `json:"transactionHash" gencodec:"required"`
	ContractAddress   common.Address `json:"contractAddress"`
	GasUsed           uint64         `json:"gasUsed" gencodec:"required"`
	EffectiveGasPrice *big.Int       `json:"effectiveGasPrice"` // required, but tag omitted for backwards compatibility
	BlobGasUsed       uint64         `json:"blobGasUsed,omitempty"`
	BlobGasPrice      *big.Int       `json:"blobGasPrice,omitempty"`

	// Inclusion information: These fields provide information about the inclusion of the
	// transaction corresponding to this receipt.
	BlockHash        common.Hash `json:"blockHash,omitempty"`
	BlockNumber      *big.Int    `json:"blockNumber,omitempty"`
	TransactionIndex uint        `json:"transactionIndex"`
}

type receiptMarshaling struct {
	Type              hexutil.Uint64
	PostState         hexutil.Bytes
	Status            hexutil.Uint64
	CumulativeGasUsed hexutil.Uint64
	Payer             common.Address
	FrameReceipts     []frameReceiptMarshaling
	GasUsed           hexutil.Uint64
	EffectiveGasPrice *hexutil.Big
	BlobGasUsed       hexutil.Uint64
	BlobGasPrice      *hexutil.Big
	BlockNumber       *hexutil.Big
	TransactionIndex  hexutil.Uint
}

type frameReceiptMarshaling struct {
	Status  hexutil.Uint64
	GasUsed hexutil.Uint64
	Logs    []*Log
}

// receiptRLP is the consensus encoding of a receipt.
type receiptRLP struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Bloom             Bloom
	Logs              []*Log
}

// FrameReceipt represents the results of a single frame execution.
// For frame transactions, receipts are a list of these entries.
type FrameReceipt struct {
	Status  uint8  `json:"status"`
	GasUsed uint64 `json:"gasUsed"`
	Logs    []*Log `json:"logs"`
}

// frameReceiptRLP is the consensus encoding of a frame receipt entry.
type frameReceiptRLP struct {
	Status  uint8
	GasUsed uint64
	Logs    []*Log
}

// frameReceiptPayload is the consensus encoding for a frame transaction receipt.
// Payload: [cumulative_gas_used, payer, [frame_receipt, ...]]
type frameReceiptPayload struct {
	CumulativeGasUsed uint64
	Payer             common.Address
	FrameReceipts     []frameReceiptRLP
}

// storedReceiptRLP is the storage encoding of a receipt.
type storedReceiptRLP struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Logs              []*Log
}

// NewReceipt creates a barebone transaction receipt, copying the init fields.
// Deprecated: create receipts using a struct literal instead.
func NewReceipt(root []byte, failed bool, cumulativeGasUsed uint64) *Receipt {
	r := &Receipt{
		Type:              LegacyTxType,
		PostState:         common.CopyBytes(root),
		CumulativeGasUsed: cumulativeGasUsed,
	}
	if failed {
		r.Status = ReceiptStatusFailed
	} else {
		r.Status = ReceiptStatusSuccessful
	}
	return r
}

// EncodeRLP implements rlp.Encoder, and flattens the consensus fields of a receipt
// into an RLP stream. If no post state is present, byzantium fork is assumed.
func (r *Receipt) EncodeRLP(w io.Writer) error {
	if r.Type == LegacyTxType {
		return rlp.Encode(w, r.consensusPayload())
	}
	buf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(buf)
	buf.Reset()
	if r.Type == FrameTxType {
		if err := r.encodeTypedPayload(r.framePayload(), buf); err != nil {
			return err
		}
		return rlp.Encode(w, buf.Bytes())
	}
	if err := r.encodeTyped(r.consensusPayload(), buf); err != nil {
		return err
	}
	return rlp.Encode(w, buf.Bytes())
}

// encodeTyped writes the canonical encoding of a typed receipt to w.
func (r *Receipt) encodeTyped(data *receiptRLP, w *bytes.Buffer) error {
	return r.encodeTypedPayload(data, w)
}

// encodeTypedPayload writes the canonical encoding of a typed receipt to w
// using the provided payload.
func (r *Receipt) encodeTypedPayload(payload any, w *bytes.Buffer) error {
	w.WriteByte(r.Type)
	return rlp.Encode(w, payload)
}

// MarshalBinary returns the consensus encoding of the receipt.
func (r *Receipt) MarshalBinary() ([]byte, error) {
	if r.Type == LegacyTxType {
		return rlp.EncodeToBytes(r)
	}
	var buf bytes.Buffer
	var err error
	if r.Type == FrameTxType {
		err = r.encodeTypedPayload(r.framePayload(), &buf)
	} else {
		err = r.encodeTyped(r.consensusPayload(), &buf)
	}
	return buf.Bytes(), err
}

// DecodeRLP implements rlp.Decoder, and loads the consensus fields of a receipt
// from an RLP stream.
func (r *Receipt) DecodeRLP(s *rlp.Stream) error {
	kind, size, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == rlp.List:
		// It's a legacy receipt.
		var dec receiptRLP
		if err := s.Decode(&dec); err != nil {
			return err
		}
		r.Type = LegacyTxType
		return r.setFromRLP(dec)
	case kind == rlp.Byte:
		return errShortTypedReceipt
	default:
		// It's an EIP-2718 typed tx receipt.
		b, buf, err := getPooledBuffer(size)
		if err != nil {
			return err
		}
		defer encodeBufferPool.Put(buf)
		if err := s.ReadBytes(b); err != nil {
			return err
		}
		return r.decodeTyped(b)
	}
}

// UnmarshalBinary decodes the consensus encoding of receipts.
// It supports legacy RLP receipts and EIP-2718 typed receipts.
func (r *Receipt) UnmarshalBinary(b []byte) error {
	if len(b) > 0 && b[0] > 0x7f {
		// It's a legacy receipt decode the RLP
		var data receiptRLP
		err := rlp.DecodeBytes(b, &data)
		if err != nil {
			return err
		}
		r.Type = LegacyTxType
		return r.setFromRLP(data)
	}
	// It's an EIP2718 typed transaction envelope.
	return r.decodeTyped(b)
}

// decodeTyped decodes a typed receipt from the canonical format.
func (r *Receipt) decodeTyped(b []byte) error {
	if len(b) <= 1 {
		return errShortTypedReceipt
	}
	switch b[0] {
	case DynamicFeeTxType, AccessListTxType, BlobTxType, SetCodeTxType:
		var data receiptRLP
		err := rlp.DecodeBytes(b[1:], &data)
		if err != nil {
			return err
		}
		r.Type = b[0]
		return r.setFromRLP(data)
	case FrameTxType:
		var data frameReceiptPayload
		err := rlp.DecodeBytes(b[1:], &data)
		if err != nil {
			return err
		}
		r.Type = b[0]
		r.setFromFrameRLP(data)
		return nil
	default:
		return ErrTxTypeNotSupported
	}
}

func (r *Receipt) setFromRLP(data receiptRLP) error {
	r.CumulativeGasUsed, r.Bloom, r.Logs = data.CumulativeGasUsed, data.Bloom, data.Logs
	r.Payer = common.Address{}
	r.FrameReceipts = nil
	return r.setStatus(data.PostStateOrStatus)
}

func (r *Receipt) setFromFrameRLP(data frameReceiptPayload) {
	r.CumulativeGasUsed = data.CumulativeGasUsed
	r.Payer = data.Payer
	r.FrameReceipts = frameReceiptsFromRLP(data.FrameReceipts)
	r.Logs = flattenFrameLogs(r.FrameReceipts)
	r.Status = ReceiptStatusSuccessful
	r.PostState = nil
	r.Bloom = CreateBloom(r)
}

func frameReceiptsToRLP(frames []FrameReceipt) []frameReceiptRLP {
	if len(frames) == 0 {
		return nil
	}
	out := make([]frameReceiptRLP, len(frames))
	for i, fr := range frames {
		out[i] = frameReceiptRLP{
			Status:  fr.Status,
			GasUsed: fr.GasUsed,
			Logs:    fr.Logs,
		}
	}
	return out
}

func frameReceiptsFromRLP(frames []frameReceiptRLP) []FrameReceipt {
	if len(frames) == 0 {
		return nil
	}
	out := make([]FrameReceipt, len(frames))
	for i, fr := range frames {
		out[i] = FrameReceipt{
			Status:  fr.Status,
			GasUsed: fr.GasUsed,
			Logs:    fr.Logs,
		}
	}
	return out
}

func flattenFrameLogs(frames []FrameReceipt) []*Log {
	if len(frames) == 0 {
		return nil
	}
	var logs []*Log
	for _, fr := range frames {
		if len(fr.Logs) > 0 {
			logs = append(logs, fr.Logs...)
		}
	}
	return logs
}

func (r *Receipt) setStatus(postStateOrStatus []byte) error {
	r.PostState = nil
	r.Status = 0
	switch {
	case bytes.Equal(postStateOrStatus, receiptStatusSuccessfulRLP):
		r.Status = ReceiptStatusSuccessful
	case bytes.Equal(postStateOrStatus, receiptStatusFailedRLP):
		r.Status = ReceiptStatusFailed
	case len(postStateOrStatus) == len(common.Hash{}):
		r.PostState = postStateOrStatus
	default:
		return fmt.Errorf("invalid receipt status %x", postStateOrStatus)
	}
	return nil
}

func (r *Receipt) consensusPayload() *receiptRLP {
	return &receiptRLP{r.statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs}
}

func (r *Receipt) framePayload() *frameReceiptPayload {
	return &frameReceiptPayload{
		CumulativeGasUsed: r.CumulativeGasUsed,
		Payer:             r.Payer,
		FrameReceipts:     frameReceiptsToRLP(r.FrameReceipts),
	}
}

func (r *Receipt) statusEncoding() []byte {
	if len(r.PostState) == 0 {
		if r.Status == ReceiptStatusFailed {
			return receiptStatusFailedRLP
		}
		return receiptStatusSuccessfulRLP
	}
	return r.PostState
}

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (r *Receipt) Size() common.StorageSize {
	size := common.StorageSize(unsafe.Sizeof(*r)) + common.StorageSize(len(r.PostState))
	size += common.StorageSize(len(r.Logs)) * common.StorageSize(unsafe.Sizeof(Log{}))
	for _, log := range r.Logs {
		size += common.StorageSize(len(log.Topics)*common.HashLength + len(log.Data))
	}
	return size
}

// DeriveReceiptContext holds the contextual information needed to derive a receipt
type DeriveReceiptContext struct {
	BlockHash    common.Hash
	BlockNumber  uint64
	BlockTime    uint64
	BaseFee      *big.Int
	BlobGasPrice *big.Int
	GasUsed      uint64
	LogIndex     uint // Number of logs in the block until this receipt
	Tx           *Transaction
	TxIndex      uint
}

// DeriveFields fills the receipt with computed fields based on consensus
// data and contextual infos like containing block and transactions.
func (r *Receipt) DeriveFields(signer Signer, context DeriveReceiptContext) {
	// The transaction type and hash can be retrieved from the transaction itself
	r.Type = context.Tx.Type()
	r.TxHash = context.Tx.Hash()
	r.GasUsed = context.GasUsed
	r.EffectiveGasPrice = context.Tx.inner.effectiveGasPrice(new(big.Int), context.BaseFee)

	// EIP-4844 blob transaction fields
	if context.Tx.Type() == BlobTxType {
		r.BlobGasUsed = context.Tx.BlobGas()
		r.BlobGasPrice = context.BlobGasPrice
	}

	// Block location fields
	r.BlockHash = context.BlockHash
	r.BlockNumber = new(big.Int).SetUint64(context.BlockNumber)
	r.TransactionIndex = context.TxIndex

	// The contract address can be derived from the transaction itself
	if context.Tx.To() == nil {
		// Deriving the signer is expensive, only do if it's actually needed
		from, _ := Sender(signer, context.Tx)
		r.ContractAddress = crypto.CreateAddress(from, context.Tx.Nonce())
	} else {
		r.ContractAddress = common.Address{}
	}
	// The derived log fields can simply be set from the block and transaction
	logIndex := context.LogIndex
	for j := 0; j < len(r.Logs); j++ {
		r.Logs[j].BlockNumber = context.BlockNumber
		r.Logs[j].BlockHash = context.BlockHash
		r.Logs[j].BlockTimestamp = context.BlockTime
		r.Logs[j].TxHash = r.TxHash
		r.Logs[j].TxIndex = context.TxIndex
		r.Logs[j].Index = logIndex
		logIndex++
	}
	// Also derive the Bloom if not derived yet
	r.Bloom = CreateBloom(r)
}

// ReceiptForStorage is a wrapper around a Receipt with RLP serialization
// that omits the Bloom field. The Bloom field is recomputed by DeriveFields.
type ReceiptForStorage Receipt

// EncodeRLP implements rlp.Encoder, and flattens all content fields of a receipt
// into an RLP stream.
func (r *ReceiptForStorage) EncodeRLP(_w io.Writer) error {
	if r.Type == FrameTxType {
		buf := encodeBufferPool.Get().(*bytes.Buffer)
		defer encodeBufferPool.Put(buf)
		buf.Reset()
		buf.WriteByte(FrameTxType)
		if err := rlp.Encode(buf, (*Receipt)(r).framePayload()); err != nil {
			return err
		}
		return rlp.Encode(_w, buf.Bytes())
	}
	w := rlp.NewEncoderBuffer(_w)
	outerList := w.List()
	w.WriteBytes((*Receipt)(r).statusEncoding())
	w.WriteUint64(r.CumulativeGasUsed)
	logList := w.List()
	for _, log := range r.Logs {
		if err := log.EncodeRLP(w); err != nil {
			return err
		}
	}
	w.ListEnd(logList)
	w.ListEnd(outerList)
	return w.Flush()
}

// DecodeRLP implements rlp.Decoder, and loads both consensus and implementation
// fields of a receipt from an RLP stream.
func (r *ReceiptForStorage) DecodeRLP(s *rlp.Stream) error {
	kind, size, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == rlp.List:
		var stored storedReceiptRLP
		if err := s.Decode(&stored); err != nil {
			return err
		}
		r.Type = LegacyTxType
		if err := (*Receipt)(r).setStatus(stored.PostStateOrStatus); err != nil {
			return err
		}
		r.CumulativeGasUsed = stored.CumulativeGasUsed
		r.Logs = stored.Logs
		r.Bloom = Bloom{}
		r.Payer = common.Address{}
		r.FrameReceipts = nil
		return nil
	case kind == rlp.Byte:
		return errShortTypedReceipt
	default:
		b, buf, err := getPooledBuffer(size)
		if err != nil {
			return err
		}
		defer encodeBufferPool.Put(buf)
		if err := s.ReadBytes(b); err != nil {
			return err
		}
		if len(b) <= 1 {
			return errShortTypedReceipt
		}
		if b[0] != FrameTxType {
			return ErrTxTypeNotSupported
		}
		var payload frameReceiptPayload
		if err := rlp.DecodeBytes(b[1:], &payload); err != nil {
			return err
		}
		(*Receipt)(r).Type = b[0]
		(*Receipt)(r).setFromFrameRLP(payload)
		return nil
	}
}

// Receipts implements DerivableList for receipts.
type Receipts []*Receipt

// Len returns the number of receipts in this list.
func (rs Receipts) Len() int { return len(rs) }

// EncodeIndex encodes the i'th receipt to w.
func (rs Receipts) EncodeIndex(i int, w *bytes.Buffer) {
	r := rs[i]
	if r.Type == LegacyTxType {
		rlp.Encode(w, r.consensusPayload())
		return
	}
	w.WriteByte(r.Type)
	switch r.Type {
	case AccessListTxType, DynamicFeeTxType, BlobTxType, SetCodeTxType:
		rlp.Encode(w, r.consensusPayload())
	case FrameTxType:
		rlp.Encode(w, r.framePayload())
	default:
		// For unsupported types, write nothing. Since this is for
		// DeriveSha, the error will be caught matching the derived hash
		// to the block.
	}
}

// DeriveFields fills the receipts with their computed fields based on consensus
// data and contextual infos like containing block and transactions.
func (rs Receipts) DeriveFields(config *params.ChainConfig, blockHash common.Hash, blockNumber uint64, blockTime uint64, baseFee *big.Int, blobGasPrice *big.Int, txs []*Transaction) error {
	signer := MakeSigner(config, new(big.Int).SetUint64(blockNumber), blockTime)

	logIndex := uint(0)
	if len(txs) != len(rs) {
		return errors.New("transaction and receipt count mismatch")
	}
	for i := 0; i < len(rs); i++ {
		var cumulativeGasUsed uint64
		if i > 0 {
			cumulativeGasUsed = rs[i-1].CumulativeGasUsed
		}
		rs[i].DeriveFields(signer, DeriveReceiptContext{
			BlockHash:    blockHash,
			BlockNumber:  blockNumber,
			BlockTime:    blockTime,
			BaseFee:      baseFee,
			BlobGasPrice: blobGasPrice,
			GasUsed:      rs[i].CumulativeGasUsed - cumulativeGasUsed,
			LogIndex:     logIndex,
			Tx:           txs[i],
			TxIndex:      uint(i),
		})
		logIndex += uint(len(rs[i].Logs))
	}
	return nil
}

// EncodeBlockReceiptLists encodes a list of block receipt lists into RLP.
func EncodeBlockReceiptLists(receipts []Receipts) []rlp.RawValue {
	var storageReceipts []*ReceiptForStorage
	result := make([]rlp.RawValue, len(receipts))
	for i, receipt := range receipts {
		storageReceipts = storageReceipts[:0]
		for _, r := range receipt {
			storageReceipts = append(storageReceipts, (*ReceiptForStorage)(r))
		}
		bytes, err := rlp.EncodeToBytes(storageReceipts)
		if err != nil {
			log.Crit("Failed to encode block receipts", "err", err)
		}
		result[i] = bytes
	}
	return result
}

// SlimReceipt is a wrapper around a Receipt with RLP serialization that omits
// the Bloom field and includes the tx type. Used for era files.
type SlimReceipt Receipt

type slimReceiptRLP struct {
	Type              uint8
	StatusEncoding    []byte
	CumulativeGasUsed uint64
	Logs              []*Log
}

// EncodeRLP implements rlp.Encoder, encoding the receipt as
// [tx-type, post-state-or-status, cumulative-gas, logs].
func (r *SlimReceipt) EncodeRLP(w io.Writer) error {
	data := &slimReceiptRLP{r.Type, (*Receipt)(r).statusEncoding(), r.CumulativeGasUsed, r.Logs}
	return rlp.Encode(w, data)
}

// DecodeRLP implements rlp.Decoder.
func (r *SlimReceipt) DecodeRLP(s *rlp.Stream) error {
	var data slimReceiptRLP
	if err := s.Decode(&data); err != nil {
		return err
	}
	r.Type = data.Type
	r.CumulativeGasUsed = data.CumulativeGasUsed
	r.Logs = data.Logs
	return (*Receipt)(r).setStatus(data.StatusEncoding)
}
