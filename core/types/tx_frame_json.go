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
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/holiman/uint256"
)

// MarshalJSON marshals a frame using RPC quantity/bytes encoding.
func (f Frame) MarshalJSON() ([]byte, error) {
	type frameJSON struct {
		Mode          hexutil.Uint64  `json:"mode"`
		Flags         hexutil.Uint64  `json:"flags"`
		Target        *common.Address `json:"target"`
		GasLimit      hexutil.Uint64  `json:"gasLimit"`
		StateGasLimit hexutil.Uint64  `json:"stateGasLimit"`
		Value         *hexutil.Big    `json:"value"`
		Data          hexutil.Bytes   `json:"data"`
	}
	value := new(big.Int)
	if f.Value != nil {
		value = f.Value.ToBig()
	}
	return json.Marshal(&frameJSON{
		Mode:          hexutil.Uint64(f.Mode),
		Flags:         hexutil.Uint64(f.Flags),
		Target:        f.Target,
		GasLimit:      hexutil.Uint64(f.GasLimit),
		StateGasLimit: hexutil.Uint64(f.StateGasLimit),
		Value:         (*hexutil.Big)(value),
		Data:          hexutil.Bytes(f.Data),
	})
}

// UnmarshalJSON unmarshals a frame from RPC quantity/bytes encoding.
func (f *Frame) UnmarshalJSON(input []byte) error {
	type frameJSON struct {
		Mode          *hexutil.Uint64 `json:"mode"`
		Flags         *hexutil.Uint64 `json:"flags"`
		Target        *common.Address `json:"target"`
		GasLimit      *hexutil.Uint64 `json:"gasLimit"`
		StateGasLimit *hexutil.Uint64 `json:"stateGasLimit"`
		Value         *hexutil.Big    `json:"value"`
		Data          *hexutil.Bytes  `json:"data"`
	}
	var dec frameJSON
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Mode == nil {
		return errors.New("missing required field 'mode' in frame")
	}
	if *dec.Mode > 0xff {
		return errors.New("'mode' value overflows uint8")
	}
	f.Mode = uint8(*dec.Mode)
	if dec.Flags == nil {
		return errors.New("missing required field 'flags' in frame")
	}
	if *dec.Flags > 0xff {
		return errors.New("'flags' value overflows uint8")
	}
	f.Flags = uint8(*dec.Flags)
	f.Target = dec.Target
	if dec.GasLimit == nil {
		return errors.New("missing required field 'gasLimit' in frame")
	}
	f.GasLimit = uint64(*dec.GasLimit)
	if dec.StateGasLimit == nil {
		return errors.New("missing required field 'stateGasLimit' in frame")
	}
	f.StateGasLimit = uint64(*dec.StateGasLimit)
	if dec.Value == nil {
		return errors.New("missing required field 'value' in frame")
	}
	value, overflow := uint256.FromBig(dec.Value.ToInt())
	if overflow {
		return errors.New("'value' value overflows uint256")
	}
	f.Value = value
	if dec.Data == nil {
		return errors.New("missing required field 'data' in frame")
	}
	f.Data = common.CopyBytes(*dec.Data)
	return nil
}

// MarshalJSON marshals a transaction-level signature using RPC encoding.
func (sig TxSignature) MarshalJSON() ([]byte, error) {
	type txSignatureJSON struct {
		Scheme    hexutil.Uint64 `json:"scheme"`
		Signer    common.Address `json:"signer"`
		Msg       hexutil.Bytes  `json:"msg"`
		Signature hexutil.Bytes  `json:"signature"`
	}
	return json.Marshal(&txSignatureJSON{
		Scheme:    hexutil.Uint64(sig.Scheme),
		Signer:    sig.Signer,
		Msg:       hexutil.Bytes(sig.Msg),
		Signature: hexutil.Bytes(sig.Signature),
	})
}

// UnmarshalJSON unmarshals a transaction-level signature from RPC encoding.
func (sig *TxSignature) UnmarshalJSON(input []byte) error {
	type txSignatureJSON struct {
		Scheme    *hexutil.Uint64 `json:"scheme"`
		Signer    *common.Address `json:"signer"`
		Msg       *hexutil.Bytes  `json:"msg"`
		Signature *hexutil.Bytes  `json:"signature"`
	}
	var dec txSignatureJSON
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Scheme == nil {
		return errors.New("missing required field 'scheme' in tx signature")
	}
	if *dec.Scheme > 0xff {
		return errors.New("'scheme' value overflows uint8")
	}
	sig.Scheme = uint8(*dec.Scheme)
	sig.signerPresent = false
	if dec.Signer == nil {
		return errors.New("missing required field 'signer' in tx signature")
	}
	sig.Signer = *dec.Signer
	if dec.Msg == nil {
		return errors.New("missing required field 'msg' in tx signature")
	}
	sig.Msg = common.CopyBytes(*dec.Msg)
	if dec.Signature == nil {
		return errors.New("missing required field 'signature' in tx signature")
	}
	sig.Signature = common.CopyBytes(*dec.Signature)
	return nil
}
