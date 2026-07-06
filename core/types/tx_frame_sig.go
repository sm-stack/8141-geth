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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256r1"
)

const (
	signatureLengthSecp256k1 = 65
	signatureLengthP256      = 128
)

func validateTxSignature(sig TxSignature) error {
	switch sig.Scheme {
	case SignatureSchemeSecp256k1:
		if len(sig.Signature) != signatureLengthSecp256k1 {
			return fmt.Errorf("secp256k1 signature length %d, want %d", len(sig.Signature), signatureLengthSecp256k1)
		}
	case SignatureSchemeP256:
		if len(sig.Signature) != signatureLengthP256 {
			return fmt.Errorf("p256 signature length %d, want %d", len(sig.Signature), signatureLengthP256)
		}
	default:
		return fmt.Errorf("unsupported scheme %d", sig.Scheme)
	}
	switch len(sig.Msg) {
	case 0:
		return nil
	case common.HashLength:
		if bytes.Equal(sig.Msg, make([]byte, common.HashLength)) {
			return errors.New("explicit signature msg must not be zero")
		}
		return nil
	default:
		return fmt.Errorf("signature msg length %d, want 0 or 32", len(sig.Msg))
	}
}

// ValidateFrameTxSignatures verifies every transaction-level signature against
// either the canonical frame transaction sig hash or its explicit 32-byte msg.
func ValidateFrameTxSignatures(tx *FrameTx, sigHash common.Hash) error {
	for i, sig := range tx.Signatures {
		if err := validateTxSignature(sig); err != nil {
			return fmt.Errorf("invalid signature %d: %w", i, err)
		}
		if err := verifyTxSignature(sig, sigHash); err != nil {
			return fmt.Errorf("invalid signature %d: %w", i, err)
		}
	}
	return nil
}

func verifyTxSignature(sig TxSignature, sigHash common.Hash) error {
	msg := sig.Msg
	if len(msg) == 0 {
		msg = sigHash[:]
	}
	switch sig.Scheme {
	case SignatureSchemeSecp256k1:
		return verifySecp256k1TxSignature(sig, msg)
	case SignatureSchemeP256:
		return verifyP256TxSignature(sig, msg)
	default:
		return fmt.Errorf("unsupported scheme %d", sig.Scheme)
	}
}

func verifySecp256k1TxSignature(sig TxSignature, msg []byte) error {
	if len(sig.Signature) != signatureLengthSecp256k1 {
		return fmt.Errorf("secp256k1 signature length %d, want %d", len(sig.Signature), signatureLengthSecp256k1)
	}
	if sig.Signature[0] > 1 {
		return fmt.Errorf("secp256k1 recovery id %d, want 0 or 1", sig.Signature[0])
	}
	var compact [signatureLengthSecp256k1]byte
	copy(compact[0:32], sig.Signature[1:33])
	copy(compact[32:64], sig.Signature[33:65])
	compact[64] = sig.Signature[0]
	pub, err := crypto.SigToPub(msg, compact[:])
	if err != nil {
		return err
	}
	if recovered := crypto.PubkeyToAddress(*pub); recovered != sig.Signer {
		return fmt.Errorf("recovered signer %s, want %s", recovered, sig.Signer)
	}
	return nil
}

func verifyP256TxSignature(sig TxSignature, msg []byte) error {
	if len(sig.Signature) != signatureLengthP256 {
		return fmt.Errorf("p256 signature length %d, want %d", len(sig.Signature), signatureLengthP256)
	}
	r := new(big.Int).SetBytes(sig.Signature[0:32])
	s := new(big.Int).SetBytes(sig.Signature[32:64])
	qx := new(big.Int).SetBytes(sig.Signature[64:96])
	qy := new(big.Int).SetBytes(sig.Signature[96:128])
	addrHash := crypto.Keccak256(sig.Signature[64:128])
	if derived := common.BytesToAddress(addrHash[12:]); derived != sig.Signer {
		return fmt.Errorf("p256 public key address %s, want %s", derived, sig.Signer)
	}
	if !secp256r1.Verify(msg, r, s, qx, qy) {
		return errors.New("p256 signature verification failed")
	}
	return nil
}
