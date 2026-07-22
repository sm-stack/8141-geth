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
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

func (r RecentRootRef) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SourceID common.Hash    `json:"sourceId"`
		Slot     hexutil.Uint64 `json:"slot"`
		Root     common.Hash    `json:"root"`
	}{r.SourceID, hexutil.Uint64(r.Slot), r.Root})
}

func (r *RecentRootRef) UnmarshalJSON(input []byte) error {
	var dec struct {
		SourceID *common.Hash    `json:"sourceId"`
		Slot     *hexutil.Uint64 `json:"slot"`
		Root     *common.Hash    `json:"root"`
	}
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.SourceID == nil {
		return errors.New("missing required field 'sourceId' for recent root reference")
	}
	if dec.Slot == nil {
		return errors.New("missing required field 'slot' for recent root reference")
	}
	if dec.Root == nil {
		return errors.New("missing required field 'root' for recent root reference")
	}
	r.SourceID, r.Slot, r.Root = *dec.SourceID, uint64(*dec.Slot), *dec.Root
	return nil
}

var (
	recentRootEntryDomain   = crypto.Keccak256Hash([]byte("RECENT_ROOT_ENTRY"))
	recentRootStorageDomain = crypto.Keccak256Hash([]byte("RECENT_ROOT_STORAGE"))
)

func RecentRootSourceID(source common.Address, salt common.Hash) common.Hash {
	return crypto.Keccak256Hash(source[:], salt[:])
}

func RecentRootEntryHash(sourceID common.Hash, slot uint64, root common.Hash) common.Hash {
	var slotBytes [8]byte
	binary.BigEndian.PutUint64(slotBytes[:], slot)
	return crypto.Keccak256Hash(recentRootEntryDomain[:], sourceID[:], slotBytes[:], root[:])
}

func RecentRootStorageKey(sourceID common.Hash, slot uint64) common.Hash {
	var indexBytes [8]byte
	binary.BigEndian.PutUint64(indexBytes[:], slot%params.RecentRootWindow)
	return crypto.Keccak256Hash(recentRootStorageDomain[:], sourceID[:], indexBytes[:])
}

func RecentRootReferenceInWindow(currentSlot, slot uint64) bool {
	return slot < currentSlot && currentSlot-slot < params.RecentRootWindow
}
