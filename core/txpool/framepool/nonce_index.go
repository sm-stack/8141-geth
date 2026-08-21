// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// checkNonceKeyAdmission resolves exact replacement and rejects nonce-domain
// overlap. The caller must hold p.mu.
func (p *FramePool) checkNonceKeyAdmission(frameTx *types.FrameTx) (*types.Transaction, int, error) {
	const noReplacement = -1

	sender := frameTx.Sender
	owners := p.nonceKeyOwner[sender]
	for _, key := range frameTx.NonceKeys {
		owner, ok := owners[nonceKeyID(key)]
		if !ok {
			continue
		}
		previous := p.all[owner]
		if previous != nil {
			if previousFrameTx := previous.GetFrameTx(); previousFrameTx != nil &&
				frameTx.NonceSeq == previousFrameTx.NonceSeq && frameTx.NonceKeySetEqual(previousFrameTx) &&
				nonceKeySetOwnedBy(owners, frameTx.NonceKeys, owner) {
				for index, pendingTx := range p.pending[sender] {
					if pendingTx.Hash() == owner {
						return previous, index, nil
					}
				}
			}
		}
		return nil, noReplacement, fmt.Errorf("%w: sender %s nonce key %x overlaps pending transaction %s", txpool.ErrAccountLimitExceeded, sender, key.Bytes32(), owner)
	}
	if frameTx.UsesLegacyNonce() && len(p.pending[sender]) > 0 {
		return nil, noReplacement, fmt.Errorf("%w: sender %s legacy nonce domain is exclusive", txpool.ErrAccountLimitExceeded, sender)
	}
	if !frameTx.UsesLegacyNonce() {
		if owner, ok := owners[common.Hash{}]; ok {
			return nil, noReplacement, fmt.Errorf("%w: sender %s has pending legacy nonce transaction %s", txpool.ErrAccountLimitExceeded, sender, owner)
		}
	}
	if pending := len(p.pending[sender]); pending >= p.limits.maxPendingPerSender {
		return nil, noReplacement, fmt.Errorf("%w: sender %s has %d pending frame transactions", txpool.ErrAccountLimitExceeded, sender, pending)
	}
	return nil, noReplacement, nil
}

// reserveNonceKeys assigns every nonce domain of tx to its hash. The caller
// must hold p.mu and must have checked nonce-key admission first.
func (p *FramePool) reserveNonceKeys(tx *types.Transaction) {
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return
	}
	owners := p.nonceKeyOwner[frameTx.Sender]
	if owners == nil {
		owners = make(map[common.Hash]common.Hash)
		p.nonceKeyOwner[frameTx.Sender] = owners
	}
	hash := tx.Hash()
	for _, key := range frameTx.NonceKeys {
		owners[nonceKeyID(key)] = hash
	}
}

// releaseNonceKeys removes only domains still owned by tx. The ownership check
// prevents a stale removal from releasing a replacement's domains.
func (p *FramePool) releaseNonceKeys(tx *types.Transaction) {
	frameTx := tx.GetFrameTx()
	if frameTx == nil {
		return
	}
	owners := p.nonceKeyOwner[frameTx.Sender]
	hash := tx.Hash()
	for _, key := range frameTx.NonceKeys {
		id := nonceKeyID(key)
		if owners[id] == hash {
			delete(owners, id)
		}
	}
	if len(owners) == 0 {
		delete(p.nonceKeyOwner, frameTx.Sender)
	}
}

func nonceKeyID(key *uint256.Int) common.Hash {
	return common.Hash(key.Bytes32())
}

func nonceKeySetOwnedBy(owners map[common.Hash]common.Hash, keys []*uint256.Int, owner common.Hash) bool {
	for _, key := range keys {
		if owners[nonceKeyID(key)] != owner {
			return false
		}
	}
	return true
}
