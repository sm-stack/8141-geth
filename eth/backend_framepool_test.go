// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package eth

import (
	"testing"

	"github.com/ethereum/go-ethereum/core/txpool/framepool"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func TestValidateFramePoolNetworkPolicy(t *testing.T) {
	networked := p2p.Config{MaxPeers: 50, ListenAddr: ":30303", DiscoveryV4: true}
	if err := validateFramePoolNetworkPolicy(framepool.PublicMaxVerifyGas, networked); err != nil {
		t.Fatalf("public validation limit must be accepted on networked nodes: %v", err)
	}
	if err := validateFramePoolNetworkPolicy(framepool.PublicMaxVerifyGas+1, networked); err == nil {
		t.Fatal("validation limit above public maximum must be rejected on networked nodes")
	}
	isolated := p2p.Config{MaxPeers: 0, NoDial: true, NoDiscovery: true}
	if err := validateFramePoolNetworkPolicy(500_000, isolated); err != nil {
		t.Fatalf("isolated private node must allow an explicit PoC validation limit: %v", err)
	}
	trusted := isolated
	trusted.TrustedNodes = []*enode.Node{new(enode.Node)}
	if err := validateFramePoolNetworkPolicy(500_000, trusted); err == nil {
		t.Fatal("a node with trusted peers must not use the private validation override")
	}
}
