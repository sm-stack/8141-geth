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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool/framepool"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
)

func TestValidateFramePoolNetworkPolicy(t *testing.T) {
	networked := p2p.Config{MaxPeers: 50, ListenAddr: ":30303", DiscoveryV4: true}
	if err := validateFramePoolNetworkPolicy(framepool.DefaultConfig, 1, params.MainnetGenesisHash, networked, []string{"enrtree://mainnet"}, nil); err != nil {
		t.Fatalf("public validation limit must be accepted on networked nodes: %v", err)
	}
	bounded := framepool.DefaultConfig
	bounded.MaxStateDependentVerifyGas = 20_000
	bounded.CacheValidationPrecompiles = true
	bounded.ValidationMemoMaxEntries = 4
	bounded.ValidationMemoMaxBytes = 8192
	if err := validateFramePoolNetworkPolicy(bounded, 1, params.MainnetGenesisHash, networked, []string{"enrtree://mainnet"}, nil); err != nil {
		t.Fatalf("bounded state policy and memo must not require the unsafe acceptance override: %v", err)
	}
	for _, mutate := range []func(*framepool.Config){
		func(config *framepool.Config) { config.MaxVerifyGas++ },
		func(config *framepool.Config) { config.MaxPendingPerSender++ },
		func(config *framepool.Config) { config.MaxPendingPerNonCanonicalPaymaster++ },
	} {
		config := framepool.DefaultConfig
		mutate(&config)
		if err := validateFramePoolNetworkPolicy(config, 1337, common.Hash{}, p2p.Config{NoDiscovery: true}, nil, nil); err == nil {
			t.Fatal("raised policy was accepted without the benchmark override")
		}
	}

	unsafe := framepool.DefaultConfig
	unsafe.MaxVerifyGas = 500_000
	unsafe.MaxPendingPerSender = 8
	unsafe.MaxPendingPerNonCanonicalPaymaster = 16
	unsafe.AllowUnsafeBenchmarkPolicy = true
	// NoDiscovery is authoritative even though the protocol-specific defaults
	// remain true when --nodiscover is applied.
	private := p2p.Config{MaxPeers: 50, ListenAddr: ":30303", NoDiscovery: true, DiscoveryV4: true, DiscoveryV5: true}
	if err := validateFramePoolNetworkPolicy(unsafe, 1337, common.Hash{}, private, nil, nil); err != nil {
		t.Fatalf("private no-discovery benchmark network rejected: %v", err)
	}
	if err := validateFramePoolNetworkPolicy(unsafe, 1, common.Hash{}, private, nil, nil); err == nil {
		t.Fatal("mainnet network ID accepted an unsafe benchmark policy")
	}
	if err := validateFramePoolNetworkPolicy(unsafe, 1337, params.MainnetGenesisHash, private, nil, nil); err == nil {
		t.Fatal("mainnet genesis accepted an unsafe benchmark policy")
	}
	if err := validateFramePoolNetworkPolicy(unsafe, 1337, common.Hash{}, networked, nil, nil); err == nil {
		t.Fatal("discovery-enabled P2P accepted an unsafe benchmark policy")
	}
	if err := validateFramePoolNetworkPolicy(unsafe, 1337, common.Hash{}, private, []string{"enrtree://benchmark"}, nil); err == nil {
		t.Fatal("DNS discovery accepted an unsafe benchmark policy")
	}
}
