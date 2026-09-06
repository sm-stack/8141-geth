// Copyright 2020 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/cmd/devp2p/internal/ethtest"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/urfave/cli/v2"
)

// decodeRLPxDisconnect parses a disconnect message payload. Per the RLPx spec
// the payload is a list containing a single reason, but some implementations
// (including older geth) sent the reason as a bare byte. Accept both forms.
func decodeRLPxDisconnect(data []byte) (p2p.DiscReason, error) {
	s := rlp.NewStream(bytes.NewReader(data), uint64(len(data)))
	k, _, err := s.Kind()
	if err != nil {
		return 0, err
	}
	var reason p2p.DiscReason
	if k == rlp.List {
		if _, err := s.List(); err != nil {
			return 0, err
		}
		if err := s.Decode(&reason); err != nil {
			return 0, err
		}
		return reason, nil
	}
	if err := s.Decode(&reason); err != nil {
		return 0, err
	}
	return reason, nil
}

var (
	rlpxCommand = &cli.Command{
		Name:  "rlpx",
		Usage: "RLPx Commands",
		Subcommands: []*cli.Command{
			rlpxPingCommand,
			rlpxEthTestCommand,
			rlpxSnapTestCommand,
			rlpxSnap2TestCommand,
			rlpxFrameLoadCommand,
			rlpxFrameMassCommand,
			rlpxFrameMassStreamCommand,
		},
	}
	rlpxPingCommand = &cli.Command{
		Name:   "ping",
		Usage:  "ping <node>",
		Action: rlpxPing,
	}
	rlpxEthTestCommand = &cli.Command{
		Name:      "eth-test",
		Usage:     "Runs eth protocol tests against a node",
		ArgsUsage: "<node>",
		Action:    rlpxEthTest,
		Flags: []cli.Flag{
			testPatternFlag,
			testTAPFlag,
			testChainDirFlag,
			testNodeFlag,
			testNodeJWTFlag,
			testNodeEngineFlag,
		},
	}
	rlpxSnapTestCommand = &cli.Command{
		Name:      "snap-test",
		Usage:     "Runs snap protocol tests against a node",
		ArgsUsage: "",
		Action:    rlpxSnapTest,
		Flags: []cli.Flag{
			testPatternFlag,
			testTAPFlag,
			testChainDirFlag,
			testNodeFlag,
			testNodeJWTFlag,
			testNodeEngineFlag,
		},
	}
	rlpxSnap2TestCommand = &cli.Command{
		Name:      "snap2-test",
		Usage:     "Runs snap/2 (EIP-8189) protocol tests against a node",
		ArgsUsage: "",
		Action:    rlpxSnap2Test,
		Flags: []cli.Flag{
			testPatternFlag,
			testTAPFlag,
			testChainDirFlag,
			testNodeFlag,
			testNodeJWTFlag,
			testNodeEngineFlag,
		},
	}
	rlpxFrameLoadCommand = &cli.Command{
		Name:      "frame-load",
		Usage:     "Send adversarial frame transactions over real RLPx peers",
		ArgsUsage: "<node>",
		Action:    rlpxFrameLoad,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "corpus", Value: "bls", Usage: "workload corpus: arithmetic, bls, or an EIP-8141 validation-split shape"},
			&cli.Uint64Flag{Name: "chain-id", Value: 1337, Usage: "frame transaction chain ID"},
			&cli.Uint64Flag{Name: "verify-gas", Value: 100_000, Usage: "VERIFY frame gas limit"},
			&cli.IntFlag{Name: "peers", Value: 16, Usage: "parallel RLPx peers"},
			&cli.IntFlag{Name: "batch", Value: 1, Usage: "transactions per eth/Transactions packet"},
			&cli.IntFlag{Name: "rate", Value: 100, Usage: "total requested transactions per second (0 is unbounded)"},
			&cli.DurationFlag{Name: "duration", Value: 30 * time.Second, Usage: "load duration"},
		},
	}
	rlpxFrameMassCommand = &cli.Command{
		Name:      "frame-mass",
		Usage:     "Fill the framepool once with valid shared-payer transactions",
		ArgsUsage: "<node>",
		Action:    rlpxFrameMass,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "corpus", Value: "bls", Usage: "workload corpus (bls)"},
			&cli.StringFlag{Name: "payer-mode", Value: "canonical", Usage: "payer fixture: canonical or default-eoa"},
			&cli.Uint64Flag{Name: "chain-id", Value: 1337, Usage: "frame transaction chain ID"},
			&cli.Uint64Flag{Name: "verify-gas", Value: 100_000, Usage: "combined signature and VERIFY-frame gas"},
			&cli.IntFlag{Name: "count", Value: 256, Usage: "unique sender transactions to write"},
			&cli.IntFlag{Name: "peers", Value: 1, Usage: "parallel RLPx peers"},
			&cli.IntFlag{Name: "batch", Value: 16, Usage: "transactions per eth/Transactions packet"},
			&cli.DurationFlag{Name: "settle", Value: time.Second, Usage: "time to keep peers open after the final write"},
		},
	}
	rlpxFrameMassStreamCommand = &cli.Command{
		Name:      "frame-mass-stream",
		Usage:     "Continuously replay shared-payer frame transactions over real RLPx peers",
		ArgsUsage: "<node>",
		Action:    rlpxFrameMassStream,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "corpus", Value: "bls", Usage: "workload corpus (bls)"},
			&cli.StringFlag{Name: "payer-mode", Value: "canonical", Usage: "payer fixture: canonical or default-eoa"},
			&cli.StringFlag{Name: "hash-mode", Value: "exact", Usage: "transaction hash mode: exact or unique"},
			&cli.Uint64Flag{Name: "chain-id", Value: 1337, Usage: "frame transaction chain ID"},
			&cli.Uint64Flag{Name: "verify-gas", Value: 100_000, Usage: "combined signature and VERIFY-frame gas"},
			&cli.IntFlag{Name: "count", Value: 256, Usage: "unique sender transactions per manifest"},
			&cli.IntFlag{Name: "peers", Value: 16, Usage: "parallel RLPx peers"},
			&cli.IntFlag{Name: "batch", Value: 128, Usage: "transactions per eth/Transactions packet (must not exceed count)"},
			&cli.IntFlag{Name: "rate", Value: 25, Usage: "total requested transactions per second"},
			&cli.DurationFlag{Name: "duration", Value: 30 * time.Second, Usage: "stream duration"},
		},
	}
)

func rlpxPing(ctx *cli.Context) error {
	n := getNodeArg(ctx)
	tcpEndpoint, ok := n.TCPEndpoint()
	if !ok {
		return errors.New("node has no TCP endpoint")
	}
	fd, err := net.Dial("tcp", tcpEndpoint.String())
	if err != nil {
		return err
	}
	conn := rlpx.NewConn(fd, n.Pubkey())
	ourKey, _ := crypto.GenerateKey()
	_, err = conn.Handshake(ourKey)
	if err != nil {
		return err
	}
	code, data, _, err := conn.Read()
	if err != nil {
		return err
	}
	switch code {
	case 0:
		var h ethtest.Hello
		if err := rlp.DecodeBytes(data, &h); err != nil {
			return fmt.Errorf("invalid handshake: %v", err)
		}
		fmt.Printf("%+v\n", h)
	case 1:
		// The disconnect message is specified as a list containing the reason,
		// but some implementations (including older geth) send the reason as a
		// single byte. Handle both forms, and on failure include the raw payload
		// so the operator can see what was actually sent.
		reason, decErr := decodeRLPxDisconnect(data)
		if decErr != nil {
			return fmt.Errorf("invalid disconnect message: %v (raw=0x%x)", decErr, data)
		}
		return fmt.Errorf("received disconnect message: %v", reason)
	default:
		return fmt.Errorf("invalid message code %d, expected handshake (code zero) or disconnect (code one)", code)
	}
	return nil
}

// rlpxEthTest runs the eth protocol test suite.
func rlpxEthTest(ctx *cli.Context) error {
	p := cliTestParams(ctx)
	suite, err := ethtest.NewSuite(p.node, p.chainDir, p.engineAPI, p.jwt)
	if err != nil {
		exit(err)
	}
	return runTests(ctx, suite.EthTests())
}

// rlpxSnapTest runs the snap protocol test suite.
func rlpxSnapTest(ctx *cli.Context) error {
	p := cliTestParams(ctx)
	suite, err := ethtest.NewSuite(p.node, p.chainDir, p.engineAPI, p.jwt)
	if err != nil {
		exit(err)
	}
	return runTests(ctx, suite.SnapTests())
}

// rlpxSnap2Test runs the snap/2 (EIP-8189) protocol test suite.
func rlpxSnap2Test(ctx *cli.Context) error {
	p := cliTestParams(ctx)
	suite, err := ethtest.NewSuite(p.node, p.chainDir, p.engineAPI, p.jwt)
	if err != nil {
		exit(err)
	}
	return runTests(ctx, suite.Snap2Tests())
}

func rlpxFrameLoad(ctx *cli.Context) error {
	result, err := ethtest.RunFrameLoad(ctx.Context, ethtest.FrameLoadConfig{
		Dest:      getNodeArg(ctx),
		Corpus:    ctx.String("corpus"),
		ChainID:   ctx.Uint64("chain-id"),
		VerifyGas: ctx.Uint64("verify-gas"),
		Peers:     ctx.Int("peers"),
		Batch:     ctx.Int("batch"),
		Rate:      ctx.Int("rate"),
		Duration:  ctx.Duration("duration"),
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func rlpxFrameMass(ctx *cli.Context) error {
	result, err := ethtest.RunFrameMass(ctx.Context, ethtest.FrameMassConfig{
		Dest:      getNodeArg(ctx),
		Corpus:    ctx.String("corpus"),
		PayerMode: ctx.String("payer-mode"),
		ChainID:   ctx.Uint64("chain-id"),
		VerifyGas: ctx.Uint64("verify-gas"),
		Count:     ctx.Int("count"),
		Peers:     ctx.Int("peers"),
		Batch:     ctx.Int("batch"),
		Settle:    ctx.Duration("settle"),
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func rlpxFrameMassStream(ctx *cli.Context) error {
	result, err := ethtest.RunFrameMassStream(ctx.Context, ethtest.FrameMassStreamConfig{
		Dest:      getNodeArg(ctx),
		Corpus:    ctx.String("corpus"),
		PayerMode: ctx.String("payer-mode"),
		HashMode:  ctx.String("hash-mode"),
		ChainID:   ctx.Uint64("chain-id"),
		VerifyGas: ctx.Uint64("verify-gas"),
		Count:     ctx.Int("count"),
		Peers:     ctx.Int("peers"),
		Batch:     ctx.Int("batch"),
		Rate:      ctx.Int("rate"),
		Duration:  ctx.Duration("duration"),
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

type testParams struct {
	node      *enode.Node
	engineAPI string
	jwt       string
	chainDir  string
}

func cliTestParams(ctx *cli.Context) *testParams {
	nodeStr := ctx.String(testNodeFlag.Name)
	node, err := parseNode(nodeStr)
	if err != nil {
		exit(err)
	}
	p := testParams{
		node:      node,
		engineAPI: ctx.String(testNodeEngineFlag.Name),
		jwt:       ctx.String(testNodeJWTFlag.Name),
		chainDir:  ctx.String(testChainDirFlag.Name),
	}
	return &p
}
