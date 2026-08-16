// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package ethtest

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

var (
	// FrameLoadArithmeticSender and FrameLoadBLSSender are pre-funded contract
	// accounts installed by benchmark/genesis.json.
	FrameLoadArithmeticSender = common.HexToAddress("0x1111111111111111111111111111111111111111")
	FrameLoadBLSSender        = common.HexToAddress("0x2222222222222222222222222222222222222222")

	frameLoadArithmeticCode = common.FromHex("0x5f355b600190038060025700")
	frameLoadBLSCode        = common.FromHex("0x60a05f5f3760a0355b5f5f60a05f61000c5afa5060019003806008575000")
	frameLoadBLSInput       = common.FromHex("0x0000000000000000000000000000000002c7919b322a84cb1e6164043d745a53535edad9ef74533d3155900d4e1d63674b2616d87ca8b3dac6def99441cf196c00000000000000000000000000000000069f2ddefcadf0463b0c40e389837d1079781e04ccd8262623d5df6fb1989973ef6fcb8628b978a088e4f043f54d54391824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffd")
)

const (
	frameLoadArithmeticFixedGas uint64 = 5
	frameLoadArithmeticLoopGas  uint64 = 26
	frameLoadBLSFixedGas        uint64 = 48
	frameLoadBLSLoopGas         uint64 = 12_142
)

// FrameLoadConfig controls an adversarial frame-transaction load run.
type FrameLoadConfig struct {
	Dest      *enode.Node
	Corpus    string
	ChainID   uint64
	VerifyGas uint64
	Peers     int
	Batch     int
	Rate      int
	Duration  time.Duration
}

// FrameLoadResult is emitted as one structured record by the CLI.
type FrameLoadResult struct {
	SchemaVersion       int      `json:"schema_version"`
	Corpus              string   `json:"corpus"`
	ChainID             uint64   `json:"chain_id"`
	VerifyGas           uint64   `json:"verify_gas"`
	Peers               int      `json:"peers"`
	Batch               int      `json:"batch"`
	RequestedTPS        int      `json:"requested_tps"`
	DurationMS          int64    `json:"duration_ms"`
	Attempted           uint64   `json:"attempted"`
	Sent                uint64   `json:"sent"`
	Packets             uint64   `json:"packets"`
	UncompressedTxBytes uint64   `json:"uncompressed_tx_bytes"`
	ActualTPS           float64  `json:"actual_tps"`
	WriteErrors         uint64   `json:"write_errors"`
	ReadErrors          uint64   `json:"read_errors"`
	PeerDisconnects     uint64   `json:"peer_disconnects"`
	OtherErrors         uint64   `json:"other_errors"`
	Errors              []string `json:"errors,omitempty"`
}

type frameLoadCounters struct {
	sequence     atomic.Uint64
	attempted    atomic.Uint64
	sent         atomic.Uint64
	packets      atomic.Uint64
	payloadBytes atomic.Uint64
	readErrors   atomic.Uint64
	writeErrors  atomic.Uint64
	disconnects  atomic.Uint64
	otherErrors  atomic.Uint64

	mu     sync.Mutex
	errors []string
}

func (c *frameLoadCounters) recordReadError(err error) {
	c.readErrors.Add(1)
	c.appendError(err)
}

func (c *frameLoadCounters) recordWriteError(err error) {
	c.writeErrors.Add(1)
	c.appendError(err)
}

func (c *frameLoadCounters) recordDisconnect(err error) {
	c.disconnects.Add(1)
	c.appendError(err)
}

func (c *frameLoadCounters) recordOtherError(err error) {
	c.otherErrors.Add(1)
	c.appendError(err)
}

func (c *frameLoadCounters) appendError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.errors) < 16 {
		c.errors = append(c.errors, err.Error())
	}
}

type frameLoadConn struct {
	*Conn
	writeMu sync.Mutex
}

func frameLoadPongPayload() []any {
	// devp2p Ping and Pong carry an empty RLP list. Passing an untyped nil to
	// Conn.Write makes reflect-based RLP encoding panic when a long-running
	// benchmark receives Geth's periodic Ping.
	return []any{}
}

func (c *frameLoadConn) write(proto Proto, code uint64, msg any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Write(proto, code, msg)
}

// FrameLoadGenesisCode returns the runtime bytecode expected at the two
// benchmark sender addresses.
func FrameLoadGenesisCode() map[common.Address][]byte {
	return map[common.Address][]byte{
		FrameLoadArithmeticSender: common.CopyBytes(frameLoadArithmeticCode),
		FrameLoadBLSSender:        common.CopyBytes(frameLoadBLSCode),
	}
}

func mirrorStatusPeer(s *Suite) (*frameLoadConn, error) {
	conn, err := s.dial()
	if err != nil {
		return nil, err
	}
	if err := conn.handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	for {
		code, data, err := conn.Read()
		if err != nil {
			conn.Close()
			return nil, err
		}
		switch code {
		case eth.StatusMsg + protoOffset(ethProto):
			var remote eth.StatusPacket
			if err := rlp.DecodeBytes(data, &remote); err != nil {
				conn.Close()
				return nil, fmt.Errorf("decode remote status: %w", err)
			}
			remote.ProtocolVersion = uint32(conn.negotiatedProtoVersion)
			if err := conn.Write(ethProto, eth.StatusMsg, &remote); err != nil {
				conn.Close()
				return nil, fmt.Errorf("write mirrored status: %w", err)
			}
			return &frameLoadConn{Conn: conn}, nil
		case pingMsg:
			if err := conn.Write(baseProto, pongMsg, frameLoadPongPayload()); err != nil {
				conn.Close()
				return nil, err
			}
		case discMsg:
			conn.Close()
			return nil, errors.New("disconnect received before status exchange")
		default:
			conn.Close()
			return nil, fmt.Errorf("unexpected message %d before status exchange", code)
		}
	}
}

func frameLoadIterations(corpus string, gasLimit uint64) (uint64, error) {
	target := gasLimit * 96 / 100
	switch corpus {
	case "arithmetic":
		if target <= frameLoadArithmeticFixedGas {
			return 1, nil
		}
		return (target - frameLoadArithmeticFixedGas) / frameLoadArithmeticLoopGas, nil
	case "bls":
		if target <= frameLoadBLSFixedGas {
			return 1, nil
		}
		return (target - frameLoadBLSFixedGas + frameLoadBLSLoopGas - 1) / frameLoadBLSLoopGas, nil
	default:
		return 0, fmt.Errorf("unknown corpus %q (want arithmetic or bls)", corpus)
	}
}

func frameLoadTx(config FrameLoadConfig, sequence uint64) (*types.Transaction, error) {
	iterations, err := frameLoadIterations(config.Corpus, config.VerifyGas)
	if err != nil {
		return nil, err
	}
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], iterations)

	sender := FrameLoadArithmeticSender
	data := word
	if config.Corpus == "bls" {
		sender = FrameLoadBLSSender
		data = append(common.CopyBytes(frameLoadBLSInput), word...)
	}
	fee := uint256.NewInt(100_000_000_000 + sequence)
	return types.NewTx(&types.FrameTx{
		ChainID:    uint256.NewInt(config.ChainID),
		NonceKeys:  []*uint256.Int{uint256.NewInt(0)},
		NonceSeq:   0,
		Sender:     sender,
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  fee,
		BlobFeeCap: new(uint256.Int),
		Frames: []types.Frame{{
			Mode:     types.FrameModeVerify,
			Flags:    types.FrameFlagApproveScopeMask,
			GasLimit: config.VerifyGas,
			Data:     data,
		}},
	}), nil
}

func frameLoadPacket(config FrameLoadConfig, counters *frameLoadCounters) (eth.TransactionsPacket, uint64, error) {
	txs := make([]*types.Transaction, config.Batch)
	var payloadBytes uint64
	for i := range txs {
		sequence := counters.sequence.Add(1)
		tx, err := frameLoadTx(config, sequence)
		if err != nil {
			return eth.TransactionsPacket{}, 0, err
		}
		raw, err := tx.MarshalBinary()
		if err != nil {
			return eth.TransactionsPacket{}, 0, err
		}
		payloadBytes += uint64(len(raw))
		txs[i] = tx
	}
	rawList, err := rlp.EncodeToRawList(txs)
	if err != nil {
		return eth.TransactionsPacket{}, 0, err
	}
	return eth.TransactionsPacket{RawList: rawList}, payloadBytes, nil
}

func frameLoadReadLoop(ctx context.Context, conn *frameLoadConn, counters *frameLoadCounters) {
	for {
		if ctx.Err() != nil {
			return
		}
		code, _, err := conn.Read()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if ctx.Err() == nil {
				counters.recordReadError(fmt.Errorf("peer read: %w", err))
			}
			return
		}
		switch code {
		case pingMsg:
			if err := conn.write(baseProto, pongMsg, frameLoadPongPayload()); err != nil && ctx.Err() == nil {
				counters.recordWriteError(fmt.Errorf("pong: %w", err))
				return
			}
		case discMsg:
			if ctx.Err() == nil {
				counters.recordDisconnect(errors.New("peer disconnected"))
			}
			return
		}
	}
}

func frameLoadWriteLoop(ctx context.Context, conn *frameLoadConn, config FrameLoadConfig, counters *frameLoadCounters) {
	packetRate := float64(config.Rate) / float64(config.Peers*config.Batch)
	var ticker *time.Ticker
	if packetRate > 0 {
		interval := time.Duration(float64(time.Second) / packetRate)
		if interval < time.Microsecond {
			interval = time.Microsecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}
	for {
		if ticker != nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		} else if ctx.Err() != nil {
			return
		}
		packet, payloadBytes, err := frameLoadPacket(config, counters)
		if err != nil {
			counters.recordOtherError(err)
			return
		}
		counters.attempted.Add(uint64(config.Batch))
		if err := conn.write(ethProto, eth.TransactionsMsg, packet); err != nil {
			if ctx.Err() == nil {
				counters.recordWriteError(fmt.Errorf("send transactions: %w", err))
			}
			return
		}
		counters.sent.Add(uint64(config.Batch))
		counters.packets.Add(1)
		counters.payloadBytes.Add(payloadBytes)
	}
}

// RunFrameLoad opens real RLPx peers and sends invalid, near-cap frame
// transactions over eth/Transactions for the requested duration.
func RunFrameLoad(parent context.Context, config FrameLoadConfig) (FrameLoadResult, error) {
	if config.Dest == nil {
		return FrameLoadResult{}, errors.New("missing destination node")
	}
	if config.ChainID == 0 || config.VerifyGas == 0 || config.Peers <= 0 || config.Batch <= 0 || config.Rate < 0 || config.Duration <= 0 {
		return FrameLoadResult{}, errors.New("chain-id, verify-gas, peers, batch, and duration must be positive; rate must be non-negative")
	}
	if _, err := frameLoadIterations(config.Corpus, config.VerifyGas); err != nil {
		return FrameLoadResult{}, err
	}
	suite := &Suite{Dest: config.Dest}
	conns := make([]*frameLoadConn, 0, config.Peers)
	for len(conns) < config.Peers {
		conn, err := mirrorStatusPeer(suite)
		if err != nil {
			for _, open := range conns {
				open.Close()
			}
			return FrameLoadResult{}, fmt.Errorf("connect peer %d: %w", len(conns), err)
		}
		conns = append(conns, conn)
	}
	ctx, cancel := context.WithTimeout(parent, config.Duration)
	defer cancel()

	start := time.Now()
	counters := new(frameLoadCounters)
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(2)
		go func() {
			defer wg.Done()
			frameLoadReadLoop(ctx, conn, counters)
		}()
		go func() {
			defer wg.Done()
			frameLoadWriteLoop(ctx, conn, config, counters)
		}()
	}
	<-ctx.Done()
	for _, conn := range conns {
		conn.Close()
	}
	wg.Wait()
	elapsed := time.Since(start)

	counters.mu.Lock()
	recordedErrors := append([]string(nil), counters.errors...)
	counters.mu.Unlock()
	result := FrameLoadResult{
		SchemaVersion:       2,
		Corpus:              config.Corpus,
		ChainID:             config.ChainID,
		VerifyGas:           config.VerifyGas,
		Peers:               config.Peers,
		Batch:               config.Batch,
		RequestedTPS:        config.Rate,
		DurationMS:          elapsed.Milliseconds(),
		Attempted:           counters.attempted.Load(),
		Sent:                counters.sent.Load(),
		Packets:             counters.packets.Load(),
		UncompressedTxBytes: counters.payloadBytes.Load(),
		WriteErrors:         counters.writeErrors.Load(),
		ReadErrors:          counters.readErrors.Load(),
		PeerDisconnects:     counters.disconnects.Load(),
		OtherErrors:         counters.otherErrors.Load(),
		Errors:              recordedErrors,
	}
	if elapsed > 0 {
		result.ActualTPS = float64(result.Sent) / elapsed.Seconds()
	}
	return result, nil
}
