// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package ethtest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

const (
	frameMassMaxSenders    = 256
	frameMassPayerGas      = uint64(5_000)
	frameMassTipCap        = uint64(1_000_000_000)
	frameMassFeeCap        = uint64(2_000_000_000)
	frameMassVariantLength = 32
	frameMassSignAttempts  = 1_024

	frameMassHashModeExact  = "exact"
	frameMassHashModeUnique = "unique"

	frameMassPayerModeCanonical  = "canonical"
	frameMassPayerModeDefaultEOA = "default-eoa"

	// Public test key only. It is also used by the deterministic mass fixture to
	// authorize withdrawal-state transitions; it must never hold real assets.
	frameMassSignerKeyHex = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
	// Public test key for the empty-code EOA sponsor. The corresponding account
	// is also the EIP-7702 authority in the code-toggle benchmark fixture.
	frameMassDefaultEOAPayerKeyHex = "0202020202020202020202020202020202020202020202020202002020202020"
)

var (
	FrameMassPayer              = common.HexToAddress("0x9999999999999999999999999999999999999999")
	frameMassSignerKey          = mustFrameMassKey(frameMassSignerKeyHex)
	FrameMassSigner             = gethcrypto.PubkeyToAddress(frameMassSignerKey.PublicKey)
	frameMassDefaultEOAPayerKey = mustFrameMassKey(frameMassDefaultEOAPayerKeyHex)
	FrameMassDefaultEOAPayer    = gethcrypto.PubkeyToAddress(frameMassDefaultEOAPayerKey.PublicKey)
)

func mustFrameMassKey(keyHex string) *ecdsa.PrivateKey {
	key, err := gethcrypto.HexToECDSA(keyHex)
	if err != nil {
		panic(fmt.Sprintf("invalid frame-mass public test key: %v", err))
	}
	return key
}

// FrameMassConfig controls a deterministic one-shot shared-payer pool fill.
type FrameMassConfig struct {
	Dest      *enode.Node
	Corpus    string
	PayerMode string
	ChainID   uint64
	VerifyGas uint64
	Count     int
	Peers     int
	Batch     int
	Settle    time.Duration
}

// FrameMassResult records what was written to the RLPx connections. Acceptance
// is checked separately on the target through txpool and framepool metrics.
type FrameMassResult struct {
	SchemaVersion            int      `json:"schema_version"`
	Experiment               string   `json:"experiment"`
	Corpus                   string   `json:"corpus"`
	PayerMode                string   `json:"payer_mode"`
	ChainID                  uint64   `json:"chain_id"`
	VerifyGas                uint64   `json:"verify_gas"`
	SenderVerifyGas          uint64   `json:"sender_verify_gas"`
	PayerVerifyGas           uint64   `json:"payer_verify_gas"`
	SignatureCount           int      `json:"signature_count"`
	SignatureSchemes         []string `json:"signature_schemes"`
	PayerSignatureIndex      int      `json:"payer_signature_index"`
	SignatureVerificationGas uint64   `json:"signature_verification_gas"`
	SignatureSigner          string   `json:"signature_signer"`
	Requested                int      `json:"requested"`
	Peers                    int      `json:"peers"`
	Batch                    int      `json:"batch"`
	DurationMS               int64    `json:"duration_ms"`
	Sent                     int      `json:"sent"`
	Packets                  int      `json:"packets"`
	UncompressedTxBytes      uint64   `json:"uncompressed_tx_bytes"`
	ManifestSHA256           string   `json:"manifest_sha256"`
	AggregateMaxCostWei      string   `json:"aggregate_max_cost_wei"`
	FirstSender              string   `json:"first_sender"`
	LastSender               string   `json:"last_sender"`
	Payer                    string   `json:"payer"`
	WriteErrors              uint64   `json:"write_errors"`
	ReadErrors               uint64   `json:"read_errors"`
	PeerDisconnects          uint64   `json:"peer_disconnects"`
	OtherErrors              uint64   `json:"other_errors"`
	Errors                   []string `json:"errors,omitempty"`
}

// FrameMassStreamConfig controls a sustained stream over the deterministic
// shared-payer sender set. Exact mode cycles the same transaction hashes across
// packets. Unique mode changes only ignored, hash-committed sender calldata and
// regenerates the canonical outer signature for each manifest generation.
type FrameMassStreamConfig struct {
	Dest      *enode.Node
	Corpus    string
	PayerMode string
	ChainID   uint64
	VerifyGas uint64
	Count     int
	Peers     int
	Batch     int
	Rate      int
	Duration  time.Duration
	HashMode  string
}

// FrameMassStreamResult records generator-side writes. Sent means that an RLPx
// write returned successfully; target acceptance and completion must be checked
// independently with target-side metrics.
type FrameMassStreamResult struct {
	SchemaVersion              int      `json:"schema_version"`
	Experiment                 string   `json:"experiment"`
	Corpus                     string   `json:"corpus"`
	PayerMode                  string   `json:"payer_mode"`
	HashMode                   string   `json:"hash_mode"`
	ChainID                    uint64   `json:"chain_id"`
	VerifyGas                  uint64   `json:"verify_gas"`
	SenderVerifyGas            uint64   `json:"sender_verify_gas"`
	PayerVerifyGas             uint64   `json:"payer_verify_gas"`
	SignatureCount             int      `json:"signature_count"`
	SignatureSchemes           []string `json:"signature_schemes"`
	PayerSignatureIndex        int      `json:"payer_signature_index"`
	SignatureVerificationGas   uint64   `json:"signature_verification_gas"`
	SignatureSigner            string   `json:"signature_signer"`
	SenderCount                int      `json:"sender_count"`
	Peers                      int      `json:"peers"`
	Batch                      int      `json:"batch"`
	RequestedTPS               int      `json:"requested_tps"`
	Scheduled                  uint64   `json:"scheduled"`
	DurationMS                 int64    `json:"duration_ms"`
	CompletedRequestedDuration bool     `json:"completed_requested_duration"`
	TerminationReason          string   `json:"termination_reason"`
	Attempted                  uint64   `json:"attempted"`
	Sent                       uint64   `json:"sent"`
	Packets                    uint64   `json:"packets"`
	ActualTPS                  float64  `json:"actual_tps"`
	DistinctHashesSent         uint64   `json:"distinct_hashes_sent"`
	FullManifestRounds         uint64   `json:"full_manifest_rounds"`
	PartialManifestTxs         uint64   `json:"partial_manifest_txs"`
	FirstGeneration            uint64   `json:"first_generation"`
	LastGeneration             uint64   `json:"last_generation"`
	UncompressedTxBytes        uint64   `json:"uncompressed_tx_bytes"`
	BaseManifestSHA256         string   `json:"base_manifest_sha256"`
	StreamSHA256               string   `json:"stream_sha256"`
	AggregateMaxCostWei        string   `json:"aggregate_max_cost_wei"`
	FirstSender                string   `json:"first_sender"`
	LastSender                 string   `json:"last_sender"`
	Payer                      string   `json:"payer"`
	WriteErrors                uint64   `json:"write_errors"`
	ReadErrors                 uint64   `json:"read_errors"`
	PeerDisconnects            uint64   `json:"peer_disconnects"`
	OtherErrors                uint64   `json:"other_errors"`
	Errors                     []string `json:"errors,omitempty"`
}

func frameMassSender(index int) common.Address {
	var sender common.Address
	sender[0] = 0x41
	binary.BigEndian.PutUint64(sender[12:], uint64(index+1))
	return sender
}

func frameMassTx(config FrameMassConfig, index int) (*types.Transaction, error) {
	return frameMassTxVariant(config, index, 0)
}

type frameMassPayerProfile struct {
	mode           string
	payer          common.Address
	signer         common.Address
	signerKey      *ecdsa.PrivateKey
	signatureIndex int
	signatureGas   uint64
	signatureNames []string
}

func frameMassPayerProfileForMode(mode string) (frameMassPayerProfile, error) {
	switch mode {
	case "", frameMassPayerModeCanonical:
		return frameMassPayerProfile{
			mode:           frameMassPayerModeCanonical,
			payer:          FrameMassPayer,
			signer:         FrameMassSigner,
			signerKey:      frameMassSignerKey,
			signatureIndex: 0,
			signatureGas:   params.SigGasSecp256k1,
			signatureNames: []string{"secp256k1"},
		}, nil
	case frameMassPayerModeDefaultEOA:
		return frameMassPayerProfile{
			mode:           frameMassPayerModeDefaultEOA,
			payer:          FrameMassDefaultEOAPayer,
			signer:         FrameMassDefaultEOAPayer,
			signerKey:      frameMassDefaultEOAPayerKey,
			signatureIndex: 1,
			signatureGas:   params.SigGasArbitrary + params.SigGasSecp256k1,
			signatureNames: []string{"arbitrary", "secp256k1"},
		}, nil
	default:
		return frameMassPayerProfile{}, fmt.Errorf("unknown payer mode %q (want canonical or default-eoa)", mode)
	}
}

func frameMassSenderGas(verifyGas uint64, signatureGas uint64) (uint64, error) {
	fixed := frameMassPayerGas + signatureGas
	if verifyGas <= fixed {
		return 0, fmt.Errorf("verify gas %d must exceed payer plus signature gas %d", verifyGas, fixed)
	}
	return verifyGas - fixed, nil
}

func frameMassEncodeNonzeroBase255(dst []byte, value uint64) error {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(value%255) + 1
		value /= 255
	}
	if value != 0 {
		return errors.New("value does not fit non-zero base-255 encoding")
	}
	return nil
}

func frameMassVariantSalt(generation, attempt uint64) ([]byte, error) {
	// The sender runtime ignores this fixed-width trailer, but SigHash commits
	// it. Base-255 digits plus one keep every byte non-zero for every generation,
	// holding calldata intrinsic gas constant. Eight attempt bytes permit
	// deterministic signature grinding without changing that invariant.
	salt := bytes.Repeat([]byte{0xa5}, frameMassVariantLength)
	if err := frameMassEncodeNonzeroBase255(salt[16:24], attempt); err != nil {
		return nil, fmt.Errorf("encode signature attempt: %w", err)
	}
	if err := frameMassEncodeNonzeroBase255(salt[24:32], generation); err != nil {
		return nil, fmt.Errorf("encode generation: %w", err)
	}
	return salt, nil
}

func frameMassIterations(gasLimit uint64) (uint64, error) {
	// Keep the corpus near the requested budget without exceeding the frame gas
	// limit. The generic load generator rounds BLS iterations up; after reserving
	// current-spec signature and payer gas that would make a 92,200-gas sender
	// frame attempt eight 12,142-gas loops and run out of gas.
	if gasLimit < frameLoadBLSFixedGas+frameLoadBLSLoopGas {
		return 0, fmt.Errorf("sender verify gas %d cannot execute one BLS iteration", gasLimit)
	}
	target := gasLimit/100*96 + gasLimit%100*96/100
	iterations := (target - frameLoadBLSFixedGas) / frameLoadBLSLoopGas
	if iterations == 0 {
		iterations = 1
	}
	return iterations, nil
}

func frameMassTxVariant(config FrameMassConfig, index int, generation uint64) (*types.Transaction, error) {
	if config.Corpus != "bls" {
		return nil, fmt.Errorf("unknown mass-invalidation corpus %q (want bls)", config.Corpus)
	}
	if index < 0 || index >= frameMassMaxSenders {
		return nil, fmt.Errorf("sender index %d outside [0, %d)", index, frameMassMaxSenders)
	}
	profile, err := frameMassPayerProfileForMode(config.PayerMode)
	if err != nil {
		return nil, err
	}
	senderGas, err := frameMassSenderGas(config.VerifyGas, profile.signatureGas)
	if err != nil {
		return nil, err
	}
	iterations, err := frameMassIterations(senderGas)
	if err != nil {
		return nil, err
	}
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], iterations)
	baseData := append(common.CopyBytes(frameLoadBLSInput), word...)
	payer := profile.payer
	for attempt := uint64(0); attempt < frameMassSignAttempts; attempt++ {
		salt, err := frameMassVariantSalt(generation, attempt)
		if err != nil {
			return nil, err
		}
		data := append(common.CopyBytes(baseData), salt...)
		signatures := []types.TxSignature{{
			Scheme: types.SignatureSchemeSecp256k1,
			Signer: profile.signer,
		}}
		if profile.mode == frameMassPayerModeDefaultEOA {
			// EOA default code maps execution approval to signature index 0
			// and payment approval to index 1. The BLS sender verifier does
			// not read SIGPARAM, so a structurally valid ARBITRARY placeholder
			// isolates the one payer signature needed by this experiment.
			signatures = []types.TxSignature{
				{Scheme: types.SignatureSchemeArbitrary, Signature: []byte{0xa5}},
				{Scheme: types.SignatureSchemeSecp256k1, Signer: profile.signer},
			}
		}
		frameTx := &types.FrameTx{
			ChainID:    uint256.NewInt(config.ChainID),
			NonceKeys:  []*uint256.Int{uint256.NewInt(0)},
			NonceSeq:   0,
			Sender:     frameMassSender(index),
			GasTipCap:  uint256.NewInt(frameMassTipCap),
			GasFeeCap:  uint256.NewInt(frameMassFeeCap),
			BlobFeeCap: new(uint256.Int),
			Signatures: signatures,
			Frames: []types.Frame{
				{
					Mode:     types.FrameModeVerify,
					Flags:    types.FrameFlagApproveExecution,
					GasLimit: senderGas,
					Data:     data,
				},
				{
					Mode:     types.FrameModeVerify,
					Flags:    types.FrameFlagApprovePayment,
					Target:   &payer,
					GasLimit: frameMassPayerGas,
				},
			},
		}
		sigHash := frameTx.SigHash(new(big.Int).SetUint64(config.ChainID))
		compact, err := gethcrypto.Sign(sigHash[:], profile.signerKey)
		if err != nil {
			return nil, fmt.Errorf("sign frame transaction: %w", err)
		}
		// Keep signature calldata pricing constant across generations as well:
		// V=1 and non-zero R/S make all 65 wire bytes non-zero. Changing the
		// ignored attempt trailer deterministically grinds for this property.
		if compact[64] != 1 || bytes.IndexByte(compact[:64], 0) >= 0 {
			continue
		}
		// crypto.Sign returns R || S || V, while the EIP-8141 SECP256K1 wire
		// encoding used by TxSignature is V || R || S.
		wireSignature := make([]byte, len(compact))
		wireSignature[0] = compact[64]
		copy(wireSignature[1:33], compact[0:32])
		copy(wireSignature[33:65], compact[32:64])
		frameTx.Signatures[profile.signatureIndex].Signature = wireSignature
		return types.NewTx(frameTx), nil
	}
	return nil, fmt.Errorf("could not derive constant-cost signature after %d attempts", frameMassSignAttempts)
}

func frameMassPacket(txs []*types.Transaction) (eth.TransactionsPacket, uint64, error) {
	var payloadBytes uint64
	for _, tx := range txs {
		raw, err := tx.MarshalBinary()
		if err != nil {
			return eth.TransactionsPacket{}, 0, err
		}
		payloadBytes += uint64(len(raw))
	}
	rawList, err := rlp.EncodeToRawList(txs)
	if err != nil {
		return eth.TransactionsPacket{}, 0, err
	}
	return eth.TransactionsPacket{RawList: rawList}, payloadBytes, nil
}

// RunFrameMass opens real RLPx peers and writes exactly Count unique, valid
// shared-payer frame transactions once each.
func RunFrameMass(parent context.Context, config FrameMassConfig) (FrameMassResult, error) {
	if config.Dest == nil {
		return FrameMassResult{}, errors.New("missing destination node")
	}
	if config.Corpus != "bls" || config.ChainID == 0 || config.VerifyGas == 0 {
		return FrameMassResult{}, errors.New("corpus must be bls; chain-id and verify-gas must be positive")
	}
	if config.Count <= 0 || config.Count > frameMassMaxSenders || config.Peers <= 0 || config.Batch <= 0 || config.Settle < 0 {
		return FrameMassResult{}, fmt.Errorf("count must be in [1,%d]; peers and batch must be positive; settle must be non-negative", frameMassMaxSenders)
	}
	profile, err := frameMassPayerProfileForMode(config.PayerMode)
	if err != nil {
		return FrameMassResult{}, err
	}

	txs := make([]*types.Transaction, config.Count)
	totalCost := new(big.Int)
	manifest := sha256.New()
	for index := range txs {
		tx, err := frameMassTx(config, index)
		if err != nil {
			return FrameMassResult{}, err
		}
		txs[index] = tx
		totalCost.Add(totalCost, tx.Cost())
		manifest.Write(tx.Hash().Bytes())
	}

	suite := &Suite{Dest: config.Dest}
	conns := make([]*frameLoadConn, 0, config.Peers)
	for len(conns) < config.Peers {
		conn, err := mirrorStatusPeer(suite)
		if err != nil {
			for _, open := range conns {
				open.Close()
			}
			return FrameMassResult{}, fmt.Errorf("connect peer %d: %w", len(conns), err)
		}
		conns = append(conns, conn)
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	counters := new(frameLoadCounters)
	var readers sync.WaitGroup
	for _, conn := range conns {
		readers.Add(1)
		go func() {
			defer readers.Done()
			frameLoadReadLoop(ctx, conn, counters)
		}()
	}

	start := time.Now()
	sent := 0
	packets := 0
	var payloadBytes uint64
	for offset := 0; offset < len(txs); offset += config.Batch {
		end := offset + config.Batch
		if end > len(txs) {
			end = len(txs)
		}
		packet, size, err := frameMassPacket(txs[offset:end])
		if err != nil {
			cancel()
			for _, conn := range conns {
				conn.Close()
			}
			readers.Wait()
			return FrameMassResult{}, err
		}
		conn := conns[packets%len(conns)]
		counters.attempted.Add(uint64(end - offset))
		if err := conn.write(ethProto, eth.TransactionsMsg, packet); err != nil {
			counters.recordWriteError(fmt.Errorf("send transactions: %w", err))
			break
		}
		sent += end - offset
		packets++
		payloadBytes += size
	}
	if sent == len(txs) && config.Settle > 0 {
		select {
		case <-parent.Done():
		case <-time.After(config.Settle):
		}
	}
	cancel()
	for _, conn := range conns {
		conn.Close()
	}
	readers.Wait()
	elapsed := time.Since(start)

	counters.mu.Lock()
	recordedErrors := append([]string(nil), counters.errors...)
	counters.mu.Unlock()
	result := FrameMassResult{
		SchemaVersion:            4,
		Experiment:               "framepool_mass_invalidation_fill",
		Corpus:                   config.Corpus,
		ChainID:                  config.ChainID,
		VerifyGas:                config.VerifyGas,
		SenderVerifyGas:          config.VerifyGas - frameMassPayerGas - profile.signatureGas,
		PayerMode:                profile.mode,
		PayerVerifyGas:           frameMassPayerGas,
		SignatureCount:           len(profile.signatureNames),
		SignatureSchemes:         append([]string(nil), profile.signatureNames...),
		PayerSignatureIndex:      profile.signatureIndex,
		SignatureVerificationGas: profile.signatureGas,
		SignatureSigner:          profile.signer.Hex(),
		Requested:                config.Count,
		Peers:                    config.Peers,
		Batch:                    config.Batch,
		DurationMS:               elapsed.Milliseconds(),
		Sent:                     sent,
		Packets:                  packets,
		UncompressedTxBytes:      payloadBytes,
		ManifestSHA256:           "0x" + hex.EncodeToString(manifest.Sum(nil)),
		AggregateMaxCostWei:      totalCost.String(),
		FirstSender:              frameMassSender(0).Hex(),
		LastSender:               frameMassSender(config.Count - 1).Hex(),
		Payer:                    profile.payer.Hex(),
		WriteErrors:              counters.writeErrors.Load(),
		ReadErrors:               counters.readErrors.Load(),
		PeerDisconnects:          counters.disconnects.Load(),
		OtherErrors:              counters.otherErrors.Load(),
		Errors:                   recordedErrors,
	}
	if sent != len(txs) {
		return result, fmt.Errorf("wrote %d of %d transactions", sent, len(txs))
	}
	return result, nil
}

func validateFrameMassStreamConfig(config FrameMassStreamConfig) error {
	if config.Corpus != "bls" || config.ChainID == 0 || config.VerifyGas == 0 {
		return errors.New("corpus must be bls; chain-id and verify-gas must be positive")
	}
	if config.Count <= 0 || config.Count > frameMassMaxSenders {
		return fmt.Errorf("count must be in [1,%d]", frameMassMaxSenders)
	}
	if config.Peers <= 0 || config.Batch <= 0 || config.Rate <= 0 || config.Duration <= 0 {
		return errors.New("peers, batch, rate, and duration must be positive")
	}
	if config.Batch > config.Count {
		return fmt.Errorf("batch %d exceeds sender count %d; repeated hashes in one Transactions packet are a protocol error", config.Batch, config.Count)
	}
	if config.HashMode != frameMassHashModeExact && config.HashMode != frameMassHashModeUnique {
		return fmt.Errorf("unknown hash mode %q (want exact or unique)", config.HashMode)
	}
	profile, err := frameMassPayerProfileForMode(config.PayerMode)
	if err != nil {
		return err
	}
	senderGas, err := frameMassSenderGas(config.VerifyGas, profile.signatureGas)
	if err != nil {
		return err
	}
	if _, err := frameMassIterations(senderGas); err != nil {
		return err
	}
	scheduled, err := frameMassScheduledTransactions(config)
	if err != nil {
		return err
	}
	if config.HashMode == frameMassHashModeUnique {
		maxGeneration := (scheduled-1)/uint64(config.Count) + 1
		if _, err := frameMassVariantSalt(maxGeneration, uint64(frameMassSignAttempts-1)); err != nil {
			return fmt.Errorf("unique stream range: %w", err)
		}
	}
	return nil
}

func frameMassScheduledTransactions(config FrameMassStreamConfig) (uint64, error) {
	durationNanos := uint64(config.Duration)
	rate := uint64(config.Rate)
	if durationNanos != 0 && rate > math.MaxUint64/durationNanos {
		return 0, errors.New("rate times duration overflows uint64")
	}
	scheduled := rate * durationNanos / uint64(time.Second)
	if scheduled == 0 {
		return 0, errors.New("rate and duration schedule zero transactions")
	}
	return scheduled, nil
}

func frameMassNextPacket(scheduled, sent uint64, batch, rate int) (int, time.Duration) {
	remaining := scheduled - sent
	size := batch
	if remaining < uint64(size) {
		size = int(remaining)
	}
	// Schedule the next packet at cumulative-sent/rate, using 128-bit integer
	// arithmetic so common decimal rates have exact nanosecond deadlines.
	hi, lo := bits.Mul64(sent, uint64(time.Second))
	offset, _ := bits.Div64(hi, lo, uint64(rate))
	return size, time.Duration(offset)
}

func frameMassBaseConfig(config FrameMassStreamConfig) FrameMassConfig {
	return FrameMassConfig{
		Dest:      config.Dest,
		Corpus:    config.Corpus,
		PayerMode: config.PayerMode,
		ChainID:   config.ChainID,
		VerifyGas: config.VerifyGas,
		Count:     config.Count,
		Peers:     config.Peers,
		Batch:     config.Batch,
	}
}

func frameMassStreamTx(config FrameMassStreamConfig, sequence uint64) (*types.Transaction, error) {
	index := int(sequence % uint64(config.Count))
	generation := uint64(0)
	if config.HashMode == frameMassHashModeUnique {
		generation = sequence/uint64(config.Count) + 1
	}
	return frameMassTxVariant(frameMassBaseConfig(config), index, generation)
}

func frameMassBaseManifest(config FrameMassStreamConfig) ([]*types.Transaction, string, error) {
	txs := make([]*types.Transaction, config.Count)
	digest := sha256.New()
	base := frameMassBaseConfig(config)
	for index := range txs {
		tx, err := frameMassTxVariant(base, index, 0)
		if err != nil {
			return nil, "", err
		}
		txs[index] = tx
		digest.Write(tx.Hash().Bytes())
	}
	return txs, "0x" + hex.EncodeToString(digest.Sum(nil)), nil
}

// RunFrameMassStream sends a rate-limited sustained stream of shared-payer
// transactions. It deliberately sends full transaction broadcasts rather than
// hash announcements so exact hashes exercise the target's inbound Add path on
// every packet after correlated eviction.
func RunFrameMassStream(parent context.Context, config FrameMassStreamConfig) (FrameMassStreamResult, error) {
	if config.Dest == nil {
		return FrameMassStreamResult{}, errors.New("missing destination node")
	}
	if err := validateFrameMassStreamConfig(config); err != nil {
		return FrameMassStreamResult{}, err
	}
	profile, err := frameMassPayerProfileForMode(config.PayerMode)
	if err != nil {
		return FrameMassStreamResult{}, err
	}
	scheduled, _ := frameMassScheduledTransactions(config)
	baseTxs, baseManifest, err := frameMassBaseManifest(config)
	if err != nil {
		return FrameMassStreamResult{}, err
	}

	suite := &Suite{Dest: config.Dest}
	conns := make([]*frameLoadConn, 0, config.Peers)
	for len(conns) < config.Peers {
		conn, err := mirrorStatusPeer(suite)
		if err != nil {
			for _, open := range conns {
				open.Close()
			}
			return FrameMassStreamResult{}, fmt.Errorf("connect peer %d: %w", len(conns), err)
		}
		conns = append(conns, conn)
	}

	ctx, cancel := context.WithCancel(parent)
	counters := new(frameLoadCounters)
	var readers sync.WaitGroup
	for _, conn := range conns {
		readers.Add(1)
		go func() {
			defer readers.Done()
			frameLoadReadLoop(ctx, conn, counters)
		}()
	}

	streamDigest := sha256.New()
	totalCost := new(big.Int)
	terminationReason := "duration_complete"
	completedDuration := false
	start := time.Now()

	sendPacket := func(size int) bool {
		sequence := counters.sent.Load()
		txs := make([]*types.Transaction, size)
		for i := range txs {
			if config.HashMode == frameMassHashModeExact {
				txs[i] = baseTxs[(int(sequence)+i)%config.Count]
				continue
			}
			tx, err := frameMassStreamTx(config, sequence+uint64(i))
			if err != nil {
				counters.recordOtherError(fmt.Errorf("build stream transaction: %w", err))
				terminationReason = "generation_error"
				return false
			}
			txs[i] = tx
		}
		packet, payloadBytes, err := frameMassPacket(txs)
		if err != nil {
			counters.recordOtherError(fmt.Errorf("encode stream packet: %w", err))
			terminationReason = "generation_error"
			return false
		}
		counters.attempted.Add(uint64(size))
		conn := conns[counters.packets.Load()%uint64(len(conns))]
		if err := conn.write(ethProto, eth.TransactionsMsg, packet); err != nil {
			counters.recordWriteError(fmt.Errorf("send transactions: %w", err))
			terminationReason = "write_error"
			return false
		}
		for _, tx := range txs {
			streamDigest.Write(tx.Hash().Bytes())
			totalCost.Add(totalCost, tx.Cost())
		}
		counters.sent.Add(uint64(size))
		counters.packets.Add(1)
		counters.payloadBytes.Add(payloadBytes)
		return true
	}

	windowEnd := start.Add(config.Duration)
	waitUntil := func(deadline time.Time) bool {
		delay := time.Until(deadline)
		if delay <= 0 {
			return true
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-parent.Done():
			terminationReason = "parent_canceled"
			return false
		case <-timer.C:
			return true
		}
	}

	for counters.sent.Load() < scheduled {
		sent := counters.sent.Load()
		size, offset := frameMassNextPacket(scheduled, sent, config.Batch, config.Rate)
		if !waitUntil(start.Add(offset)) {
			break
		}
		if !time.Now().Before(windowEnd) {
			completedDuration = true
			terminationReason = "duration_complete_with_generator_backlog"
			break
		}
		if !sendPacket(size) {
			break
		}
	}
	if counters.sent.Load() == scheduled && !completedDuration {
		if time.Now().Before(windowEnd) {
			if waitUntil(windowEnd) {
				completedDuration = true
			}
		} else {
			completedDuration = true
			terminationReason = "duration_complete_after_generator_overrun"
		}
	}
	cancel()
	for _, conn := range conns {
		conn.Close()
	}
	readers.Wait()
	elapsed := time.Since(start)

	counters.mu.Lock()
	recordedErrors := append([]string(nil), counters.errors...)
	counters.mu.Unlock()
	sent := counters.sent.Load()
	distinct := sent
	if config.HashMode == frameMassHashModeExact && distinct > uint64(config.Count) {
		distinct = uint64(config.Count)
	}
	firstGeneration := uint64(0)
	lastGeneration := uint64(0)
	if sent > 0 && config.HashMode == frameMassHashModeUnique {
		firstGeneration = 1
		lastGeneration = (sent-1)/uint64(config.Count) + 1
	}
	lastSender := ""
	if sent > 0 {
		lastSender = frameMassSender(int((sent - 1) % uint64(config.Count))).Hex()
	}
	result := FrameMassStreamResult{
		SchemaVersion:              2,
		Experiment:                 "framepool_mass_invalidation_stream",
		Corpus:                     config.Corpus,
		HashMode:                   config.HashMode,
		ChainID:                    config.ChainID,
		VerifyGas:                  config.VerifyGas,
		SenderVerifyGas:            config.VerifyGas - frameMassPayerGas - profile.signatureGas,
		PayerMode:                  profile.mode,
		PayerVerifyGas:             frameMassPayerGas,
		SignatureCount:             len(profile.signatureNames),
		SignatureSchemes:           append([]string(nil), profile.signatureNames...),
		PayerSignatureIndex:        profile.signatureIndex,
		SignatureVerificationGas:   profile.signatureGas,
		SignatureSigner:            profile.signer.Hex(),
		SenderCount:                config.Count,
		Peers:                      config.Peers,
		Batch:                      config.Batch,
		RequestedTPS:               config.Rate,
		Scheduled:                  scheduled,
		DurationMS:                 elapsed.Milliseconds(),
		CompletedRequestedDuration: completedDuration,
		TerminationReason:          terminationReason,
		Attempted:                  counters.attempted.Load(),
		Sent:                       sent,
		Packets:                    counters.packets.Load(),
		DistinctHashesSent:         distinct,
		FullManifestRounds:         sent / uint64(config.Count),
		PartialManifestTxs:         sent % uint64(config.Count),
		FirstGeneration:            firstGeneration,
		LastGeneration:             lastGeneration,
		UncompressedTxBytes:        counters.payloadBytes.Load(),
		BaseManifestSHA256:         baseManifest,
		StreamSHA256:               "0x" + hex.EncodeToString(streamDigest.Sum(nil)),
		AggregateMaxCostWei:        totalCost.String(),
		FirstSender:                frameMassSender(0).Hex(),
		LastSender:                 lastSender,
		Payer:                      profile.payer.Hex(),
		WriteErrors:                counters.writeErrors.Load(),
		ReadErrors:                 counters.readErrors.Load(),
		PeerDisconnects:            counters.disconnects.Load(),
		OtherErrors:                counters.otherErrors.Load(),
		Errors:                     recordedErrors,
	}
	if elapsed > 0 {
		result.ActualTPS = float64(sent) / elapsed.Seconds()
	}
	return result, nil
}
