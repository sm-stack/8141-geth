// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package ethtest

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

func TestFrameMassTx(t *testing.T) {
	config := FrameMassConfig{Corpus: "bls", ChainID: 1337, VerifyGas: 100_000}
	if want := common.HexToAddress("0x71562b71999873db5b286df957af199ec94617f7"); FrameMassSigner != want {
		t.Fatalf("public test signer: have %s want %s", FrameMassSigner, want)
	}
	if params.SigGasSecp256k1 != 2_800 {
		t.Fatalf("SECP256K1 signature gas: have %d want 2800", params.SigGasSecp256k1)
	}
	seen := make(map[string]struct{})
	for _, index := range []int{0, 15, 255} {
		tx, err := frameMassTx(config, index)
		if err != nil {
			t.Fatalf("tx %d: %v", index, err)
		}
		ftx := tx.GetFrameTx()
		if ftx == nil {
			t.Fatalf("tx %d is not a frame transaction", index)
		}
		if ftx.Sender != frameMassSender(index) {
			t.Fatalf("tx %d sender: have %s want %s", index, ftx.Sender, frameMassSender(index))
		}
		if _, ok := seen[ftx.Sender.Hex()]; ok {
			t.Fatalf("duplicate sender %s", ftx.Sender)
		}
		seen[ftx.Sender.Hex()] = struct{}{}
		if len(ftx.Frames) != 2 {
			t.Fatalf("tx %d frames: have %d want 2", index, len(ftx.Frames))
		}
		if frame := ftx.Frames[0]; frame.Mode != types.FrameModeVerify || frame.Flags != types.FrameFlagApproveExecution || frame.Target != nil || frame.GasLimit != 92_200 {
			t.Fatalf("tx %d sender frame: %+v", index, frame)
		}
		iterations := binary.BigEndian.Uint64(ftx.Frames[0].Data[len(frameLoadBLSInput)+24 : len(frameLoadBLSInput)+32])
		if iterations != 7 {
			t.Fatalf("tx %d BLS iterations: have %d want 7", index, iterations)
		}
		if executionGas := frameLoadBLSFixedGas + iterations*frameLoadBLSLoopGas; executionGas > ftx.Frames[0].GasLimit {
			t.Fatalf("tx %d BLS execution gas %d exceeds sender budget %d", index, executionGas, ftx.Frames[0].GasLimit)
		}
		if frame := ftx.Frames[1]; frame.Mode != types.FrameModeVerify || frame.Flags != types.FrameFlagApprovePayment || frame.Target == nil || *frame.Target != FrameMassPayer || frame.GasLimit != 5_000 || len(frame.Data) != 0 {
			t.Fatalf("tx %d payer frame: %+v", index, frame)
		}
		signatureGas, err := ftx.SignatureGas()
		if err != nil {
			t.Fatalf("tx %d signature gas: %v", index, err)
		}
		if signatureGas != params.SigGasSecp256k1 {
			t.Fatalf("tx %d signature gas: have %d want %d", index, signatureGas, params.SigGasSecp256k1)
		}
		if ftx.Frames[0].GasLimit+ftx.Frames[1].GasLimit+signatureGas != config.VerifyGas {
			t.Fatalf("tx %d validation gas: have %d want %d", index, ftx.Frames[0].GasLimit+ftx.Frames[1].GasLimit+signatureGas, config.VerifyGas)
		}
		if len(ftx.Signatures) != 1 || ftx.Signatures[0].Scheme != types.SignatureSchemeSecp256k1 || ftx.Signatures[0].Signer != FrameMassSigner || len(ftx.Signatures[0].Msg) != 0 {
			t.Fatalf("tx %d outer signature metadata: %+v", index, ftx.Signatures)
		}
		if bytes.IndexByte(ftx.Signatures[0].Signature, 0) >= 0 {
			t.Fatalf("tx %d outer signature contains a zero-priced byte", index)
		}
		if err := types.ValidateFrameTxSignatures(ftx, ftx.SigHash(new(big.Int).SetUint64(config.ChainID))); err != nil {
			t.Fatalf("tx %d outer signature: %v", index, err)
		}
		if _, err := tx.MarshalBinary(); err != nil {
			t.Fatalf("tx %d marshal: %v", index, err)
		}
	}
}

func TestFrameMassTxDefaultEOAPayer(t *testing.T) {
	config := FrameMassConfig{
		Corpus:    "bls",
		PayerMode: frameMassPayerModeDefaultEOA,
		ChainID:   1337,
		VerifyGas: 100_000,
	}
	wantPayer := common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64")
	if FrameMassDefaultEOAPayer != wantPayer {
		t.Fatalf("default EOA payer: have %s want %s", FrameMassDefaultEOAPayer, wantPayer)
	}
	tx, err := frameMassTx(config, 0)
	if err != nil {
		t.Fatal(err)
	}
	ftx := tx.GetFrameTx()
	if len(ftx.Signatures) != 2 {
		t.Fatalf("signatures: have %d want 2", len(ftx.Signatures))
	}
	placeholder := ftx.Signatures[0]
	if placeholder.Scheme != types.SignatureSchemeArbitrary || placeholder.Signer != (common.Address{}) || !bytes.Equal(placeholder.Signature, []byte{0xa5}) {
		t.Fatalf("signature[0] placeholder: %+v", placeholder)
	}
	payerSignature := ftx.Signatures[1]
	if payerSignature.Scheme != types.SignatureSchemeSecp256k1 || payerSignature.Signer != wantPayer || len(payerSignature.Msg) != 0 {
		t.Fatalf("signature[1] payer authorization: %+v", payerSignature)
	}
	if bytes.IndexByte(payerSignature.Signature, 0) >= 0 {
		t.Fatal("payer signature contains a zero-priced byte")
	}
	signatureGas, err := ftx.SignatureGas()
	if err != nil {
		t.Fatal(err)
	}
	wantSignatureGas := params.SigGasArbitrary + params.SigGasSecp256k1
	if signatureGas != wantSignatureGas {
		t.Fatalf("signature gas: have %d want %d", signatureGas, wantSignatureGas)
	}
	if ftx.Frames[0].GasLimit != 92_100 {
		t.Fatalf("sender gas: have %d want 92100", ftx.Frames[0].GasLimit)
	}
	if ftx.Frames[1].Target == nil || *ftx.Frames[1].Target != wantPayer {
		t.Fatalf("payment target: %+v", ftx.Frames[1].Target)
	}
	if ftx.Frames[0].GasLimit+ftx.Frames[1].GasLimit+signatureGas != config.VerifyGas {
		t.Fatal("validation prefix does not conserve the configured gas cap")
	}
	if err := types.ValidateFrameTxSignatures(ftx, ftx.SigHash(new(big.Int).SetUint64(config.ChainID))); err != nil {
		t.Fatalf("protocol signatures: %v", err)
	}
}

func TestFrameMassTxRejectsInvalidConfig(t *testing.T) {
	for _, config := range []FrameMassConfig{
		{Corpus: "arithmetic", ChainID: 1337, VerifyGas: 100_000},
		{Corpus: "bls", ChainID: 1337, VerifyGas: frameMassPayerGas + params.SigGasSecp256k1},
		{Corpus: "bls", PayerMode: "mystery", ChainID: 1337, VerifyGas: 100_000},
		{Corpus: "bls", PayerMode: frameMassPayerModeDefaultEOA, ChainID: 1337, VerifyGas: frameMassPayerGas + params.SigGasArbitrary + params.SigGasSecp256k1},
	} {
		if _, err := frameMassTx(config, 0); err == nil {
			t.Fatalf("config %+v unexpectedly accepted", config)
		}
	}
	config := FrameMassConfig{Corpus: "bls", ChainID: 1337, VerifyGas: 100_000}
	if _, err := frameMassTx(config, frameMassMaxSenders); err == nil {
		t.Fatal("out-of-range sender unexpectedly accepted")
	}
}

func TestFrameMassTxVariantsPreserveExecutionWorkAndResign(t *testing.T) {
	config := FrameMassConfig{Corpus: "bls", ChainID: 1337, VerifyGas: 100_000}
	exactA, err := frameMassTxVariant(config, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	exactB, err := frameMassTxVariant(config, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	unique1, err := frameMassTxVariant(config, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	unique2, err := frameMassTxVariant(config, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if exactA.Hash() != exactB.Hash() {
		t.Fatal("same generation did not produce an exact hash")
	}
	if exactA.Hash() == unique1.Hash() || unique1.Hash() == unique2.Hash() {
		t.Fatal("different generations did not produce unique hashes")
	}
	if exactA.Cost().Cmp(unique1.Cost()) != 0 || exactA.Cost().Cmp(unique2.Cost()) != 0 {
		t.Fatalf("hash variants changed max cost: exact=%s unique1=%s unique2=%s", exactA.Cost(), unique1.Cost(), unique2.Cost())
	}
	baseIntrinsic, err := exactA.GetFrameTx().IntrinsicGas()
	if err != nil {
		t.Fatal(err)
	}

	baseFrame := exactA.GetFrameTx().Frames[0]
	for generation, tx := range []*types.Transaction{unique1, unique2} {
		ftx := tx.GetFrameTx()
		frame := ftx.Frames[0]
		if frame.GasLimit != baseFrame.GasLimit || len(frame.Data) != len(baseFrame.Data) {
			t.Fatalf("generation %d changed sender workload shape", generation+1)
		}
		prefixLength := len(frame.Data) - frameMassVariantLength
		if !bytes.Equal(frame.Data[:prefixLength], baseFrame.Data[:prefixLength]) {
			t.Fatalf("generation %d changed executed sender calldata", generation+1)
		}
		if bytes.Equal(frame.Data[prefixLength:], baseFrame.Data[prefixLength:]) {
			t.Fatalf("generation %d did not change hash-committed trailer", generation+1)
		}
		if bytes.IndexByte(frame.Data[prefixLength:], 0) >= 0 {
			t.Fatalf("generation %d trailer contains a zero-priced byte", generation+1)
		}
		if bytes.Equal(ftx.Signatures[0].Signature, exactA.GetFrameTx().Signatures[0].Signature) {
			t.Fatalf("generation %d did not regenerate the outer signature", generation+1)
		}
		if bytes.IndexByte(ftx.Signatures[0].Signature, 0) >= 0 {
			t.Fatalf("generation %d signature contains a zero-priced byte", generation+1)
		}
		intrinsic, err := ftx.IntrinsicGas()
		if err != nil {
			t.Fatalf("generation %d intrinsic gas: %v", generation+1, err)
		}
		if intrinsic != baseIntrinsic {
			t.Fatalf("generation %d changed intrinsic gas: have %d want %d", generation+1, intrinsic, baseIntrinsic)
		}
		if err := types.ValidateFrameTxSignatures(ftx, ftx.SigHash(new(big.Int).SetUint64(config.ChainID))); err != nil {
			t.Fatalf("generation %d signature: %v", generation+1, err)
		}
	}
}

func TestFrameMassStreamSequenceModes(t *testing.T) {
	config := FrameMassStreamConfig{
		Corpus:    "bls",
		ChainID:   1337,
		VerifyGas: 100_000,
		Count:     16,
		Peers:     1,
		Batch:     16,
		Rate:      25,
		Duration:  time.Second,
		HashMode:  frameMassHashModeExact,
	}
	if err := validateFrameMassStreamConfig(config); err != nil {
		t.Fatalf("valid stream config: %v", err)
	}
	if scheduled, err := frameMassScheduledTransactions(config); err != nil || scheduled != 25 {
		t.Fatalf("scheduled transactions: have %d, err %v, want 25", scheduled, err)
	}
	exact0, err := frameMassStreamTx(config, 0)
	if err != nil {
		t.Fatal(err)
	}
	exactNextRound, err := frameMassStreamTx(config, uint64(config.Count))
	if err != nil {
		t.Fatal(err)
	}
	if exact0.Hash() != exactNextRound.Hash() {
		t.Fatal("exact mode changed hash across manifest rounds")
	}

	config.HashMode = frameMassHashModeUnique
	unique0, err := frameMassStreamTx(config, 0)
	if err != nil {
		t.Fatal(err)
	}
	uniqueNextRound, err := frameMassStreamTx(config, uint64(config.Count))
	if err != nil {
		t.Fatal(err)
	}
	if unique0.Hash() == uniqueNextRound.Hash() {
		t.Fatal("unique mode repeated hash across manifest rounds")
	}
}

func TestFrameMassStreamPacketSchedule(t *testing.T) {
	for _, test := range []struct {
		name      string
		scheduled uint64
		batch     int
		rate      int
		wantSizes []int
		wantTimes []time.Duration
	}{
		{
			name:      "two-second-remainder",
			scheduled: 50,
			batch:     16,
			rate:      25,
			wantSizes: []int{16, 16, 16, 2},
			wantTimes: []time.Duration{0, 640 * time.Millisecond, 1280 * time.Millisecond, 1920 * time.Millisecond},
		},
		{
			name:      "thirty-second-remainder",
			scheduled: 750,
			batch:     128,
			rate:      25,
			wantSizes: []int{128, 128, 128, 128, 128, 110},
			wantTimes: []time.Duration{0, 5120 * time.Millisecond, 10240 * time.Millisecond, 15360 * time.Millisecond, 20480 * time.Millisecond, 25600 * time.Millisecond},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var sent uint64
			for index := range test.wantSizes {
				size, at := frameMassNextPacket(test.scheduled, sent, test.batch, test.rate)
				if size != test.wantSizes[index] || at != test.wantTimes[index] {
					t.Fatalf("packet %d: have size=%d at=%s, want size=%d at=%s", index, size, at, test.wantSizes[index], test.wantTimes[index])
				}
				sent += uint64(size)
			}
			if sent != test.scheduled {
				t.Fatalf("scheduled %d transactions, accounted for %d", test.scheduled, sent)
			}
		})
	}
}

func TestFrameMassStreamConfigGuardsPacketDuplicates(t *testing.T) {
	valid := FrameMassStreamConfig{
		Corpus:    "bls",
		ChainID:   1337,
		VerifyGas: 100_000,
		Count:     16,
		Peers:     1,
		Batch:     16,
		Rate:      25,
		Duration:  time.Second,
		HashMode:  frameMassHashModeExact,
	}
	for _, mode := range []string{frameMassHashModeExact, frameMassHashModeUnique} {
		config := valid
		config.HashMode = mode
		config.Batch = config.Count + 1
		if err := validateFrameMassStreamConfig(config); err == nil {
			t.Fatalf("mode %s accepted batch greater than sender count", mode)
		}
	}
	invalidMode := valid
	invalidMode.HashMode = "almost-exact"
	if err := validateFrameMassStreamConfig(invalidMode); err == nil {
		t.Fatal("invalid hash mode accepted")
	}
}
