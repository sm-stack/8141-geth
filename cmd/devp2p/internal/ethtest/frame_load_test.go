// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package ethtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/internal/framecorpus"
	"github.com/ethereum/go-ethereum/rlp"
)

func TestFrameLoadPongPayload(t *testing.T) {
	payload, err := rlp.EncodeToBytes(frameLoadPongPayload())
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xc0}; !bytes.Equal(payload, want) {
		t.Fatalf("pong payload: have %x want %x", payload, want)
	}
}

func TestFrameLoadErrorCounters(t *testing.T) {
	counters := new(frameLoadCounters)
	counters.recordReadError(errors.New("read"))
	counters.recordWriteError(errors.New("write"))
	counters.recordDisconnect(errors.New("disconnect"))
	counters.recordOtherError(errors.New("other"))

	if got := counters.readErrors.Load(); got != 1 {
		t.Fatalf("read errors: have %d want 1", got)
	}
	if got := counters.writeErrors.Load(); got != 1 {
		t.Fatalf("write errors: have %d want 1", got)
	}
	if got := counters.disconnects.Load(); got != 1 {
		t.Fatalf("disconnects: have %d want 1", got)
	}
	if got := counters.otherErrors.Load(); got != 1 {
		t.Fatalf("other errors: have %d want 1", got)
	}
	if got := len(counters.errors); got != 4 {
		t.Fatalf("recorded errors: have %d want 4", got)
	}
}

func TestFrameResultErrorJSONCompatibility(t *testing.T) {
	for _, test := range []struct {
		name   string
		result any
	}{
		{name: "frame-load", result: FrameLoadResult{}},
		{name: "frame-mass", result: FrameMassResult{}},
		{name: "frame-mass-stream", result: FrameMassStreamResult{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			blob, err := json.Marshal(test.result)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(blob, &fields); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"write_errors", "read_errors", "peer_disconnects", "other_errors"} {
				if _, ok := fields[name]; !ok {
					t.Fatalf("missing JSON field %q", name)
				}
			}
		})
	}
}

func TestFrameLoadValidationSplitCorpus(t *testing.T) {
	config := FrameLoadConfig{Corpus: framecorpus.PairingPureFirst, ChainID: 1337, VerifyGas: framecorpus.VerifyGas}
	first, err := frameLoadTx(config, 1)
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := frameLoadTx(config, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := frameLoadTx(config, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Frames()[0].Data, repeat.Frames()[0].Data) {
		t.Fatal("same transaction variant did not retain its pairing input")
	}
	if bytes.Equal(first.Frames()[0].Data, second.Frames()[0].Data) {
		t.Fatal("different transaction variants reused a pairing input")
	}
	workload, err := framecorpus.WorkloadFor(config.Corpus, 1)
	if err != nil {
		t.Fatal(err)
	}
	if code := FrameLoadGenesisCode()[workload.Sender]; !bytes.Equal(code, workload.Code) {
		t.Fatal("frame-load genesis code differs from the shared corpus")
	}
	if _, err := frameLoadIterations(config.Corpus, framecorpus.VerifyGas-1); err == nil {
		t.Fatal("pairing corpus accepted an undersized gas limit")
	}
}
