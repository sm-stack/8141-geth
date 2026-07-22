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

package core

import (
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestMakeFrameReceipts(t *testing.T) {
	txLogs := []*types.Log{
		{Address: common.HexToAddress("0x1001")},
		{Address: common.HexToAddress("0x1002")},
		{Address: common.HexToAddress("0x1003")},
	}
	result := &ExecutionResult{
		frameResults: []uint8{1, 3, 0, 1},
		frameGasUsed: []uint64{11, 22},
		frameLogRange: []frameLogRange{
			{start: 0, end: 1},
			{start: 1, end: 3},
			{start: -10, end: 99},
		},
	}
	frames := makeFrameReceipts(result, txLogs)
	if len(frames) != 4 {
		t.Fatalf("frame receipt count mismatch: got %d want 4", len(frames))
	}
	if frames[0].Status != 1 || frames[1].Status != 3 || frames[2].Status != 0 || frames[3].Status != 1 {
		t.Fatalf("unexpected frame statuses: %#v", frames)
	}
	if frames[0].GasUsed != 11 || frames[1].GasUsed != 22 || frames[2].GasUsed != 0 || frames[3].GasUsed != 0 {
		t.Fatalf("unexpected frame gas usage: %#v", frames)
	}
	if !reflect.DeepEqual(frames[0].Logs, txLogs[0:1]) {
		t.Fatalf("unexpected logs for frame 0: got %#v want %#v", frames[0].Logs, txLogs[0:1])
	}
	if !reflect.DeepEqual(frames[1].Logs, txLogs[1:3]) {
		t.Fatalf("unexpected logs for frame 1: got %#v want %#v", frames[1].Logs, txLogs[1:3])
	}
	if !reflect.DeepEqual(frames[2].Logs, txLogs) {
		t.Fatalf("unexpected logs for frame 2: got %#v want %#v", frames[2].Logs, txLogs)
	}
	if frames[3].Logs != nil {
		t.Fatalf("expected nil logs for frame 3, got %#v", frames[3].Logs)
	}
}

func TestLogsInRange(t *testing.T) {
	txLogs := []*types.Log{
		{Address: common.HexToAddress("0x1001")},
		{Address: common.HexToAddress("0x1002")},
		{Address: common.HexToAddress("0x1003")},
	}
	if got := logsInRange(txLogs, frameLogRange{start: 1, end: 2}); !reflect.DeepEqual(got, txLogs[1:2]) {
		t.Fatalf("unexpected logs: got %#v want %#v", got, txLogs[1:2])
	}
	if got := logsInRange(txLogs, frameLogRange{start: 4, end: 10}); got != nil {
		t.Fatalf("expected nil logs for out-of-bounds range, got %#v", got)
	}
	if got := logsInRange(txLogs, frameLogRange{start: 2, end: 1}); got != nil {
		t.Fatalf("expected nil logs for reversed range, got %#v", got)
	}
}
