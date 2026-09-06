// Copyright 2019 The go-ethereum Authors
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

// Package utils contains internal helper functions for go-ethereum commands.
package utils

import (
	"flag"
	"reflect"
	"testing"

	"github.com/urfave/cli/v2"
)

func Test_SplitTagsFlag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args string
		want map[string]string
	}{
		{
			"2 tags case",
			"host=localhost,bzzkey=123",
			map[string]string{
				"host":   "localhost",
				"bzzkey": "123",
			},
		},
		{
			"1 tag case",
			"host=localhost123",
			map[string]string{
				"host": "localhost123",
			},
		},
		{
			"empty case",
			"",
			map[string]string{},
		},
		{
			"garbage",
			"smth=smthelse=123",
			map[string]string{
				"smth": "smthelse=123",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := SplitTagsFlag(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitTagsFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNetworkPresetUsesFlagValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "unset",
			want: false,
		},
		{
			name: "enabled",
			args: []string{"--sepolia"},
			want: true,
		},
		{
			name: "explicit false",
			args: []string{"--sepolia=false"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := newTestContext(t, tt.args, NetworkFlags...)
			if got := IsNetworkPreset(ctx); got != tt.want {
				t.Fatalf("IsNetworkPreset() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFramePoolValidationFlags(t *testing.T) {
	ctx := newTestContext(t, []string{
		"--framepool.maxstatedependentverifygas=20000",
		"--framepool.cachevalidationprecompiles",
		"--framepool.rejectincompletevalidationmemo",
		"--framepool.validationmemomaxentries=4",
		"--framepool.validationmemomaxbytes=8192",
	},
		FramePoolMaxStateDependentVerifyGasFlag,
		FramePoolCacheValidationPrecompilesFlag,
		FramePoolRejectIncompleteValidationMemoFlag,
		FramePoolValidationMemoMaxEntriesFlag,
		FramePoolValidationMemoMaxBytesFlag,
	)
	if got := ctx.Uint64(FramePoolMaxStateDependentVerifyGasFlag.Name); got != 20_000 {
		t.Fatalf("state-dependent gas flag = %d", got)
	}
	if !ctx.Bool(FramePoolCacheValidationPrecompilesFlag.Name) {
		t.Fatal("validation precompile memo flag was not enabled")
	}
	if !ctx.Bool(FramePoolRejectIncompleteValidationMemoFlag.Name) {
		t.Fatal("strict validation memo flag was not enabled")
	}
	if got := ctx.Int(FramePoolValidationMemoMaxEntriesFlag.Name); got != 4 {
		t.Fatalf("memo entries flag = %d", got)
	}
	if got := ctx.Uint64(FramePoolValidationMemoMaxBytesFlag.Name); got != 8192 {
		t.Fatalf("memo bytes flag = %d", got)
	}
}

func newTestContext(t *testing.T, args []string, flags ...cli.Flag) *cli.Context {
	t.Helper()

	set := flag.NewFlagSet("test", flag.ContinueOnError)
	for _, f := range flags {
		if err := f.Apply(set); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Parse(args); err != nil {
		t.Fatal(err)
	}
	return cli.NewContext(nil, set, nil)
}
