// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package framepool

import "testing"

func TestConfigSanitized(t *testing.T) {
	defaults := (Config{}).Sanitized()
	if defaults.MaxVerifyGas != PublicMaxVerifyGas {
		t.Fatalf("default validation gas = %d, want %d", defaults.MaxVerifyGas, PublicMaxVerifyGas)
	}
	if defaults.MaxPendingPerSender != PublicMaxPendingPerSender {
		t.Fatalf("default sender limit = %d, want %d", defaults.MaxPendingPerSender, PublicMaxPendingPerSender)
	}
	if defaults.MaxPendingPerNonCanonicalPaymaster != PublicMaxPendingPerNonCanonicalPaymaster {
		t.Fatalf("default paymaster limit = %d, want %d", defaults.MaxPendingPerNonCanonicalPaymaster, PublicMaxPendingPerNonCanonicalPaymaster)
	}
	if defaults.MaxPoolSize != defaultMaxFramePoolSize {
		t.Fatalf("default pool size = %d, want %d", defaults.MaxPoolSize, defaultMaxFramePoolSize)
	}
	if defaults.ResetValidationWorkers != defaultResetValidationWorkers() {
		t.Fatalf("default reset workers = %d, want %d", defaults.ResetValidationWorkers, defaultResetValidationWorkers())
	}

	explicit := Config{
		MaxVerifyGas:                       200_000,
		MaxPendingPerSender:                8,
		MaxPendingPerNonCanonicalPaymaster: 16,
		MaxPoolSize:                        1024,
		ResetValidationWorkers:             3,
		AllowUnsafeBenchmarkPolicy:         true,
	}
	if got := explicit.Sanitized(); got != explicit {
		t.Fatalf("explicit configuration changed: have %+v want %+v", got, explicit)
	}

	invalid := Config{
		MaxPendingPerSender:                -1,
		MaxPendingPerNonCanonicalPaymaster: -1,
		MaxPoolSize:                        -1,
		ResetValidationWorkers:             -1,
	}.Sanitized()
	if invalid.MaxPendingPerSender != defaults.MaxPendingPerSender ||
		invalid.MaxPendingPerNonCanonicalPaymaster != defaults.MaxPendingPerNonCanonicalPaymaster ||
		invalid.MaxPoolSize != defaults.MaxPoolSize ||
		invalid.ResetValidationWorkers != defaults.ResetValidationWorkers {
		t.Fatalf("invalid configuration was not normalized: have %+v want numeric defaults %+v", invalid, defaults)
	}
}

func TestConfigPropagatesToFramePool(t *testing.T) {
	standard, _, _ := newTestEnv()
	config := Config{
		MaxVerifyGas:                       200_000,
		MaxPendingPerSender:                8,
		MaxPendingPerNonCanonicalPaymaster: 16,
		MaxPoolSize:                        1024,
		ResetValidationWorkers:             3,
	}
	pool := NewWithConfig(config, standard.chain)
	if pool.verifyGasCap != config.MaxVerifyGas ||
		pool.limits.maxPendingPerSender != config.MaxPendingPerSender ||
		pool.limits.maxPendingPerNonCanonicalPaymaster != config.MaxPendingPerNonCanonicalPaymaster ||
		pool.limits.maxPoolSize != config.MaxPoolSize ||
		pool.resetValidationWorkers != config.ResetValidationWorkers {
		t.Fatalf("frame pool configuration mismatch: %+v", pool)
	}
}
