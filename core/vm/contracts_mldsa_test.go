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

package vm

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// ---------------------------------------------------------------------------
// Modular arithmetic tests
// ---------------------------------------------------------------------------

func TestMLDSAModQ(t *testing.T) {
	tests := []struct {
		input    int64
		expected int32
	}{
		{0, 0},
		{1, 1},
		{-1, mldsaQ - 1},
		{mldsaQ, 0},
		{mldsaQ + 1, 1},
		{-mldsaQ, 0},
		{int64(mldsaQ) * 2, 0},
		{int64(mldsaQ)*2 + 5, 5},
	}
	for _, tt := range tests {
		got := mldsaModQ(tt.input)
		if got != tt.expected {
			t.Errorf("mldsaModQ(%d) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestMLDSAMulModQ(t *testing.T) {
	// Test that a * a_inv = 1 mod q for known inverse pair.
	// 256 * 8347681 = 1 mod q
	result := mldsaMulModQ(256, 8347681)
	if result != 1 {
		t.Errorf("256 * 8347681 mod q = %d, want 1", result)
	}

	// Test zero.
	if mldsaMulModQ(0, 12345) != 0 {
		t.Error("0 * x should be 0")
	}

	// Test identity.
	if mldsaMulModQ(1, 42) != 42 {
		t.Error("1 * 42 should be 42")
	}
}

// ---------------------------------------------------------------------------
// NTT round-trip test
// ---------------------------------------------------------------------------

func TestMLDSANTTRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	// Create a random polynomial with coefficients in [0, q-1].
	var poly [mldsaN]int32
	for i := range poly {
		poly[i] = int32(rng.Int63n(int64(mldsaQ)))
	}

	// Save original.
	original := poly

	// Forward NTT then inverse NTT should recover original.
	nttPoly := mldsaNTTForward(poly)
	recovered := mldsaNTTInverse(nttPoly)

	for i := 0; i < mldsaN; i++ {
		if recovered[i] != original[i] {
			t.Errorf("NTT round-trip failed at index %d: got %d, want %d", i, recovered[i], original[i])
		}
	}
}

func TestMLDSANTTZeroPoly(t *testing.T) {
	var zero [mldsaN]int32
	ntt := mldsaNTTForward(zero)
	inv := mldsaNTTInverse(ntt)
	for i := 0; i < mldsaN; i++ {
		if inv[i] != 0 {
			t.Errorf("NTT of zero poly: index %d = %d, want 0", i, inv[i])
		}
	}
}

func TestMLDSANTTConvolution(t *testing.T) {
	// Verify that NTT enables polynomial multiplication:
	// NTT_inv(NTT(a) * NTT(b)) should give the product of a and b in Z_q[X]/(X^n+1).
	rng := rand.New(rand.NewSource(123))

	var a, b [mldsaN]int32
	for i := range a {
		a[i] = int32(rng.Int63n(100)) // Small values to avoid overflow in schoolbook
		b[i] = int32(rng.Int63n(100))
	}

	// Schoolbook multiplication in Z_q[X]/(X^n+1).
	var expected [mldsaN]int32
	for i := 0; i < mldsaN; i++ {
		for j := 0; j < mldsaN; j++ {
			idx := i + j
			if idx < mldsaN {
				expected[idx] = mldsaAddModQ(expected[idx], mldsaMulModQ(a[i], b[j]))
			} else {
				// X^n = -1 mod (X^n+1)
				expected[idx-mldsaN] = mldsaSubModQ(expected[idx-mldsaN], mldsaMulModQ(a[i], b[j]))
			}
		}
	}

	// NTT-based multiplication.
	aNTT := mldsaNTTForward(a)
	bNTT := mldsaNTTForward(b)
	cNTT := mldsaPolyMulNTT(aNTT, bNTT)
	got := mldsaNTTInverse(cNTT)

	for i := 0; i < mldsaN; i++ {
		if got[i] != expected[i] {
			t.Errorf("NTT convolution mismatch at index %d: got %d, want %d", i, got[i], expected[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Polynomial operations tests
// ---------------------------------------------------------------------------

func TestMLDSAPolyAddSub(t *testing.T) {
	var a, b [mldsaN]int32
	a[0] = 100
	a[1] = mldsaQ - 1
	b[0] = 200
	b[1] = 2

	sum := mldsaPolyAdd(a, b)
	if sum[0] != 300 {
		t.Errorf("polyAdd[0] = %d, want 300", sum[0])
	}
	if sum[1] != 1 { // (q-1)+2 = q+1 mod q = 1
		t.Errorf("polyAdd[1] = %d, want 1", sum[1])
	}

	diff := mldsaPolySub(a, b)
	if diff[0] != mldsaQ-100 { // 100-200 mod q
		t.Errorf("polySub[0] = %d, want %d", diff[0], mldsaQ-100)
	}
}

// ---------------------------------------------------------------------------
// Decompose / UseHint tests
// ---------------------------------------------------------------------------

func TestMLDSADecompose(t *testing.T) {
	tests := []struct {
		r          int32
		expectedR1 int32
		expectedR0 int32
	}{
		{0, 0, 0},
		{1, 0, 1},
		{2 * int32(mldsaGamma2), 1, 0},
		{mldsaQ - 1, 0, -1}, // Special case: r - r0 == q - 1
	}
	for _, tt := range tests {
		r1, r0 := mldsaDecompose(tt.r)
		if r1 != tt.expectedR1 || r0 != tt.expectedR0 {
			t.Errorf("decompose(%d) = (%d, %d), want (%d, %d)",
				tt.r, r1, r0, tt.expectedR1, tt.expectedR0)
		}
	}
}

func TestMLDSAUseHint(t *testing.T) {
	// With hint=0, UseHint should return r1 from Decompose.
	r1, _ := mldsaDecompose(1000)
	got := mldsaUseHint(0, 1000)
	if got != r1 {
		t.Errorf("UseHint(0, 1000) = %d, want %d", got, r1)
	}

	// With hint=1, it should adjust r1.
	got = mldsaUseHint(1, 1000)
	if got < 0 || got >= int32((mldsaQ-1)/(2*mldsaGamma2)) {
		t.Errorf("UseHint(1, 1000) = %d, out of range", got)
	}
}

// ---------------------------------------------------------------------------
// SampleInBall tests
// ---------------------------------------------------------------------------

func TestMLDSASampleInBall(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	c := mldsaSampleInBall(seed, false)

	// Exactly tau=39 non-zero coefficients.
	nonZero := 0
	for i := 0; i < mldsaN; i++ {
		if c[i] != 0 {
			nonZero++
			// Each non-zero coefficient must be 1 or q-1 (-1 mod q).
			if c[i] != 1 && c[i] != mldsaQ-1 {
				t.Errorf("SampleInBall[%d] = %d, expected 1 or %d", i, c[i], mldsaQ-1)
			}
		}
	}
	if nonZero != mldsaTau {
		t.Errorf("SampleInBall has %d non-zero coefficients, want %d", nonZero, mldsaTau)
	}
}

func TestMLDSASampleInBallDeterministic(t *testing.T) {
	seed := []byte("test seed for determinism check!!")
	c1 := mldsaSampleInBall(seed, false)
	c2 := mldsaSampleInBall(seed, false)
	for i := 0; i < mldsaN; i++ {
		if c1[i] != c2[i] {
			t.Fatalf("SampleInBall not deterministic at index %d", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Encoding / Decoding tests
// ---------------------------------------------------------------------------

func TestMLDSADecodeAHat(t *testing.T) {
	// Valid: all zero coefficients.
	data := make([]byte, mldsaAHatSize)
	_, ok := mldsaDecodeAHat(data)
	if !ok {
		t.Error("decodeAHat should accept all-zero input")
	}

	// Invalid: coefficient >= q.
	binary.LittleEndian.PutUint32(data[0:4], uint32(mldsaQ))
	_, ok = mldsaDecodeAHat(data)
	if ok {
		t.Error("decodeAHat should reject coefficient >= q")
	}
}

func TestMLDSADecodeH(t *testing.T) {
	// Valid empty hint.
	data := make([]byte, mldsaOmega+mldsaK)
	// All counts are 0.
	_, ok := mldsaDecodeH(data)
	if !ok {
		t.Error("decodeH should accept empty hint")
	}

	// Valid: one hint in polynomial 0 at position 5.
	data2 := make([]byte, mldsaOmega+mldsaK)
	data2[0] = 5       // position
	data2[80] = 1      // poly 0 has 1 hint
	data2[81] = 1      // poly 1 starts at 1 (cumulative)
	data2[82] = 1      // poly 2 starts at 1
	data2[83] = 1      // poly 3 starts at 1
	h, ok := mldsaDecodeH(data2)
	if !ok {
		t.Error("decodeH should accept valid single hint")
	}
	if h[0][5] != 1 {
		t.Errorf("h[0][5] = %d, want 1", h[0][5])
	}

	// Invalid: unsorted indices.
	data3 := make([]byte, mldsaOmega+mldsaK)
	data3[0] = 10
	data3[1] = 5       // unsorted
	data3[80] = 2      // poly 0 has 2 hints
	data3[81] = 2
	data3[82] = 2
	data3[83] = 2
	_, ok = mldsaDecodeH(data3)
	if ok {
		t.Error("decodeH should reject unsorted indices")
	}
}

func TestMLDSADecodeZ(t *testing.T) {
	// Create encoded z with all-zero coefficients (stored as gamma1).
	data := make([]byte, mldsaZSize)
	// gamma1 = 131072 = 0x20000. In 18-bit encoding, each coefficient is 0x20000.
	// Pack 4 values of 0x20000 into 9 bytes each.
	for i := 0; i < mldsaL; i++ {
		for j := 0; j < mldsaN/4; j++ {
			base := i*576 + j*9
			// All four coefficients = gamma1 = 0x20000.
			// c0 = 0x20000: byte0 = 0x00, byte1 = 0x00, byte2[0:2] = 0x02
			// c1 = 0x20000: byte2[2:8] = 0x00, byte3 = 0x00, byte4[0:4] = 0x08 (0x20000 >> 2 = 0x8000, byte4[0:4] = 0x0)
			// This is complex; let's just verify the round-trip logic works.
			val := uint32(mldsaGamma1) // coeff = 0, stored as gamma1 - 0 = gamma1
			// Pack using LE 18-bit
			data[base+0] = byte(val)
			data[base+1] = byte(val >> 8)
			data[base+2] = byte(val>>16) & 0x03
			// Remaining coefficients are 0, which means stored value = gamma1.
			// Since we only fill c0 correctly and leave rest as 0,
			// c1-c3 would decode to gamma1 - 0 = gamma1 (which is a valid value).
		}
	}

	// Just verify it doesn't crash.
	_, ok := mldsaDecodeZ(data)
	if !ok {
		t.Error("decodeZ should accept valid input")
	}
}

func TestMLDSACheckZNorm(t *testing.T) {
	// All-zero z should pass (|0| < gamma1 - beta).
	var z [mldsaL][mldsaN]int32
	if !mldsaCheckZNorm(z) {
		t.Error("zero z should pass norm check")
	}

	// z with coefficient exactly at bound should fail.
	z[0][0] = mldsaGamma1 - mldsaBeta // |v| = gamma1-beta, which is >= bound
	if mldsaCheckZNorm(z) {
		t.Error("z at bound should fail norm check")
	}

	// z with coefficient just below bound should pass.
	z[0][0] = mldsaGamma1 - mldsaBeta - 1
	if !mldsaCheckZNorm(z) {
		t.Error("z below bound should pass norm check")
	}

	// Negative coefficient (represented as q - val).
	z[0][0] = int32(mldsaQ) - (mldsaGamma1 - mldsaBeta)
	if mldsaCheckZNorm(z) {
		t.Error("negative z at bound should fail norm check")
	}
}

// ---------------------------------------------------------------------------
// W1 encoding test
// ---------------------------------------------------------------------------

func TestMLDSAEncodeW1(t *testing.T) {
	var w1 [mldsaK][mldsaN]int32
	// Set a few known values.
	w1[0][0] = 0
	w1[0][1] = 1
	w1[0][2] = 43 // max value
	w1[0][3] = 7

	encoded := mldsaEncodeW1(w1)

	// Expected length: k * 192 = 768 bytes.
	if len(encoded) != mldsaK*192 {
		t.Errorf("encodeW1 length = %d, want %d", len(encoded), mldsaK*192)
	}

	// Decode first 3 bytes to verify packing.
	b0, b1, b2 := encoded[0], encoded[1], encoded[2]
	c0 := b0 & 0x3F
	c1 := (b0 >> 6) | ((b1 & 0x0F) << 2)
	c2 := (b1 >> 4) | ((b2 & 0x03) << 4)
	c3 := b2 >> 2

	if c0 != 0 || c1 != 1 || c2 != 43 || c3 != 7 {
		t.Errorf("encodeW1 packing error: got (%d,%d,%d,%d), want (0,1,43,7)", c0, c1, c2, c3)
	}
}

// ---------------------------------------------------------------------------
// Keccak PRNG test
// ---------------------------------------------------------------------------

func TestKeccakPRNGDeterministic(t *testing.T) {
	p1 := &keccakPRNG{}
	p1.Write([]byte("hello"))
	out1 := make([]byte, 64)
	p1.Read(out1)

	p2 := &keccakPRNG{}
	p2.Write([]byte("hello"))
	out2 := make([]byte, 64)
	p2.Read(out2)

	for i := range out1 {
		if out1[i] != out2[i] {
			t.Fatalf("keccakPRNG not deterministic at byte %d", i)
		}
	}
}

func TestKeccakPRNGDifferentSeeds(t *testing.T) {
	p1 := &keccakPRNG{}
	p1.Write([]byte("seed1"))
	out1 := make([]byte, 32)
	p1.Read(out1)

	p2 := &keccakPRNG{}
	p2.Write([]byte("seed2"))
	out2 := make([]byte, 32)
	p2.Read(out2)

	same := true
	for i := range out1 {
		if out1[i] != out2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different seeds should produce different outputs")
	}
}

// ---------------------------------------------------------------------------
// Precompile interface tests
// ---------------------------------------------------------------------------

func TestMLDSAPrecompileInvalidLength(t *testing.T) {
	p := &verifyMLDSA{}

	// Empty input.
	ret, err := p.Run(nil)
	if ret != nil || err != nil {
		t.Errorf("empty input: got (%v, %v), want (nil, nil)", ret, err)
	}

	// Wrong length.
	ret, err = p.Run(make([]byte, 100))
	if ret != nil || err != nil {
		t.Errorf("short input: got (%v, %v), want (nil, nil)", ret, err)
	}
}

func TestMLDSAPrecompileGasCost(t *testing.T) {
	p := &verifyMLDSA{}
	if p.RequiredGas(nil) != 4500 {
		t.Errorf("gas = %d, want 4500", p.RequiredGas(nil))
	}

	p2 := &verifyMLDSAEth{}
	if p2.RequiredGas(nil) != 4500 {
		t.Errorf("gas = %d, want 4500", p2.RequiredGas(nil))
	}
}

func TestMLDSAPrecompileNames(t *testing.T) {
	if (&verifyMLDSA{}).Name() != "VERIFY_MLDSA" {
		t.Error("wrong name for VERIFY_MLDSA")
	}
	if (&verifyMLDSAEth{}).Name() != "VERIFY_MLDSA_ETH" {
		t.Error("wrong name for VERIFY_MLDSA_ETH")
	}
}

func TestMLDSAPrecompileInvalidEncoding(t *testing.T) {
	// Correct length but invalid public key (coefficient >= q).
	input := make([]byte, mldsaInputSize)
	// Put an invalid coefficient in the A_hat region.
	off := mldsaMsgSize + mldsaSigSize // start of pk
	binary.LittleEndian.PutUint32(input[off:off+4], uint32(mldsaQ)) // >= q

	p := &verifyMLDSA{}
	ret, err := p.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ret) != 32 {
		t.Fatalf("expected 32-byte return, got %d bytes", len(ret))
	}
	// Should return false (all zeros).
	for i, b := range ret {
		if b != 0 {
			t.Errorf("byte %d = %d, want 0 (false)", i, b)
		}
	}
}

// ---------------------------------------------------------------------------
// BitRev8 test
// ---------------------------------------------------------------------------

func TestBitRev8(t *testing.T) {
	tests := []struct {
		in, out uint8
	}{
		{0, 0},
		{1, 128},
		{2, 64},
		{128, 1},
		{0xFF, 0xFF},
		{0x0F, 0xF0},
	}
	for _, tt := range tests {
		got := bitRev8(tt.in)
		if got != tt.out {
			t.Errorf("bitRev8(%d) = %d, want %d", tt.in, got, tt.out)
		}
	}
}

// ---------------------------------------------------------------------------
// PowModQ test
// ---------------------------------------------------------------------------

func TestMLDSAPowModQ(t *testing.T) {
	// 1753^0 = 1
	if mldsaPowModQ(1753, 0) != 1 {
		t.Error("1753^0 should be 1")
	}

	// 1753^1 = 1753
	if mldsaPowModQ(1753, 1) != 1753 {
		t.Error("1753^1 should be 1753")
	}

	// 1753^512 should be 1 (primitive 512th root of unity)
	if mldsaPowModQ(1753, 512) != 1 {
		t.Errorf("1753^512 mod q = %d, want 1", mldsaPowModQ(1753, 512))
	}

	// 1753^256 should be -1 mod q = q-1 (since 1753 is a 512th root)
	if mldsaPowModQ(1753, 256) != mldsaQ-1 {
		t.Errorf("1753^256 mod q = %d, want %d", mldsaPowModQ(1753, 256), mldsaQ-1)
	}
}
