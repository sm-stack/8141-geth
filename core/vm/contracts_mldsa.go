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
	"crypto/subtle"
	"encoding/binary"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/crypto/sha3"
)

// ML-DSA-44 parameters (NIST Level II, FIPS 204).
const (
	mldsaN      = 256                // polynomial degree
	mldsaQ      = 8380417            // field modulus
	mldsaK      = 4                  // matrix rows
	mldsaL      = 4                  // matrix columns
	mldsaGamma1 = 1 << 17           // 131072
	mldsaGamma2 = (mldsaQ - 1) / 88 // 95232
	mldsaBeta   = 78                 // tau * eta
	mldsaTau    = 39                 // number of +/-1 in challenge
	mldsaD      = 13                 // dropped bits of t
	mldsaOmega  = 80                 // max hint weight

	// Input layout sizes.
	mldsaMsgSize   = 32
	mldsaSigSize   = 2420                                      // 32 c_tilde + 2304 z + 84 h
	mldsaPKSize    = 20512                                     // 16384 A_hat + 32 tr + 4096 t1
	mldsaInputSize = mldsaMsgSize + mldsaSigSize + mldsaPKSize // 22964

	// Sub-field sizes within signature.
	mldsaCTildeSize = 32
	mldsaZSize      = 2304 // l * 576 (18-bit packed)

	// Sub-field sizes within public key.
	mldsaAHatSize = 16384 // k * l * 256 * 4 bytes
	mldsaTrSize   = 32
)

// ---------------------------------------------------------------------------
// NTT twiddle factors
// ---------------------------------------------------------------------------

// mldsaZetas contains precomputed twiddle factors for the NTT.
// Computed at init time: zetas[i] = pow(1753, bitrev8(i)) mod q.
// 1753 is a primitive 512th root of unity mod q=8380417.
var mldsaZetas [mldsaN]int32

func init() {
	const psi = 1753
	for i := 0; i < mldsaN; i++ {
		mldsaZetas[i] = mldsaPowModQ(psi, int64(bitRev8(uint8(i))))
	}
}

func bitRev8(x uint8) uint8 {
	x = (x&0xF0)>>4 | (x&0x0F)<<4
	x = (x&0xCC)>>2 | (x&0x33)<<2
	x = (x&0xAA)>>1 | (x&0x55)<<1
	return x
}

func mldsaPowModQ(base int32, exp int64) int32 {
	result := int64(1)
	b := int64(base) % int64(mldsaQ)
	if b < 0 {
		b += int64(mldsaQ)
	}
	for exp > 0 {
		if exp&1 == 1 {
			result = (result * b) % int64(mldsaQ)
		}
		b = (b * b) % int64(mldsaQ)
		exp >>= 1
	}
	return int32(result)
}

// ---------------------------------------------------------------------------
// Precompile structs
// ---------------------------------------------------------------------------

// verifyMLDSA implements EIP-8051 VERIFY_MLDSA at address 0x12.
// Uses NIST-compliant SHAKE256 (FIPS 204).
type verifyMLDSA struct{}

func (c *verifyMLDSA) RequiredGas(input []byte) uint64 { return params.VerifyMLDSAGas }

func (c *verifyMLDSA) Run(input []byte) ([]byte, error) {
	return verifyMLDSACore(input, false)
}

func (c *verifyMLDSA) Name() string { return "VERIFY_MLDSA" }

// verifyMLDSAEth implements EIP-8051 VERIFY_MLDSA_ETH at address 0x13.
// Uses Keccak-based PRNG instead of SHAKE256 for EVM efficiency.
type verifyMLDSAEth struct{}

func (c *verifyMLDSAEth) RequiredGas(input []byte) uint64 { return params.VerifyMLDSAGas }

func (c *verifyMLDSAEth) Run(input []byte) ([]byte, error) {
	return verifyMLDSACore(input, true)
}

func (c *verifyMLDSAEth) Name() string { return "VERIFY_MLDSA_ETH" }

// ---------------------------------------------------------------------------
// Core verification (FIPS 204 Algorithm 8)
// ---------------------------------------------------------------------------

func verifyMLDSACore(input []byte, useKeccak bool) ([]byte, error) {
	if len(input) != mldsaInputSize {
		return nil, nil
	}

	// Parse input regions.
	msg := input[0:mldsaMsgSize]
	sigBytes := input[mldsaMsgSize : mldsaMsgSize+mldsaSigSize]
	pkBytes := input[mldsaMsgSize+mldsaSigSize:]

	// Decode public key: A_hat (k*l polys), tr (32 bytes), t1 (k polys in NTT domain).
	aHat, ok := mldsaDecodeAHat(pkBytes[0:mldsaAHatSize])
	if !ok {
		return false32Byte, nil
	}
	tr := pkBytes[mldsaAHatSize : mldsaAHatSize+mldsaTrSize]
	t1, ok := mldsaDecodePolys(pkBytes[mldsaAHatSize+mldsaTrSize:], mldsaK)
	if !ok {
		return false32Byte, nil
	}

	// Decode signature: c_tilde (32 bytes), z (l polys), h (hint vector).
	cTilde := sigBytes[0:mldsaCTildeSize]
	z, ok := mldsaDecodeZ(sigBytes[mldsaCTildeSize : mldsaCTildeSize+mldsaZSize])
	if !ok {
		return false32Byte, nil
	}
	h, ok := mldsaDecodeH(sigBytes[mldsaCTildeSize+mldsaZSize:])
	if !ok {
		return false32Byte, nil
	}

	// Check ||z||_inf < gamma1 - beta.
	if !mldsaCheckZNorm(z) {
		return false32Byte, nil
	}

	// mu = XOF(tr || msg).squeeze(64)
	mu := mldsaComputeMu(tr, msg, useKeccak)

	// c = SampleInBall(c_tilde)
	c := mldsaSampleInBall(cTilde, useKeccak)
	cNTT := mldsaNTTForward(c)

	// NTT(z)
	var zNTT [mldsaL][mldsaN]int32
	for i := 0; i < mldsaL; i++ {
		zNTT[i] = mldsaNTTForward(z[i])
	}

	// w = A_hat * NTT(z) - NTT(c) * (2^d * t1)   [all in NTT domain]
	az := mldsaMatVecMulNTT(aHat, zNTT)
	var w [mldsaK][mldsaN]int32
	for i := 0; i < mldsaK; i++ {
		var ct1 [mldsaN]int32
		for j := 0; j < mldsaN; j++ {
			scaled := mldsaMulModQ(t1[i][j], 1<<mldsaD)
			ct1[j] = mldsaMulModQ(cNTT[j], scaled)
		}
		diff := mldsaPolySub(az[i], ct1)
		w[i] = mldsaNTTInverse(diff)
	}

	// Apply hint: w1' = UseHint(h, w)
	var w1Prime [mldsaK][mldsaN]int32
	for i := 0; i < mldsaK; i++ {
		for j := 0; j < mldsaN; j++ {
			w1Prime[i][j] = mldsaUseHint(h[i][j], w[i][j])
		}
	}

	// c_tilde' = XOF(mu || encodeW1(w1')).squeeze(32)
	cTildeCheck := mldsaComputeCTilde(mu, w1Prime, useKeccak)

	if subtle.ConstantTimeCompare(cTilde, cTildeCheck) == 1 {
		return true32Byte, nil
	}
	return false32Byte, nil
}

// ---------------------------------------------------------------------------
// Modular arithmetic (q = 8380417 < 2^23; products < 2^46, fits int64)
// ---------------------------------------------------------------------------

func mldsaModQ(x int64) int32 {
	r := x % int64(mldsaQ)
	if r < 0 {
		r += int64(mldsaQ)
	}
	return int32(r)
}

func mldsaAddModQ(a, b int32) int32 {
	return mldsaModQ(int64(a) + int64(b))
}

func mldsaSubModQ(a, b int32) int32 {
	return mldsaModQ(int64(a) - int64(b))
}

func mldsaMulModQ(a, b int32) int32 {
	return mldsaModQ(int64(a) * int64(b))
}

// ---------------------------------------------------------------------------
// NTT (Cooley-Tukey / Gentleman-Sande butterflies)
// Reference: FIPS 204, Dilithium reference implementation.
// ---------------------------------------------------------------------------

func mldsaNTTForward(a [mldsaN]int32) [mldsaN]int32 {
	k := 0
	for length := 128; length >= 1; length >>= 1 {
		for start := 0; start < mldsaN; start += 2 * length {
			k++
			zeta := mldsaZetas[k]
			for j := start; j < start+length; j++ {
				t := mldsaMulModQ(zeta, a[j+length])
				a[j+length] = mldsaSubModQ(a[j], t)
				a[j] = mldsaAddModQ(a[j], t)
			}
		}
	}
	return a
}

func mldsaNTTInverse(a [mldsaN]int32) [mldsaN]int32 {
	k := mldsaN
	for length := 1; length < mldsaN; length <<= 1 {
		for start := 0; start < mldsaN; start += 2 * length {
			k--
			zeta := mldsaZetas[k]
			for j := start; j < start+length; j++ {
				t := a[j]
				a[j] = mldsaAddModQ(t, a[j+length])
				a[j+length] = mldsaMulModQ(zeta, mldsaSubModQ(a[j+length], t))
			}
		}
	}
	// Multiply by n^{-1} mod q.  256^{-1} mod 8380417 = 8347681.
	const nInv int32 = 8347681
	for i := range a {
		a[i] = mldsaMulModQ(a[i], nInv)
	}
	return a
}

// ---------------------------------------------------------------------------
// Polynomial / vector operations
// ---------------------------------------------------------------------------

func mldsaPolyAdd(a, b [mldsaN]int32) [mldsaN]int32 {
	var c [mldsaN]int32
	for i := 0; i < mldsaN; i++ {
		c[i] = mldsaAddModQ(a[i], b[i])
	}
	return c
}

func mldsaPolySub(a, b [mldsaN]int32) [mldsaN]int32 {
	var c [mldsaN]int32
	for i := 0; i < mldsaN; i++ {
		c[i] = mldsaSubModQ(a[i], b[i])
	}
	return c
}

func mldsaPolyMulNTT(a, b [mldsaN]int32) [mldsaN]int32 {
	var c [mldsaN]int32
	for i := 0; i < mldsaN; i++ {
		c[i] = mldsaMulModQ(a[i], b[i])
	}
	return c
}

func mldsaMatVecMulNTT(aHat [mldsaK][mldsaL][mldsaN]int32, v [mldsaL][mldsaN]int32) [mldsaK][mldsaN]int32 {
	var result [mldsaK][mldsaN]int32
	for i := 0; i < mldsaK; i++ {
		for j := 0; j < mldsaL; j++ {
			t := mldsaPolyMulNTT(aHat[i][j], v[j])
			result[i] = mldsaPolyAdd(result[i], t)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Encoding / Decoding
// ---------------------------------------------------------------------------

// mldsaDecodeAHat decodes a k*l matrix of polynomials from 4-byte LE coefficients.
func mldsaDecodeAHat(data []byte) ([mldsaK][mldsaL][mldsaN]int32, bool) {
	var m [mldsaK][mldsaL][mldsaN]int32
	off := 0
	for i := 0; i < mldsaK; i++ {
		for j := 0; j < mldsaL; j++ {
			for c := 0; c < mldsaN; c++ {
				v := int32(binary.LittleEndian.Uint32(data[off : off+4]))
				if v < 0 || v >= mldsaQ {
					return m, false
				}
				m[i][j][c] = v
				off += 4
			}
		}
	}
	return m, true
}

// mldsaDecodePolys decodes count polynomials from 4-byte LE coefficients.
func mldsaDecodePolys(data []byte, count int) ([mldsaK][mldsaN]int32, bool) {
	var polys [mldsaK][mldsaN]int32
	off := 0
	for i := 0; i < count; i++ {
		for c := 0; c < mldsaN; c++ {
			v := int32(binary.LittleEndian.Uint32(data[off : off+4]))
			if v < 0 || v >= mldsaQ {
				return polys, false
			}
			polys[i][c] = v
			off += 4
		}
	}
	return polys, true
}

// mldsaDecodeZ decodes l polynomials with 18-bit packed signed coefficients.
// Each coefficient is in [-gamma1+1, gamma1]. Stored as gamma1 - coeff (unsigned 18-bit).
func mldsaDecodeZ(data []byte) ([mldsaL][mldsaN]int32, bool) {
	var z [mldsaL][mldsaN]int32
	// 18 bits per coeff, 256 coeffs = 576 bytes per polynomial.
	for i := 0; i < mldsaL; i++ {
		polyData := data[i*576 : (i+1)*576]
		for j := 0; j < mldsaN/4; j++ {
			// 4 coefficients * 18 bits = 72 bits = 9 bytes.
			base := j * 9

			c0 := uint32(polyData[base+0]) | uint32(polyData[base+1])<<8 | (uint32(polyData[base+2])&0x03)<<16
			c1 := uint32(polyData[base+2])>>2 | uint32(polyData[base+3])<<6 | (uint32(polyData[base+4])&0x0F)<<14
			c2 := uint32(polyData[base+4])>>4 | uint32(polyData[base+5])<<4 | (uint32(polyData[base+6])&0x3F)<<12
			c3 := uint32(polyData[base+6])>>6 | uint32(polyData[base+7])<<2 | uint32(polyData[base+8])<<10

			// Decode: stored as gamma1 - coeff, so coeff = gamma1 - stored.
			z[i][j*4+0] = mldsaModQ(int64(mldsaGamma1) - int64(c0))
			z[i][j*4+1] = mldsaModQ(int64(mldsaGamma1) - int64(c1))
			z[i][j*4+2] = mldsaModQ(int64(mldsaGamma1) - int64(c2))
			z[i][j*4+3] = mldsaModQ(int64(mldsaGamma1) - int64(c3))
		}
	}
	return z, true
}

// mldsaDecodeH decodes the hint vector from omega+k = 84 bytes.
// FIPS 204 Algorithm 21 (HintBitUnpack).
func mldsaDecodeH(data []byte) ([mldsaK][mldsaN]int32, bool) {
	var h [mldsaK][mldsaN]int32
	idx := 0
	for i := 0; i < mldsaK; i++ {
		limit := int(data[mldsaOmega+i])
		if limit < idx || limit > mldsaOmega {
			return h, false
		}
		prev := -1
		for idx < limit {
			pos := int(data[idx])
			if pos >= mldsaN {
				return h, false
			}
			if pos <= prev {
				return h, false
			}
			h[i][pos] = 1
			prev = pos
			idx++
		}
	}
	for i := idx; i < mldsaOmega; i++ {
		if data[i] != 0 {
			return h, false
		}
	}
	return h, true
}

// ---------------------------------------------------------------------------
// Norm check
// ---------------------------------------------------------------------------

func mldsaCheckZNorm(z [mldsaL][mldsaN]int32) bool {
	bound := int32(mldsaGamma1 - mldsaBeta)
	for i := 0; i < mldsaL; i++ {
		for j := 0; j < mldsaN; j++ {
			v := z[i][j]
			if v > mldsaQ/2 {
				v = v - mldsaQ
			}
			if v < 0 {
				v = -v
			}
			if v >= bound {
				return false
			}
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Decompose / UseHint (FIPS 204 Algorithms 36-37)
// ---------------------------------------------------------------------------

func mldsaDecompose(r int32) (r1, r0 int32) {
	r0 = mldsaCenterMod(r, 2*int32(mldsaGamma2))
	if int64(r)-int64(r0) == int64(mldsaQ)-1 {
		r1 = 0
		r0--
	} else {
		r1 = int32((int64(r) - int64(r0)) / int64(2*mldsaGamma2))
	}
	return
}

func mldsaCenterMod(a int32, alpha int32) int32 {
	r := a % alpha
	if r < 0 {
		r += alpha
	}
	if r > alpha/2 {
		r -= alpha
	}
	return r
}

func mldsaUseHint(hint int32, r int32) int32 {
	r1, r0 := mldsaDecompose(r)
	if hint == 0 {
		return r1
	}
	m := int32((mldsaQ - 1) / (2 * mldsaGamma2))
	if r0 > 0 {
		return (r1 + 1) % m
	}
	return (r1 - 1 + m) % m
}

// ---------------------------------------------------------------------------
// XOF: SHAKE256 vs Keccak PRNG
// ---------------------------------------------------------------------------

type mldsaXOF interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
}

func mldsaNewXOF(useKeccak bool) mldsaXOF {
	if useKeccak {
		return &keccakPRNG{}
	}
	return sha3.NewShake256()
}

// keccakPRNG implements a counter-mode PRNG based on Keccak256
// as specified in the ML-DSA-ETH variant of EIP-8051.
type keccakPRNG struct {
	seed    []byte
	ctr     uint64
	buf     []byte
	pos     int
	flipped bool // true after first Read (flip() from absorb to squeeze)
}

func (k *keccakPRNG) Write(p []byte) (int, error) {
	k.seed = append(k.seed, p...)
	return len(p), nil
}

func (k *keccakPRNG) Read(p []byte) (int, error) {
	if !k.flipped {
		k.ctr = 0
		k.buf = nil
		k.pos = 0
		k.flipped = true
	}
	n := 0
	for n < len(p) {
		if k.pos >= len(k.buf) {
			ctrBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(ctrBytes, k.ctr)
			input := make([]byte, len(k.seed)+8)
			copy(input, k.seed)
			copy(input[len(k.seed):], ctrBytes)
			k.buf = crypto.Keccak256(input)
			k.ctr++
			k.pos = 0
		}
		copied := copy(p[n:], k.buf[k.pos:])
		k.pos += copied
		n += copied
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Hash computations
// ---------------------------------------------------------------------------

func mldsaComputeMu(tr, msg []byte, useKeccak bool) []byte {
	xof := mldsaNewXOF(useKeccak)
	combined := make([]byte, len(tr)+len(msg))
	copy(combined, tr)
	copy(combined[len(tr):], msg)
	xof.Write(combined)
	mu := make([]byte, 64)
	xof.Read(mu)
	return mu
}

// mldsaSampleInBall implements FIPS 204 Algorithm 29.
func mldsaSampleInBall(seed []byte, useKeccak bool) [mldsaN]int32 {
	xof := mldsaNewXOF(useKeccak)
	xof.Write(seed)

	var c [mldsaN]int32

	var signBytes [8]byte
	xof.Read(signBytes[:])
	signs := binary.LittleEndian.Uint64(signBytes[:])

	for i := mldsaN - mldsaTau; i < mldsaN; i++ {
		var jBuf [1]byte
		for {
			xof.Read(jBuf[:])
			j := int(jBuf[0])
			if j <= i {
				c[i] = c[j]
				if signs&1 == 1 {
					c[j] = mldsaQ - 1 // -1 mod q
				} else {
					c[j] = 1
				}
				signs >>= 1
				break
			}
		}
	}
	return c
}

// mldsaComputeCTilde computes XOF(mu || encodeW1(w1Prime)).squeeze(32).
func mldsaComputeCTilde(mu []byte, w1Prime [mldsaK][mldsaN]int32, useKeccak bool) []byte {
	xof := mldsaNewXOF(useKeccak)
	w1Enc := mldsaEncodeW1(w1Prime)
	combined := make([]byte, len(mu)+len(w1Enc))
	copy(combined, mu)
	copy(combined[len(mu):], w1Enc)
	xof.Write(combined)
	out := make([]byte, 32)
	xof.Read(out)
	return out
}

// mldsaEncodeW1 packs w1 coefficients (each in [0, 43]) as 6-bit values.
// 256 * 6 / 8 = 192 bytes per polynomial.
func mldsaEncodeW1(w1 [mldsaK][mldsaN]int32) []byte {
	out := make([]byte, mldsaK*192)
	for i := 0; i < mldsaK; i++ {
		for j := 0; j < mldsaN/4; j++ {
			c0 := byte(w1[i][j*4+0] & 0x3F)
			c1 := byte(w1[i][j*4+1] & 0x3F)
			c2 := byte(w1[i][j*4+2] & 0x3F)
			c3 := byte(w1[i][j*4+3] & 0x3F)
			base := i*192 + j*3
			out[base+0] = c0 | (c1 << 6)
			out[base+1] = (c1 >> 2) | (c2 << 4)
			out[base+2] = (c2 >> 4) | (c3 << 2)
		}
	}
	return out
}
