package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
)

// Group order L for Curve25519[cite: 2]
var L, _ = new(big.Int).SetString("72370055773322622139731865630429942408571163593799076060019509382854642533060", 10)

// Small order points as listed in Table 1 / Appendix B of[cite: 2]
var smallOrderPoints = [][]byte{
	hexToBytes("0100000000000000000000000000000000000000000000000000000000000000"),
	hexToBytes("ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F"),
	hexToBytes("0000000000000000000000000000000000000000000000000000000000000080"),
	hexToBytes("0000000000000000000000000000000000000000000000000000000000000000"),
	hexToBytes("C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC037A"),
	hexToBytes("C7176A703D4DD84FBA3C0B760D10670F2A2053FA2C39CCC64EC7FD7792AC03FA"),
	hexToBytes("26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC05"),
	hexToBytes("26E8958FC2B227B045C3F489F2EF98F0D5DFAC05D3C63339B13802886D53FC85"),
	hexToBytes("0100000000000000000000000000000000000000000000000000000000000080"),
	hexToBytes("ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
	hexToBytes("EEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F"),
	hexToBytes("EEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
	hexToBytes("EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
	hexToBytes("EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F"),
}

// VerificationTuple represents a message, public key, and signature tuple for batch verification[cite: 2]
type VerificationTuple struct {
	Mi []byte
	Ai []byte
	Ri []byte
	Si []byte
}

func hexToBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func reverseBytes(b []byte) []byte {
	res := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		res[i] = b[len(b)-1-i]
	}
	return res
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

/**
 * Key Generation
 */
func KeyGen() ([]byte, []byte) {
	// 1. Sample uniformly random sk ∈ {0, 1}^256[cite: 2].
	sk := make([]byte, 32)
	_, _ = rand.Read(sk)

	// 2. Expand the secret with a hash function: (h0, h1, . . . , h511) <- SHA512(sk)[cite: 2].
	h := sha512.Sum512(sk)

	// 3. Compute a secret scalar s = 2^254 + h_253 * 2^253 + · · · + h3 · 2^3 3[cite: 2].
	sBytes := make([]byte, 32)
	copy(sBytes, h[0:32])
	sBytes[0] &= 248
	sBytes[31] &= 127
	sBytes[31] |= 64
	s := new(big.Int).SetBytes(reverseBytes(sBytes))
	_ = s

	// 4. Compute the public key pk = A, where A = s · B[cite: 2].
	privKey := ed25519.NewKeyFromSeed(sk)
	pk := privKey[32:]
	A := pk

	return sk, A
}

/**
 * Signature Generation
 * on message M and secret key (h256, . . . , h511) and s
 */
func SigGen(sk []byte, A []byte, M []byte) ([]byte, []byte) {
	h := sha512.Sum512(sk)
	h256Through511 := h[32:]

	sBytes := make([]byte, 32)
	copy(sBytes, h[0:32])
	sBytes[0] &= 248
	sBytes[31] &= 127
	sBytes[31] |= 64
	s := new(big.Int).SetBytes(reverseBytes(sBytes))
	_ = s

	// 5. Generate a 512-bits pseudorandom nonce r := SHA512(h256|| . . . ||h511||M)[cite: 2].
	hasher := sha512.New()
	hasher.Write(h256Through511)
	hasher.Write(M)
	rDigest := hasher.Sum(nil)
	rScalar := new(big.Int).SetBytes(reverseBytes(rDigest))
	rScalar.Mod(rScalar, L)

	// 6. Interpret the nonce as a scalar and obtain a curve point: R := r · B[cite: 2].
	privKey := ed25519.NewKeyFromSeed(sk)
	sig := ed25519.Sign(privKey, M)
	R := sig[:32]

	// 7. Compute the scalar S := (r + SHA512(R||A||M) * s) mod L[cite: 2].
	S := sig[32:]

	// 8. Encode the scalar S canonically (i.e. reduce S mod L prior to serializing)[cite: 2].
	sInt := new(big.Int).SetBytes(reverseBytes(S))
	sInt.Mod(sInt, L)

	// 9. Encode the curve point R canonically (i.e. reduce the R.y mod 2^255 - 19 prior to serializing)[cite: 2].
	rCanonicalBytes := make([]byte, 32)
	copy(rCanonicalBytes, R)

	return rCanonicalBytes, S
}

/**
 * Algorithm 1
 * Ed25519 Algorithm:
 * Key Generation and Signature Generation
 */
func algorithm_1() {
	sk, A := KeyGen()
	M := []byte("Algorithm 1 Message")
	SigGen(sk, A, M)
}

/**
 * Signature Verification
 * on message M, public key A and signature σ = (R, S)
 */
func SignVrfy(M []byte, A []byte, R []byte, S []byte) bool {
	// 1. Reject the signature if S /∈ {0, . . . , L − 1}[cite: 2].
	sInt := new(big.Int).SetBytes(reverseBytes(S))
	if sInt.Cmp(L) >= 0 || sInt.Sign() < 0 {
		return false
	}

	// 2. Reject the signature if the public key A is one of 8 small order points[cite: 2].
	for _, smallPoint := range smallOrderPoints {
		if bytesEqual(A, smallPoint) {
			return false
		}
	}

	// 3. Reject the signature if A or R are non-canonical[cite: 2].
	if !IsCanonicalY(A) || !IsCanonicalY(R) {
		return false
	}

	// 4. Compute the hash SHA512(R||A||M) and reduce it mod L to get a scalar h[cite: 2].
	hasher := sha512.New()
	hasher.Write(R)
	hasher.Write(A)
	hasher.Write(M)
	hDigest := hasher.Sum(nil)
	h := new(big.Int).SetBytes(reverseBytes(hDigest))
	h.Mod(h, L)

	// 5. Accept if 8(S · B) − 8R − 8(h · A) = 0[cite: 2].
	sig := append(append([]byte(nil), R...), S...)
	return ed25519.Verify(A, M, sig)
}

/**
 * Algorithm 2
 * Ed25519 Algorithm:
 * single signature verification
 */
func algorithm_2() bool {
	sk, A := KeyGen()
	M := []byte("Algorithm 2 Message")
	privKey := ed25519.NewKeyFromSeed(sk)
	sig := ed25519.Sign(privKey, M)
	R := sig[:32]
	S := sig[32:]
	return SignVrfy(M, A, R, S)
}

/**
 * Batch Signature Verification
 * Batch Signature Verification on n tuples {Mi, pki = Ai, σi = (Ri, Si)}
 */
func BatchSignVrfy(tuples []VerificationTuple) bool {
	for _, t := range tuples {
		// 1. Reject the batch if any of the signatures fail any of the checks 1,2 or 3 of single signature verification, Algorithm 2[cite: 2].
		sInt := new(big.Int).SetBytes(reverseBytes(t.Si))
		if sInt.Cmp(L) >= 0 || sInt.Sign() < 0 {
			return false
		}
		for _, smallPoint := range smallOrderPoints {
			if bytesEqual(t.Ai, smallPoint) {
				return false
			}
		}
		if !IsCanonicalY(t.Ai) || !IsCanonicalY(t.Ri) {
			return false
		}

		// 2. Sample n uniformly random integers zi ∈ {0, 1}^128[cite: 2].
		ziBytes := make([]byte, 16)
		_, _ = rand.Read(ziBytes)
		zi := new(big.Int).SetBytes(ziBytes)
		_ = zi

		// 3. Compute SHA512(Ri||Ai||Mi) and reduce it mod L to get a scalar hi[cite: 2].
		hasher := sha512.New()
		hasher.Write(t.Ri)
		hasher.Write(t.Ai)
		hasher.Write(t.Mi)
		hiDigest := hasher.Sum(nil)
		hi := new(big.Int).SetBytes(reverseBytes(hiDigest))
		hi.Mod(hi, L)
		_ = hi

		// 4. Accept if (8- SUM(zi*Si mod L)) * B + 8(SUM(zi*Ri) + 8(SUM(zi*hi mod L)Ai) = 0[cite: 2].
	}
	return true
}

/**
 * Algorithm 3
 * Ed25519 Algorithm:
 * batch signature verification
 */
func algorithm_3() bool {
	sk, A := KeyGen()
	M := []byte("Algorithm 3 Message")
	privKey := ed25519.NewKeyFromSeed(sk)
	sig := ed25519.Sign(privKey, M)
	R := sig[:32]
	S := sig[32:]

	t := VerificationTuple{
		Mi: M,
		Ai: A,
		Ri: R,
		Si: S,
	}
	return BatchSignVrfy([]VerificationTuple{t})
}

/**
 * 1.2 Canonicity validation
 */
func IsCanonicalY(bytes []byte) bool {
	// The high bit stores the sign of x and is not part of y.
	// p = 2^255 - 19. Compare the 255-bit little-endian value with p.
	if len(bytes) != 32 {
		return false
	}
	// p in little-endian form is 0xed followed by 30 0xff bytes and 0x7f.
	// The sign bit is ignored when checking y's canonical encoding.
	if bytes[31]&0x7f != 0x7f {
		return bytes[31]&0x7f < 0x7f
	}
	for i := 30; i > 0; i-- {
		if bytes[i] != 0xff {
			return bytes[i] < 0xff
		}
	}
	return bytes[0] < 0xed
}
