package eddsa

/**
 * Key Generation
 */
func KeyGen() {
	// 1. Sample uniformly random sk ∈ {0, 1}^256.
	// 2. Expand the secret with a hash function: (h0, h1, . . . , h511) <- SHA512(sk).
	// 3. Compute a secret scalar s = 2^254 + h_253 * 2^253 + · · · + h3 · 2^3 3.
	// 4. Compute the public key pk = A, where A = s · B.
}

/**
 * Signature Generation
 * on message M and secret key (h256, . . . , h511) and s
 */
func SigGen() {
	// 5. Generate a 512-bits pseudorandom nonce r := SHA512(h256|| . . . ||h511||M).
	// 6. Interpret the nonce as a scalar and obtain a curve point: R := r · B.
	// 7. Compute the scalar S := (r + SHA512(R||A||M) * s) mod L.
	// 8. Encode the scalar S canonically (i.e. reduce S mod L prior to serializing).
	// 9. Encode the curve point R canonically (i.e. reduce the R.y mod 2^255 - 19 prior to serializing).
}

/**
 * Algorithm 1
 * Ed25519 Algorithm:
 * Key Generation and Signature Generation
 */
func algorithm_1() {
	KeyGen()
	SigGen()
}

/**
 * Signature Verification
 * on message M, public key A and signature σ = (R, S)
 */
func SignVrfy() {
	// 1. Reject the signature if S /∈ {0, . . . , L − 1}.
	// 2. Reject the signature if the public key A is one of 8 small order points.
	// 3. Reject the signature if A or R are non-canonical.
	// 4. Compute the hash SHA512(R||A||M) and reduce it mod L to get a scalar h.
	// 5. Accept if 8(S · B) − 8R − 8(h · A) = 0.
}

/**
 * Algorithm 2
 * Ed25519 Algorithm:
 * single signature verification
 */
func algorithm_2() {
	SignVrfy()
}

/**
 * Batch Signature Verification
 * Batch Signature Verification on n tuples {Mi, pki = Ai, σi = (Ri, Si)}
 */
func BatchSignVrfy() {
	// 1. Reject the batch if any of the signatures fail any of the checks 1,2 or 3 of single signature verification, Algorithm 2.
	// 2. Sample n uniformly random integers zi ∈ {0, 1}^128.
	// 3. Compute SHA512(Ri||Ai||Mi) and reduce it mod L to get a scalar hi.
	// 4. Accept if (8- SUM(zi*Si mod L)) * B + 8(SUM(zi*Ri) + 8(SUM(zi*hi mod L)Ai) = 0.
}

/**
 * Algorithm 3
 * Ed25519 Algorithm:
 * batch signature verification
 */
func algorithm_3() {
	BatchSignVrfy()
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
