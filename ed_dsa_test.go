package eddsa

import (
	"encoding/hex"
	"testing"
)

type KATVector struct {
	Name      string
	Message   string
	PubKey    string
	Signature string
	Expected  bool // expected result for SignVrfy
}

// Test vectors from Appendix C / Table 6c of the paper ("Taming the many EdDSAs")
// exercising small-order, non-canonical scalar, and non-canonical point conditions.
var katVectors = []KATVector{
	{
		Name:      "Paper Vector 0: Small order A and small order R",
		Message:   "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
		PubKey:    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		Signature: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
		Expected:  false, // Rejected because A is a small order point (Rule 2 for SBS security)
	},
	{
		Name:      "Paper Vector 1: Small order A and mixed order R",
		Message:   "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230614861d861de092e79",
		PubKey:    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		Signature: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
		Expected:  false, // Rejected because A is a small order point (Rule 2 for SBS security)
	},
	{
		Name:      "Paper Vector 6: Non-canonical S (S > L)",
		Message:   "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
		PubKey:    "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
		Signature: "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723606686540911a9a6a58921d6925e434ab10aa7940551809",
		Expected:  false, // Rejected because S >= L (Rule 1 for SUF-CMA security)
	},
	{
		Name:      "Paper Vector 7: Non-canonical S (S >> L)",
		Message:   "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
		PubKey:    "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
		Signature: "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
		Expected:  false, // Rejected because S >= L
	},
	{
		Name:      "Paper Vector 8: Non-canonical R",
		Message:   "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
		PubKey:    "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
		Signature: "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e54717690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
		Expected:  false, // Rejected because R is non-canonical (Rule 3)
	},
	{
		Name:      "Paper Vector 10: Non-canonical A",
		Message:   "9bedc2674237254473888631ebf45988bad3db83851ee85c85e241a07d148b41",
		PubKey:    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		Signature: "03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0ff7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
		Expected:  false, // Rejected because A is non-canonical (Rule 3)
	},
}

// TestKATSingleSignatureVerification performs KAT on single signature verification.
func TestKATSingleSignatureVerification(t *testing.T) {
	for _, kat := range katVectors {
		t.Run(kat.Name, func(t *testing.T) {
			msgBytes, err := hex.DecodeString(kat.Message)
			if err != nil {
				t.Fatalf("failed to decode message hex: %v", err)
			}
			pubBytes, err := hex.DecodeString(kat.PubKey)
			if err != nil {
				t.Fatalf("failed to decode pubkey hex: %v", err)
			}
			sigBytes, err := hex.DecodeString(kat.Signature)
			if err != nil {
				t.Fatalf("failed to decode signature hex: %v", err)
			}
			if len(sigBytes) != 64 {
				t.Fatalf("invalid signature length: %d", len(sigBytes))
			}

			R := sigBytes[:32]
			S := sigBytes[32:]

			got := SignVrfy(msgBytes, pubBytes, R, S)
			if got != kat.Expected {
				t.Errorf("SignVrfy() = %v, expected %v", got, kat.Expected)
			}
		})
	}
}

// TestKATBatchSignatureVerification performs KAT on batch signature verification.
func TestKATBatchSignatureVerification(t *testing.T) {
	var batch []VerificationTuple
	for _, kat := range katVectors {
		msgBytes, _ := hex.DecodeString(kat.Message)
		pubBytes, _ := hex.DecodeString(kat.PubKey)
		sigBytes, _ := hex.DecodeString(kat.Signature)
		batch = append(batch, VerificationTuple{
			Mi: msgBytes,
			Ai: pubBytes,
			Ri: sigBytes[:32],
			Si: sigBytes[32:],
		})
	}

	// Since all KAT vectors are invalid/malformed according to the paper rules,
	// the batch MUST be rejected.
	got := BatchSignVrfy(batch)
	if got != false {
		t.Errorf("BatchSignVrfy() = %v, expected false for invalid batch", got)
	}
}

// TestKATValidSignature verifies that a valid generated signature passes single and batch verification.
func TestKATValidSignature(t *testing.T) {
	sk, A := KeyGen()
	M := []byte("Valid KAT Test Message")
	R, S := SigGen(sk, A, M)

	if !SignVrfy(M, A, R, S) {
		t.Errorf("SignVrfy failed on valid generated signature")
	}

	tuple := VerificationTuple{
		Mi: M,
		Ai: A,
		Ri: R,
		Si: S,
	}
	if !BatchSignVrfy([]VerificationTuple{tuple}) {
		t.Errorf("BatchSignVrfy failed on valid generated signature batch")
	}
}
