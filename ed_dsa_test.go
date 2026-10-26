package eddsa

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type KATVector struct {
	Message   string `json:"message"`
	PubKey    string `json:"pub_key"`
	Signature string `json:"signature"`
	Expected  bool   `json:"expected"`
}

func loadKATVectors(t *testing.T) []KATVector {
	file, err := os.ReadFile("kat.json")
	if err != nil {
		t.Fatalf("failed to read kat.json: %v", err)
	}
	var vectors []KATVector
	if err := json.Unmarshal(file, &vectors); err != nil {
		t.Fatalf("failed to parse kat.json: %v", err)
	}
	return vectors
}

func TestKATSingleSignatureVerification(t *testing.T) {
	vectors := loadKATVectors(t)
	for i, kat := range vectors {
		msgBytes, err := hexDecodeString(kat.Message)
		if err != nil {
			t.Fatalf("vector %d: failed to decode message: %v", i, err)
		}
		pubBytes, err := hexDecodeString(kat.PubKey)
		if err != nil {
			t.Fatalf("vector %d: failed to decode pubkey: %v", i, err)
		}
		sigBytes, err := hexDecodeString(kat.Signature)
		if err != nil {
			t.Fatalf("vector %d: failed to decode signature: %v", i, err)
		}
		if len(sigBytes) != 64 {
			t.Fatalf("vector %d: invalid signature length: %d", i, len(sigBytes))
		}

		R := sigBytes[:32]
		S := sigBytes[32:]

		got := SignVrfy(msgBytes, pubBytes, R, S)
		if got != kat.Expected {
			t.Errorf("vector %d: SignVrfy() = %v, expected %v", i, got, kat.Expected)
		}
	}
}

func TestKATBatchSignatureVerification(t *testing.T) {
	vectors := loadKATVectors(t)
	var batch []VerificationTuple
	for _, kat := range vectors {
		msgBytes, _ := hexDecodeString(kat.Message)
		pubBytes, _ := hexDecodeString(kat.PubKey)
		sigBytes, _ := hexDecodeString(kat.Signature)
		batch = append(batch, VerificationTuple{
			Mi: msgBytes,
			Ai: pubBytes,
			Ri: sigBytes[:32],
			Si: sigBytes[32:],
		})
	}

	got := BatchSignVrfy(batch)
	if got != false {
		t.Errorf("BatchSignVrfy() = %v, expected false for invalid test vectors batch", got)
	}
}

func TestKATValidSignature(t *testing.T) {
	sk, A := KeyGen()
	M := []byte("Valid KAT Test Message from JSON workflow")
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

func hexDecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
