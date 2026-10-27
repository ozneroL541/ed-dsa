package eddsa

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

/**
 * Known Answer Tests (KATs) Vector Structure
 */
type KATVector struct {
	Message   string `json:"message"`   /** Message in hex format */
	PublicKey string `json:"pub_key"`   /** Public key in hex format */
	Signature string `json:"signature"` /** Signature in hex format */
}

/**
 * JSON file containing KATs from
 * DOI: 10.1007/978-3-030-64357-7_4
 * Paper 2020/1244
 * Taming the many EdDSAs
 * Konstantinos Chalkias, François Garillot, and Valeria Nikolaenko
 */
const katFilePath = "kat.json"

func TestKnownAnswerTests(t *testing.T) {
	file, err := os.Open(katFilePath)
	if err != nil {
		t.Fatalf("failed to open %s: %v", katFilePath, err)
	}
	defer file.Close()
	/* List of KAT vectors */
	var vectors []KATVector
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatalf("failed to parse %s: %v", katFilePath, err)
	}
	/* For each KAT vector, verify the signature */
	for i, v := range vectors {
		/* Decode hex strings to byte slices */
		msgBytes, _ := hex.DecodeString(v.Message)
		pubBytes, _ := hex.DecodeString(v.PublicKey)
		sigBytes, _ := hex.DecodeString(v.Signature)
		/* Check signature length */
		if len(sigBytes) != 64 {
			t.Errorf("vector %d: invalid signature length %d", i, len(sigBytes))
			continue
		}
		/* Split signature into R and S components */
		R := sigBytes[:32]
		S := sigBytes[32:]
		/* Verify the signature */
		valid := SignVrfy(msgBytes, pubBytes, R, S)
		t.Logf("Vector %d verification result: %v", i, valid)
	}
}
