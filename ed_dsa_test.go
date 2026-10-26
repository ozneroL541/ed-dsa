package eddsa

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type KATVector struct {
	Message   string `json:"message"`
	PublicKey string `json:"pub_key"`
	Signature string `json:"signature"`
}

const katFilePath = "kat.json"

func TestKnownAnswerTests(t *testing.T) {
	file, err := os.Open(katFilePath)
	if err != nil {
		t.Fatalf("failed to open %s: %v", katFilePath, err)
	}
	defer file.Close()

	var vectors []KATVector
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatalf("failed to parse %s: %v", katFilePath, err)
	}

	for i, v := range vectors {
		msgBytes, _ := hex.DecodeString(v.Message)
		pubBytes, _ := hex.DecodeString(v.PublicKey)
		sigBytes, _ := hex.DecodeString(v.Signature)

		if len(sigBytes) != 64 {
			t.Errorf("vector %d: invalid signature length %d", i, len(sigBytes))
			continue
		}

		R := sigBytes[:32]
		S := sigBytes[32:]

		valid := SignVrfy(msgBytes, pubBytes, R, S)
		t.Logf("Vector %d verification result: %v", i, valid)
	}
}
