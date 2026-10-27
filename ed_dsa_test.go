package eddsa

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

/**
 * RFC 8032 Test Vector Structure
 */
type RFC8032TestVector struct {
	Name      string `json:"name"`
	Algorithm string `json:"algothm"`
	SecretKey string `json:"sectret_key"`
	PublicKey string `json:"pub_key"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

/**
 * JSON file containing KATs
 * RFC 8032
 * link: https://www.rfc-editor.org/info/rfc8032/#section-7
 */
const kat2FilePath = "kat.json"

func TestRFC8032CustomImplementation(t *testing.T) {
	file, err := os.Open(kat2FilePath)
	if err != nil {
		t.Fatalf("failed to open %s: %v", kat2FilePath, err)
	}
	defer file.Close()

	var vectors []RFC8032TestVector
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatalf("failed to parse %s: %v", kat2FilePath, err)
	}

	for _, v := range vectors {
		if v.Algorithm != "Ed25519" {
			t.Logf("Skipping test vector %s: unsupported algorithm %s", v.Name, v.Algorithm)
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			expectedPub, _ := hex.DecodeString(v.PublicKey)
			msgBytes, _ := hex.DecodeString(v.Message)
			sigBytes, _ := hex.DecodeString(v.Signature)
			// Extract R and S from the signature
			R := sigBytes[:32]
			S := sigBytes[32:]
			// 3. Test verification
			valid := SignVrfy(msgBytes, expectedPub, R, S)
			if !valid {
				t.Errorf("%s failed custom SignVrfy validation", v.Name)
			}
		})
	}
}
