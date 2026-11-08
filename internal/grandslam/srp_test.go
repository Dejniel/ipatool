package grandslam

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func unhex(t *testing.T, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestIndependentSRPVectors(t *testing.T) {
	// Independent Python vectors published by blacktop/ipsw, see THIRD_PARTY.md.
	// A=2 and B=3 detect accidentally using IDMSA's padded A/B hashes.
	for _, tc := range []struct{ protocol, derived, m1, m2, key string }{
		{"s2k", "7e45a9b84ecc792912c1eebbefb2ba11ed372d6fc501a7c2f096b1c7866a6419", "2ecc03e26a4ca980554dd328c9a6877f69623d141466708d067c294b7e3e5815", "49cfd96cec137366e34b011251766fbafe51a081655479f7ccf35ca2a4e44628", "a10b5d599ea9dbf3a8f2bc7af0ec0e0cb8d405657703077d70a9088ddbf2a05a"},
		{"s2k_fo", "50278ff04f769bcd5230ef32224212eb98224c5142a50ef78fd98372201519a0", "8851b00fb4f2a2d5dbf9fdf4abf7cbe528fd11de3b001681569d07e008a97ab2", "3edd05101984381a14f5fffde6b6fbbc0136408953d95366a8f4a1ef761e278f", "e17917f5e2258f0cd846ef0d80f35915e085528dd47a55543a23a8c2d3448962"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			salt := unhex(t, "00112233445566778899aabbccddeeff")
			derived, err := passwordKey("synthetic-password-\u0394", salt, 17, tc.protocol)
			if err != nil || !bytes.Equal(derived, unhex(t, tc.derived)) {
				t.Fatalf("password KDF mismatch: %v", err)
			}
			client, _ := srpWithSecret([]byte{1})
			proof, err := client.complete("synthetic@example.test", "synthetic-password-\u0394", salt, []byte{0, 3}, 17, tc.protocol)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(proof.m1, unhex(t, tc.m1)) || !bytes.Equal(proof.m2, unhex(t, tc.m2)) || !bytes.Equal(proof.key, unhex(t, tc.key)) {
				t.Fatal("SRP proof mismatch")
			}
		})
	}
}

func TestSRPRejectsInvalidChallenges(t *testing.T) {
	client, _ := srpWithSecret([]byte{1})
	n, _ := new(big.Int).SetString(modulusHex, 16)
	for _, server := range [][]byte{nil, {0}, n.Bytes(), bytes.Repeat([]byte{1}, 258)} {
		if _, err := client.complete("u", "p", []byte("s"), server, 1, "s2k"); err == nil {
			t.Fatal("accepted invalid B")
		}
	}
	for _, rounds := range []int{-1, 0, 1_000_001} {
		if _, err := passwordKey("p", []byte("s"), rounds, "s2k"); err == nil {
			t.Fatal("accepted invalid rounds")
		}
	}
	if _, err := passwordKey(strings.Repeat("p", 4097), []byte("s"), 1, "s2k"); err == nil {
		t.Fatal("accepted oversized password")
	}
	if _, err := passwordKey("p", []byte("s"), 1, "unknown"); err == nil {
		t.Fatal("accepted unknown protocol")
	}
	if _, err := srpWithSecret(nil); err == nil {
		t.Fatal("accepted zero secret")
	}
	if _, err := (&srpProof{m2: []byte("expected")}).decrypt([]byte("wrong"), bytes.Repeat([]byte{0}, 16)); err == nil {
		t.Fatal("accepted invalid server proof")
	}
}
