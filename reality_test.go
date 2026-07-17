package tls

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestRealityValue(t *testing.T) {
	tests := []struct {
		input    []byte
		expected int
	}{
		{[]byte{26, 7, 11}, (26 << 16) | (7 << 8) | 11},
		{[]byte{25, 1, 1}, (25 << 16) | (1 << 8) | 1},
		{[]byte{0, 0, 0}, 0},
		{[]byte{255, 255, 255}, (255 << 16) | (255 << 8) | 255},
	}

	for _, tc := range tests {
		actual := realityValue(tc.input...)
		if actual != tc.expected {
			t.Errorf("realityValue(%v) = %d; want %d", tc.input, actual, tc.expected)
		}
	}
}

func TestRealityMldsa65CertSize(t *testing.T) {
	_, signedCert := realityServerCertMldsa65()

	// The certificate must be large enough to embed an ML-DSA-65 signature at offset 126.
	// ML-DSA-65 signature size is mldsa65.SignatureSize (3309 bytes).
	minRequiredLen := 126 + mldsa65.SignatureSize
	if len(signedCert) < minRequiredLen {
		t.Fatalf("signedCert length %d is too short to hold ML-DSA-65 signature at offset 126 (requires at least %d bytes)", len(signedCert), minRequiredLen)
	}
}

func TestRealitySignMldsa65(t *testing.T) {
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ML-DSA-65 key: %v", err)
	}

	_, signedCert := realityServerCertMldsa65()

	// Mocking what RealityServer does
	digest := []byte("mock-tls-transcript-hash-32bytes-long")
	if len(digest) < 32 {
		digest = append(digest, make([]byte, 32-len(digest))...)
	}

	// Sign
	mldsa65.SignTo(sk, digest, nil, false, signedCert[126:])

	// Verify
	valid := mldsa65.Verify(pk, digest, nil, signedCert[126:126+mldsa65.SignatureSize])
	if !valid {
		t.Fatalf("ML-DSA-65 signature verification failed on the mock signedCert buffer")
	}
}
