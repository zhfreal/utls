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
		{[]byte{26, 7}, (26 << 16) | (7 << 8)},
		{[]byte{26}, 26 << 16},
		{nil, 0},
		{[]byte{}, 0},
		{[]byte{26, 7, 11, 99}, (26 << 16) | (7 << 8) | 11}, // truncated to 3 bytes
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

	_, rawCert := realityServerCertMldsa65()
	signedCert := append([]byte(nil), rawCert...)

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

func TestRealityFallbackReadDeadlineConstant(t *testing.T) {
	if realityFallbackReadDeadline <= 0 {
		t.Fatalf("expected positive realityFallbackReadDeadline, got %v", realityFallbackReadDeadline)
	}
}

func TestRealityS2CBufPoolPreservesCapacity(t *testing.T) {
	bufPtr := realityS2CBufPool.Get().(*[]byte)
	if cap(*bufPtr) < int(realitySize) {
		t.Fatalf("expected initial capacity >= %d, got %d", realitySize, cap(*bufPtr))
	}
	s2cSaved := (*bufPtr)[:0]
	s2cSaved = append(s2cSaved, make([]byte, 2048)...)
	s2cSaved = s2cSaved[1200:]
	s2cSaved = s2cSaved[848:]
	realityS2CBufPool.Put(bufPtr)

	bufPtr2 := realityS2CBufPool.Get().(*[]byte)
	defer realityS2CBufPool.Put(bufPtr2)
	if cap(*bufPtr2) < int(realitySize) {
		t.Fatalf("pooled buffer lost capacity after reslicing: got %d, want >= %d", cap(*bufPtr2), realitySize)
	}
}

func TestRealityReleaseHandshakeBuffers(t *testing.T) {
	c := &Conn{}
	c.hand.Write(make([]byte, 4096))
	c.rawInput.Write(make([]byte, 4096))
	c.out.handshakeBuf = make([]byte, 1024)

	c.releaseHandshakeBuffers(false)
	if c.hand.Cap() == 0 || c.rawInput.Cap() == 0 {
		t.Fatal("expected non-empty buffers to be retained when force=false")
	}

	c.releaseHandshakeBuffers(true)
	if c.hand.Cap() != 0 || c.rawInput.Cap() != 0 || c.out.handshakeBuf != nil {
		t.Fatal("expected all handshake buffers to be freed when force=true")
	}
}
