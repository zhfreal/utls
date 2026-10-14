// Copyright 2026 uTLS. Licensed under the BSD 3-Clause License.

package tls

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"testing"

	circlpki "github.com/cloudflare/circl/pki"
	circlsign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

var mldsaTestSchemes = []struct {
	name   string
	scheme circlsign.Scheme
	tls    SignatureScheme
}{
	{"ML-DSA-44", mldsa44.Scheme(), MLDSA44},
	{"ML-DSA-65", mldsa65.Scheme(), MLDSA65},
	{"ML-DSA-87", mldsa87.Scheme(), MLDSA87},
}

// TestMLDSAVerifyHandshakeSignature verifies the client accepts a valid
// server CertificateVerify signed with ML-DSA and rejects a bad one.
func TestMLDSAVerifyHandshakeSignature(t *testing.T) {
	for _, tc := range mldsaTestSchemes {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, err := tc.scheme.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			signed := []byte("TLS 1.3, server CertificateVerify transcript bytes")
			sig := tc.scheme.Sign(priv, signed, nil)

			// Low-level verify: valid signature accepted.
			if err := verifyMLDSAHandshakeSignature(pub, signed, sig); err != nil {
				t.Fatalf("verifyMLDSAHandshakeSignature(valid): %v", err)
			}

			// Full dispatch path (as called from TLS 1.3 handshake).
			if err := verifyHandshakeSignature(signatureMLDSA, pub, directSigning, signed, sig); err != nil {
				t.Fatalf("verifyHandshakeSignature(valid): %v", err)
			}

			// A wrong hash (not directSigning) must be rejected by dispatch.
			if err := verifyHandshakeSignature(signatureMLDSA, pub, 0x20, signed, sig); err == nil {
				t.Fatalf("verifyHandshakeSignature: expected error for non-direct hash")
			}

			// Tampered signature rejected.
			bad := slices.Clone(sig)
			bad[0] ^= 0xff
			if err := verifyMLDSAHandshakeSignature(pub, signed, bad); err == nil {
				t.Fatalf("verifyMLDSAHandshakeSignature(tampered): expected error")
			}

			// Tampered message rejected.
			if err := verifyMLDSAHandshakeSignature(pub, append(slices.Clone(signed), '!'), sig); err == nil {
				t.Fatalf("verifyMLDSAHandshakeSignature(wrong message): expected error")
			}
		})
	}
}

// TestMLDSAVerifyRejectsNonMLDSAKey ensures a non-ML-DSA public key is rejected.
func TestMLDSAVerifyRejectsNonMLDSAKey(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyMLDSAHandshakeSignature(edPub, []byte("x"), []byte("y")); err == nil {
		t.Fatalf("expected error for non-ML-DSA public key")
	}
}

// TestMLDSATypeAndHash checks the SignatureScheme -> (sigType, hash) mapping.
func TestMLDSATypeAndHash(t *testing.T) {
	for _, s := range []SignatureScheme{MLDSA44, MLDSA65, MLDSA87} {
		sigType, hash, err := typeAndHashFromSignatureScheme(s)
		if err != nil {
			t.Fatalf("%v: %v", s, err)
		}
		if sigType != signatureMLDSA {
			t.Fatalf("%v: sigType = %d, want signatureMLDSA(%d)", s, sigType, signatureMLDSA)
		}
		if hash != directSigning {
			t.Fatalf("%v: hash = %v, want directSigning", s, hash)
		}
	}
}

// TestMLDSAIsSignatureScheme checks the ML-DSA classification.
func TestMLDSAIsSignatureScheme(t *testing.T) {
	for _, s := range []SignatureScheme{MLDSA44, MLDSA65, MLDSA87} {
		if !isMLDSASignatureScheme(s) {
			t.Errorf("isMLDSASignatureScheme(%v) = false, want true", s)
		}
	}
	for _, s := range []SignatureScheme{Ed25519, ECDSAWithP256AndSHA256, PSSWithSHA256} {
		if isMLDSASignatureScheme(s) {
			t.Errorf("isMLDSASignatureScheme(%v) = true, want false", s)
		}
	}
}

// TestMLDSASchemeRecoveryFromSPKI validates SPKI round-trip and scheme recovery.
func TestMLDSASchemeRecoveryFromSPKI(t *testing.T) {
	for _, tc := range mldsaTestSchemes {
		t.Run(tc.name, func(t *testing.T) {
			pub, _, err := tc.scheme.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			spki, err := circlpki.MarshalPKIXPublicKey(pub)
			if err != nil {
				t.Fatalf("MarshalPKIXPublicKey: %v", err)
			}
			recovered, err := circlpki.UnmarshalPKIXPublicKey(spki)
			if err != nil {
				t.Fatalf("UnmarshalPKIXPublicKey: %v", err)
			}
			got, ok := mldsaSchemeForPublicKey(recovered)
			if !ok || got != tc.tls {
				t.Fatalf("mldsaSchemeForPublicKey = (%v, %v), want (%v, true)", got, ok, tc.tls)
			}
		})
	}
}
