// Copyright 2026 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
)

// TestNewOnlineFingerprintPresets verifies that all newly integrated client presets
// build valid ClientHello messages and populate appropriate cryptographic fields.
func TestNewOnlineFingerprintPresets(t *testing.T) {
	testCases := []struct {
		name       string
		id         ClientHelloID
		wantTLS13  bool
		wantAlpn   bool
		wantGrease bool
	}{
		{"Android_14_OkHttp", HelloAndroid_14_OkHttp, true, true, false},
		{"Android_15_OkHttp", HelloAndroid_15_OkHttp, true, true, false},
		{"Android_Auto", HelloAndroid_Auto, true, true, false},
		{"Brave_146", HelloBrave_146, true, true, true},
		{"Brave_Auto", HelloBrave_Auto, true, true, true},
		{"Opera_89", HelloOpera_89, true, true, true},
		{"Opera_90", HelloOpera_90, true, true, true},
		{"Opera_91", HelloOpera_91, true, true, true},
		{"Opera_Auto", HelloOpera_Auto, true, true, true},
		{"360_122", Hello360_122, true, true, true},
		{"360_Auto", Hello360_Auto, true, true, true},
		{"QQ_123", HelloQQ_123, true, true, true},
		{"QQ_Auto", HelloQQ_Auto, true, true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, tc.id)
			if err := uconn.BuildHandshakeState(); err != nil {
				t.Fatalf("failed to build handshake state for %s: %v", tc.name, err)
			}
			hello := uconn.HandshakeState.Hello
			if hello == nil {
				t.Fatalf("hello is nil for %s", tc.name)
			}
			if len(hello.CipherSuites) == 0 {
				t.Fatalf("empty cipher suites for %s", tc.name)
			}

			// Check ALPN
			hasAlpn := len(hello.AlpnProtocols) > 0
			if hasAlpn != tc.wantAlpn {
				t.Errorf("%s ALPN presence = %v, want %v", tc.name, hasAlpn, tc.wantAlpn)
			}

			// Check TLS 1.3 SupportedVersions
			hasTLS13 := false
			for _, v := range hello.SupportedVersions {
				if v == VersionTLS13 {
					hasTLS13 = true
					break
				}
			}
			if hasTLS13 != tc.wantTLS13 {
				t.Errorf("%s TLS 1.3 presence = %v, want %v", tc.name, hasTLS13, tc.wantTLS13)
			}

			// Check GREASE
			if tc.wantGrease {
				hasGreaseCipher := false
				for _, c := range hello.CipherSuites {
					if isGREASEUint16(c) {
						hasGreaseCipher = true
						break
					}
				}
				if !hasGreaseCipher {
					t.Errorf("%s expected GREASE cipher suite but found none", tc.name)
				}
			}
		})
	}
}

// TestMultiKeyShareCycling verifies that when multiple key shares are offered,
// key agreement succeeds regardless of whether the server selects the primary or secondary curve.
func TestMultiKeyShareCycling(t *testing.T) {
	spec := ClientHelloSpec{
		TLSVersMin:   VersionTLS12,
		TLSVersMax:   VersionTLS13,
		CipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
		Extensions: []TLSExtension{
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
			&KeyShareExtension{KeyShares: []KeyShare{
				{Group: X25519},
				{Group: CurveP256},
			}},
		},
	}

	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}

	state13 := uconn.HandshakeState.State13
	if state13.KeyShareKeys == nil || state13.KeyShareKeys.Keys == nil {
		t.Fatal("KeyShareKeys.Keys map was not initialized")
	}

	// Verify both keys exist in the map
	x25519Key, hasX25519 := state13.KeyShareKeys.Keys[X25519]
	p256Key, hasP256 := state13.KeyShareKeys.Keys[CurveP256]
	if !hasX25519 || x25519Key == nil {
		t.Fatal("X25519 private key missing from keys map")
	}
	if !hasP256 || p256Key == nil {
		t.Fatal("CurveP256 private key missing from keys map")
	}

	// Test 1: Key exchange with primary group (X25519)
	keX25519, err := keyExchangeForCurveID(X25519)
	if err != nil {
		t.Fatal(err)
	}
	serverX25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sharedX25519, err := keX25519.clientSharedSecret(state13.KeyShareKeys.ToPrivate(), serverX25519Key.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("clientSharedSecret failed for X25519: %v", err)
	}
	expectedX25519, err := serverX25519Key.ECDH(x25519Key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if string(sharedX25519) != string(expectedX25519) {
		t.Fatal("X25519 shared secret mismatch")
	}

	// Test 2: Key exchange with secondary group (CurveP256)
	keP256, err := keyExchangeForCurveID(CurveP256)
	if err != nil {
		t.Fatal(err)
	}
	serverP256Key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sharedP256, err := keP256.clientSharedSecret(state13.KeyShareKeys.ToPrivate(), serverP256Key.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("clientSharedSecret failed for secondary CurveP256: %v", err)
	}
	expectedP256, err := serverP256Key.ECDH(p256Key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if string(sharedP256) != string(expectedP256) {
		t.Fatal("CurveP256 shared secret mismatch")
	}
}
