// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

type opera136WireHello struct {
	Version            uint16
	RandomLength       int
	SessionIDLength    int
	CipherSuites       []uint16
	CompressionMethods []byte
	Extensions         map[uint16][]string
}

type opera136Reader struct {
	t     *testing.T
	b     []byte
	label string
}

func (r *opera136Reader) take(n int) []byte {
	r.t.Helper()
	if n < 0 || n > len(r.b) {
		r.t.Fatalf("%s: truncated field: need %d bytes, have %d", r.label, n, len(r.b))
	}
	b := r.b[:n]
	r.b = r.b[n:]
	return b
}

func (r *opera136Reader) number(n int) int {
	r.t.Helper()
	v := 0
	for _, b := range r.take(n) {
		v = v<<8 | int(b)
	}
	return v
}

func (r *opera136Reader) vector(n int) []byte {
	r.t.Helper()
	return r.take(r.number(n))
}

func (r *opera136Reader) end() {
	r.t.Helper()
	if len(r.b) != 0 {
		r.t.Fatalf("%s: %d trailing bytes", r.label, len(r.b))
	}
}

func opera136NormalizeGREASE(v uint16) uint16 {
	if isGREASEUint16(v) {
		return GREASE_PLACEHOLDER
	}
	return v
}

func opera136Uint16s(t *testing.T, b []byte) []uint16 {
	t.Helper()
	if len(b)%2 != 0 {
		t.Fatalf("odd uint16 vector length: %d", len(b))
	}
	out := make([]uint16, len(b)/2)
	for i := range out {
		out[i] = opera136NormalizeGREASE(uint16(b[2*i])<<8 | uint16(b[2*i+1]))
	}
	return out
}

func opera136NormalizeExtension(t *testing.T, id uint16, body []byte) string {
	t.Helper()
	r := opera136Reader{t, body, fmt.Sprintf("extension %#04x", id)}
	var value string
	switch id {
	case 10, 13: // supported_groups, signature_algorithms
		value = fmt.Sprint(opera136Uint16s(t, r.vector(2)))
	case 43: // supported_versions
		value = fmt.Sprint(opera136Uint16s(t, r.vector(1)))
	case 51: // key_share
		shares := opera136Reader{t, r.vector(2), "key_share entries"}
		var entries []string
		for len(shares.b) > 0 {
			group := uint16(shares.number(2))
			key := shares.vector(2)
			entry := fmt.Sprintf("%04x/%d", opera136NormalizeGREASE(group), len(key))
			if isGREASEUint16(group) {
				entry += "/" + hex.EncodeToString(key)
			}
			entries = append(entries, entry)
		}
		value = strings.Join(entries, ",")
	case 0xfe0d: // GREASE encrypted_client_hello
		outer, kdf, aead := r.number(1), r.number(2), r.number(2)
		r.take(1) // randomized config_id
		enc, payload := r.vector(2), r.vector(2)
		if outer != 0 || !slices.Contains([]int{144, 176, 208, 240}, len(payload)) {
			t.Fatalf("unexpected GREASE ECH shape: outer=%d, payload length=%d", outer, len(payload))
		}
		value = fmt.Sprintf("%d/%d/%d/enc=%d/payload=144,176,208,240", outer, kdf, aead, len(enc))
	case 0xca34: // trust_anchors
		ids := opera136Reader{t, r.vector(2), "trust anchor IDs"}
		for len(ids.b) > 0 {
			if len(ids.vector(1)) == 0 {
				t.Fatal("empty trust anchor ID in fixture")
			}
		}
		value = hex.EncodeToString(body)
	default:
		value = hex.EncodeToString(r.take(len(r.b)))
	}
	r.end()
	return value
}

func opera136ParseWire(t *testing.T, data []byte) (opera136WireHello, []uint16, map[uint16][]byte) {
	t.Helper()
	r := opera136Reader{t, data, "ClientHello"}
	if len(data) > 0 && data[0] == byte(recordTypeHandshake) {
		if r.number(1) != int(recordTypeHandshake) || r.number(2) != int(VersionTLS10) {
			t.Fatal("unexpected ClientHello TLS record header")
		}
		record := r.vector(2)
		r.end()
		r = opera136Reader{t, record, "ClientHello handshake"}
	}
	if r.number(1) != 1 {
		t.Fatal("fixture is not a ClientHello")
	}
	body := r.vector(3)
	r.end()
	r = opera136Reader{t, body, "ClientHello body"}
	version := uint16(r.number(2))
	random := r.take(32)
	sid := r.vector(1)
	ciphers := opera136Uint16s(t, r.vector(2))
	compression := bytes.Clone(r.vector(1))
	extensions := r.vector(2)
	r.end()
	out := opera136WireHello{version, len(random), len(sid), ciphers, compression, make(map[uint16][]string)}
	r = opera136Reader{t, extensions, "ClientHello extensions"}
	seen, raw := make(map[uint16]bool), make(map[uint16][]byte)
	var order []uint16
	for len(r.b) > 0 {
		id := uint16(r.number(2))
		body := r.vector(2)
		if seen[id] {
			t.Fatalf("duplicate extension %#04x", id)
		}
		seen[id] = true
		raw[id] = bytes.Clone(body)
		normalizedID := opera136NormalizeGREASE(id)
		order = append(order, normalizedID)
		out.Extensions[normalizedID] = append(out.Extensions[normalizedID], opera136NormalizeExtension(t, id, body))
	}
	for _, values := range out.Extensions {
		sort.Strings(values)
	}
	return out, order, raw
}

func opera136Fixture(t *testing.T) []byte {
	t.Helper()
	text, err := os.ReadFile("testdata/opera136_clienthello.hex")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.Join(strings.Fields(string(text)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func opera136FixtureServerName(t *testing.T, extensions map[uint16][]byte) string {
	t.Helper()
	data, ok := extensions[0]
	if !ok {
		return ""
	}
	r := opera136Reader{t, data, "server_name extension"}
	names := opera136Reader{t, r.vector(2), "server_name list"}
	r.end()
	if names.number(1) != 0 {
		t.Fatal("fixture SNI is not a host name")
	}
	name := string(names.vector(2))
	names.end()
	return name
}

func opera136Build(t *testing.T, id ClientHelloID, serverName string, spec *ClientHelloSpec) *UConn {
	t.Helper()
	client := UClient(&net.TCPConn{}, &Config{ServerName: serverName, ClientSessionCache: nil}, id)
	if spec != nil {
		if err := client.ApplyPreset(spec); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	return client
}

func opera136CompareWire(t *testing.T, want, got opera136WireHello) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("generated ClientHello differs from fresh Opera 136 capture:\n got: %+v\nwant: %+v", got, want)
	}
}

func TestOpera136CapturedClientHello(t *testing.T) {
	if HelloOpera_Auto != HelloOpera_136 {
		t.Fatalf("HelloOpera_Auto = %s, want %s", HelloOpera_Auto.Str(), HelloOpera_136.Str())
	}
	want, _, captured := opera136ParseWire(t, opera136Fixture(t))
	client := opera136Build(t, HelloOpera_136, opera136FixtureServerName(t, captured), nil)
	got, _, generated := opera136ParseWire(t, client.HandshakeState.Hello.Raw)
	opera136CompareWire(t, want, got)
	if ticket, ok := generated[35]; !ok || len(ticket) != 0 {
		t.Fatal("fresh profile must advertise an empty session_ticket extension")
	}
	if _, ok := generated[41]; ok {
		t.Fatal("fresh profile unexpectedly offers pre_shared_key")
	}
	if len(opera136TrustAnchorIDs()) != 32 {
		t.Fatalf("expected 32 trust anchors for Opera 136, got %d", len(opera136TrustAnchorIDs()))
	}
}

func TestOpera136DefaultFingerprintRoundTrip(t *testing.T) {
	fixture := opera136Fixture(t)
	want, wantOrder, raw := opera136ParseWire(t, fixture)
	spec, err := (&Fingerprinter{}).FingerprintClientHello(fixture)
	if err != nil {
		t.Fatalf("default Fingerprinter must parse captured Opera 136 ClientHello: %v", err)
	}
	client := opera136Build(t, HelloCustom, opera136FixtureServerName(t, raw), spec)
	got, gotOrder, _ := opera136ParseWire(t, client.HandshakeState.Hello.Raw)
	opera136CompareWire(t, want, got)
	if !slices.Equal(gotOrder, wantOrder) {
		t.Errorf("fingerprint roundtrip reordered extensions: got %x, want %x", gotOrder, wantOrder)
	}
}
