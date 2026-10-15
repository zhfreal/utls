package tls

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"reflect"
	"testing"
)

func TestModernBrowserAutoDefaults(t *testing.T) {
	if HelloFirefox_Auto != HelloFirefox_157 {
		t.Fatalf("HelloFirefox_Auto = %s, want %s", HelloFirefox_Auto.Str(), HelloFirefox_157.Str())
	}
	if HelloChrome_Auto != HelloChrome_155 {
		t.Fatalf("HelloChrome_Auto = %s, want %s", HelloChrome_Auto.Str(), HelloChrome_155.Str())
	}
	if HelloEdge_Auto != HelloEdge_155 {
		t.Fatalf("HelloEdge_Auto = %s, want %s", HelloEdge_Auto.Str(), HelloEdge_155.Str())
	}
	if HelloIOS_Auto != HelloIOS_26_3 {
		t.Fatalf("HelloIOS_Auto = %s, want %s", HelloIOS_Auto.Str(), HelloIOS_26_3.Str())
	}
	if HelloSafari_Auto != HelloSafari_26_3 {
		t.Fatalf("HelloSafari_Auto = %s, want %s", HelloSafari_Auto.Str(), HelloSafari_26_3.Str())
	}
}

type firefoxParsedCH struct {
	RecordVersion uint16
	ClientVersion uint16
	CipherSuites  []uint16
	Compression   []uint8
	ExtTypes      []uint16
	ExtData       map[uint16][]byte
}

func parseFirefoxCH(raw []byte) (*firefoxParsedCH, error) {
	if len(raw) < 5 || raw[0] != 0x16 {
		return nil, os.ErrInvalid
	}
	rLen := binary.BigEndian.Uint16(raw[3:5])
	hs := raw[5 : 5+rLen]
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	body := hs[4 : 4+hsLen]

	offset := 34 // skip vers + random
	sessLen := int(body[offset])
	offset += 1 + sessLen

	csLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	var ciphers []uint16
	for i := 0; i < csLen; i += 2 {
		ciphers = append(ciphers, binary.BigEndian.Uint16(body[offset+i:offset+i+2]))
	}
	offset += csLen

	compLen := int(body[offset])
	offset += 1
	comp := body[offset : offset+compLen]
	offset += compLen

	extLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	extDataSlice := body[offset : offset+extLen]

	parsed := &firefoxParsedCH{
		RecordVersion: binary.BigEndian.Uint16(raw[1:3]),
		ClientVersion: binary.BigEndian.Uint16(body[0:2]),
		CipherSuites:  ciphers,
		Compression:   comp,
		ExtData:       make(map[uint16][]byte),
	}

	eOff := 0
	for eOff+4 <= len(extDataSlice) {
		eType := binary.BigEndian.Uint16(extDataSlice[eOff : eOff+2])
		eL := int(binary.BigEndian.Uint16(extDataSlice[eOff+2 : eOff+4]))
		eOff += 4
		data := extDataSlice[eOff : eOff+eL]
		eOff += eL

		parsed.ExtTypes = append(parsed.ExtTypes, eType)
		parsed.ExtData[eType] = data
	}

	return parsed, nil
}

func TestFirefox157MatchesCapture(t *testing.T) {
	fixtureHex, err := os.ReadFile("testdata/firefox157_clienthello.hex")
	if err != nil {
		t.Fatalf("failed to read firefox157 fixture: %v", err)
	}
	fixtureRaw, err := hex.DecodeString(string(bytes.TrimSpace(fixtureHex)))
	if err != nil {
		t.Fatalf("failed to decode hex fixture: %v", err)
	}

	fixParsed, err := parseFirefoxCH(fixtureRaw)
	if err != nil {
		t.Fatalf("failed to parse fixture: %v", err)
	}

	pipeR, pipeW := net.Pipe()
	uconn := UClient(pipeW, &Config{InsecureSkipVerify: true, VerifyConnection: func(ConnectionState) error { return nil }}, HelloFirefox_157)
	go func() {
		_ = uconn.Handshake()
		pipeW.Close()
	}()
	buf := make([]byte, 4096)
	n, _ := pipeR.Read(buf)
	pipeR.Close()

	genParsed, err := parseFirefoxCH(buf[:n])
	if err != nil {
		t.Fatalf("failed to parse generated Firefox 157: %v", err)
	}

	// 1. Verify Cipher Suites match exactly
	if !reflect.DeepEqual(fixParsed.CipherSuites, genParsed.CipherSuites) {
		t.Fatalf("CipherSuites mismatch:\n  Want: %04x\n  Got:  %04x", fixParsed.CipherSuites, genParsed.CipherSuites)
	}

	// 2. Verify Extension Ordering and Types match exactly
	if !reflect.DeepEqual(fixParsed.ExtTypes, genParsed.ExtTypes) {
		t.Fatalf("ExtTypes mismatch:\n  Want: %04x\n  Got:  %04x", fixParsed.ExtTypes, genParsed.ExtTypes)
	}

	// 3. Verify Supported Curves payload matches
	if !bytes.Equal(fixParsed.ExtData[10], genParsed.ExtData[10]) {
		t.Fatalf("Supported Groups payload mismatch:\n  Want: %x\n  Got:  %x", fixParsed.ExtData[10], genParsed.ExtData[10])
	}

	// 4. Verify EC Point Formats payload matches
	if !bytes.Equal(fixParsed.ExtData[11], genParsed.ExtData[11]) {
		t.Fatalf("EC Point Formats payload mismatch:\n  Want: %x\n  Got:  %x", fixParsed.ExtData[11], genParsed.ExtData[11])
	}

	// 5. Verify ALPN payload matches
	if !bytes.Equal(fixParsed.ExtData[16], genParsed.ExtData[16]) {
		t.Fatalf("ALPN payload mismatch:\n  Want: %x\n  Got:  %x", fixParsed.ExtData[16], genParsed.ExtData[16])
	}

	// 6. Verify Delegated Credentials payload matches
	if !bytes.Equal(fixParsed.ExtData[34], genParsed.ExtData[34]) {
		t.Fatalf("Delegated Credentials payload mismatch:\n  Want: %x\n  Got:  %x", fixParsed.ExtData[34], genParsed.ExtData[34])
	}

	// 7. Verify Supported Versions payload matches
	if !bytes.Equal(fixParsed.ExtData[43], genParsed.ExtData[43]) {
		t.Fatalf("Supported Versions payload mismatch:\n  Want: %x\n  Got:  %x", fixParsed.ExtData[43], genParsed.ExtData[43])
	}

	// 8. Verify Signature Algorithms payload matches
	if !bytes.Equal(fixParsed.ExtData[13], genParsed.ExtData[13]) {
		t.Fatalf("Signature Algorithms payload mismatch:\n  Want: %x\n  Got:  %x", fixParsed.ExtData[13], genParsed.ExtData[13])
	}

	// 9. Verify PSK Key Exchange Modes payload matches
	if !bytes.Equal(fixParsed.ExtData[45], genParsed.ExtData[45]) {
		t.Fatalf("PSK Key Exchange Modes payload mismatch:\n  Want: %x\n  Got:  %x", fixParsed.ExtData[45], genParsed.ExtData[45])
	}

	// 10. Verify Record Size Limit payload matches
	if !bytes.Equal(fixParsed.ExtData[28], genParsed.ExtData[28]) {
		t.Fatalf("Record Size Limit payload mismatch:\n  Want: %x\n  Got:  %x", fixParsed.ExtData[28], genParsed.ExtData[28])
	}

	// 11. Verify Compress Certificate payload matches
	if !bytes.Equal(fixParsed.ExtData[27], genParsed.ExtData[27]) {
		t.Fatalf("Compress Certificate payload mismatch:\n  Want: %x\n  Got:  %x", fixParsed.ExtData[27], genParsed.ExtData[27])
	}

	// 12. Verify Key Share total length matches (1327 bytes)
	if len(genParsed.ExtData[51]) != 1327 {
		t.Fatalf("Key Share length mismatch: want 1327, got %d", len(genParsed.ExtData[51]))
	}
}

func TestFirefox157WithSNI(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	uconn := UClient(pipeW, &Config{ServerName: "example.com"}, HelloFirefox_157)
	go func() {
		_ = uconn.Handshake()
		pipeW.Close()
	}()
	buf := make([]byte, 4096)
	n, _ := pipeR.Read(buf)
	pipeR.Close()

	genParsed, err := parseFirefoxCH(buf[:n])
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	// First extension should be SNI (0)
	if len(genParsed.ExtTypes) == 0 || genParsed.ExtTypes[0] != 0 {
		t.Fatalf("expected first extension to be SNI (0), got %04x", genParsed.ExtTypes[0])
	}
}
