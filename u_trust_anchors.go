package tls

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

const (
	trustAnchorsHeaderLen       = 4 // 2 bytes extension type + 2 bytes extension length
	trustAnchorsListLenBytes    = 2 // 2 bytes list length prefix
	trustAnchorsTotalHeaderLen  = trustAnchorsHeaderLen + trustAnchorsListLenBytes // 6 bytes
	trustAnchorIDMinLen         = 1
	trustAnchorIDMaxLen         = 255
	trustAnchorsMaxExtensionLen = 65535
)

// TrustAnchorsExtension implements the draft trust_anchors ClientHello extension
// (0xca34). Each TrustAnchorID contains 1 to 255 bytes; an empty list is valid.
// The IDs are advertised to the server and do not change Config.RootCAs.
type TrustAnchorsExtension struct {
	TrustAnchorIDs [][]byte `json:"trust_anchor_ids"`
}

func (e *TrustAnchorsExtension) writeToUConn(_ *UConn) error {
	return nil
}

func (e *TrustAnchorsExtension) Len() int {
	n := trustAnchorsTotalHeaderLen
	for _, id := range e.TrustAnchorIDs {
		n += 1 + len(id)
	}
	return n
}

func (e *TrustAnchorsExtension) validate() error {
	listLen := 0
	for _, id := range e.TrustAnchorIDs {
		if len(id) < trustAnchorIDMinLen || len(id) > trustAnchorIDMaxLen {
			return fmt.Errorf("tls: trust anchor ID length %d is outside %d..%d", len(id), trustAnchorIDMinLen, trustAnchorIDMaxLen)
		}
		listLen += 1 + len(id)
		// The extension_data length also includes the two-byte list length.
		if listLen > trustAnchorsMaxExtensionLen-trustAnchorsListLenBytes {
			return fmt.Errorf("tls: trust anchors extension data exceeds %d bytes", trustAnchorsMaxExtensionLen)
		}
	}
	return nil
}

func (e *TrustAnchorsExtension) Read(b []byte) (int, error) {
	if err := e.validate(); err != nil {
		return 0, err
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	listLen := e.Len() - trustAnchorsTotalHeaderLen
	extDataLen := trustAnchorsListLenBytes + listLen
	b[0] = byte(utlsExtensionTrustAnchors >> 8)
	b[1] = byte(utlsExtensionTrustAnchors & 0xff)
	b[2] = byte(extDataLen >> 8)
	b[3] = byte(extDataLen)
	b[4] = byte(listLen >> 8)
	b[5] = byte(listLen)
	offset := trustAnchorsTotalHeaderLen
	for _, id := range e.TrustAnchorIDs {
		b[offset] = byte(len(id))
		offset++
		offset += copy(b[offset:], id)
	}
	return offset, io.EOF
}

func (e *TrustAnchorsExtension) Write(b []byte) (int, error) {
	if len(b) > trustAnchorsMaxExtensionLen {
		return 0, fmt.Errorf("tls: trust anchors extension data exceeds %d bytes", trustAnchorsMaxExtensionLen)
	}
	extData := cryptobyte.String(b)
	var list cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&list) || !extData.Empty() {
		return 0, errors.New("tls: unable to read trust anchors extension data")
	}
	ids := make([][]byte, 0)
	for !list.Empty() {
		var id cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&id) || id.Empty() {
			return 0, errors.New("tls: unable to read trust anchor ID")
		}
		ids = append(ids, append([]byte(nil), id...))
	}
	e.TrustAnchorIDs = ids
	return len(b), nil
}

func (e *TrustAnchorsExtension) UnmarshalJSON(data []byte) error {
	var value struct {
		TrustAnchorIDs [][]byte `json:"trust_anchor_ids"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	parsed := TrustAnchorsExtension{TrustAnchorIDs: value.TrustAnchorIDs}
	if err := parsed.validate(); err != nil {
		return err
	}
	e.TrustAnchorIDs = parsed.TrustAnchorIDs
	return nil
}
