package tls

import (
	"bytes"
	"testing"
)

func TestMarshal(t *testing.T) {
	t.Run("Firefox", testTransportParametersFirefox)
}

func testTransportParametersFirefox(t *testing.T) {
	if !bytes.Equal(_inputTransportParametersFirefox.Marshal(), _truthTransportParametersFirefox) {
		t.Errorf("TransportParameters.Marshal() = %v, want %v", _inputTransportParametersFirefox.Marshal(), _truthTransportParametersFirefox)
	}
}

var (
	_inputTransportParametersFirefox = TransportParameters{
		InitialMaxStreamDataBidiRemote(0x100000),
		InitialMaxStreamsBidi(16),
		MaxDatagramFrameSize(1200),
		MaxIdleTimeout(30000),
		ActiveConnectionIDLimit(8),
		&GREASEQUICBit{},
		&VersionInformation{
			ChoosenVersion: 0x00000001,
			AvailableVersions: []uint32{
				0x8acafaea,
				0x00000001,
			},
			LegacyID: true,
		},
		InitialMaxStreamsUni(16),
		&GREASETransportParameter{
			IdOverride: 0xff02de1a,
			ValueOverride: []byte{
				0x43, 0xe8,
			},
		},
		InitialMaxStreamDataBidiLocal(0xc00000),
		InitialMaxStreamDataUni(0x100000),
		InitialSourceConnectionID([]byte{0x53, 0xf0, 0xb2}),
		MaxAckDelay(20),
		InitialMaxData(0x1800000),
		&DisableActiveMigration{},
	}
	_truthTransportParametersFirefox = []byte{
		0x06, 0x04, 0x80, 0x10,
		0x00, 0x00, 0x08, 0x01,
		0x10, 0x20, 0x02, 0x44,
		0xb0, 0x01, 0x04, 0x80,
		0x00, 0x75, 0x30, 0x0e,
		0x01, 0x08, 0x6a, 0xb2,
		0x00, 0x80, 0xff, 0x73,
		0xdb, 0x0c, 0x00, 0x00,
		0x00, 0x01, 0x8a, 0xca,
		0xfa, 0xea, 0x00, 0x00,
		0x00, 0x01, 0x09, 0x01,
		0x10, 0xc0, 0x00, 0x00,
		0x00, 0xff, 0x02, 0xde,
		0x1a, 0x02, 0x43, 0xe8,
		0x05, 0x04, 0x80, 0xc0,
		0x00, 0x00, 0x07, 0x04,
		0x80, 0x10, 0x00, 0x00,
		0x0f, 0x03, 0x53, 0xf0,
		0xb2, 0x0b, 0x01, 0x14,
		0x04, 0x04, 0x81, 0x80,
		0x00, 0x00, 0x0c, 0x00,
	}
)

func TestUQUICConn_SetTransportParameters(t *testing.T) {
	runtimeParams := []byte{0x01, 0x02, 0x03, 0x04}

	// Case 1: Empty TransportParameters (e.g. from preset) receives runtime params
	{
		emptyQTP := &QUICTransportParametersExtension{}
		uconn := UClient(nil, &Config{MinVersion: VersionTLS13}, HelloCustom)
		uconn.Extensions = []TLSExtension{emptyQTP}
		qconn := newUQUICConn(uconn, &QUICConfig{TLSConfig: &Config{MinVersion: VersionTLS13}})
		qconn.SetTransportParameters(runtimeParams)

		if !bytes.Equal(emptyQTP.marshalResult, runtimeParams) {
			t.Fatalf("expected emptyQTP.marshalResult = %v, got %v", runtimeParams, emptyQTP.marshalResult)
		}
		if !bytes.Equal(uconn.quic.transportParams, runtimeParams) {
			t.Fatalf("expected quic.transportParams = %v, got %v", runtimeParams, uconn.quic.transportParams)
		}
	}

	// Case 2: Explicit TransportParameters must NOT be overwritten by runtime params
	{
		explicitQTP := &QUICTransportParametersExtension{
			TransportParameters: TransportParameters{
				MaxDatagramFrameSize(1200),
			},
		}
		uconn := UClient(nil, &Config{MinVersion: VersionTLS13}, HelloCustom)
		uconn.Extensions = []TLSExtension{explicitQTP}
		qconn := newUQUICConn(uconn, &QUICConfig{TLSConfig: &Config{MinVersion: VersionTLS13}})
		qconn.SetTransportParameters(runtimeParams)

		if len(explicitQTP.marshalResult) != 0 {
			t.Fatalf("expected explicitQTP.marshalResult to remain empty, got %v", explicitQTP.marshalResult)
		}
		if !bytes.Equal(uconn.quic.transportParams, runtimeParams) {
			t.Fatalf("expected quic.transportParams = %v, got %v", runtimeParams, uconn.quic.transportParams)
		}
	}

	// Case 3: writeToUConn propagates quic.transportParams on ApplyConfig if empty
	{
		emptyQTP := &QUICTransportParametersExtension{}
		uconn := UClient(nil, &Config{MinVersion: VersionTLS13}, HelloCustom)
		uconn.quic = &quicState{transportParams: append([]byte{}, runtimeParams...)}
		uconn.Extensions = []TLSExtension{emptyQTP}
		if err := uconn.ApplyConfig(); err != nil {
			t.Fatalf("ApplyConfig failed: %v", err)
		}
		if !bytes.Equal(emptyQTP.marshalResult, runtimeParams) {
			t.Fatalf("expected emptyQTP.marshalResult = %v, got %v", runtimeParams, emptyQTP.marshalResult)
		}

		// Ensure mutating uconn.quic.transportParams does not mutate marshalResult (anti-aliasing)
		uconn.quic.transportParams[0] = 0xee
		if !bytes.Equal(emptyQTP.marshalResult, runtimeParams) {
			t.Fatalf("expected emptyQTP.marshalResult to be cloned, got %v", emptyQTP.marshalResult)
		}
	}
}
