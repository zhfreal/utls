package tls

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

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

type realityDeadlineEvent struct {
	op   string
	zero bool
}

type realityDeadlineRecordingConn struct {
	net.Conn
	mu     sync.Mutex
	events []realityDeadlineEvent
}

func (c *realityDeadlineRecordingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.events = append(c.events, realityDeadlineEvent{op: "SetDeadline", zero: t.IsZero()})
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *realityDeadlineRecordingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.events = append(c.events, realityDeadlineEvent{op: "SetReadDeadline", zero: t.IsZero()})
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *realityDeadlineRecordingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *realityDeadlineRecordingConn) assertNoZeroClearAfterReadDeadline(t *testing.T, name string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()

	zeroSetDeadlines := 0
	sawNonZeroReadDeadline := false
	for _, ev := range c.events {
		if ev.op == "SetReadDeadline" && !ev.zero {
			sawNonZeroReadDeadline = true
		}
		if ev.op == "SetDeadline" && ev.zero {
			zeroSetDeadlines++
			if sawNonZeroReadDeadline {
				t.Fatalf("%s: SetDeadline(zero) called after SetReadDeadline(nonzero): %+v", name, c.events)
			}
		}
	}
	if zeroSetDeadlines > 1 {
		t.Fatalf("%s: expected SetDeadline(zero) at most once, got %d (%+v)", name, zeroSetDeadlines, c.events)
	}
}

func TestRealityFallbackDeadlinesClearedOnce(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		_, _ = io.Copy(io.Discard, conn)
	}()

	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen frontend: %v", err)
	}
	defer frontLn.Close()

	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var targetTrackerMu sync.Mutex
	var trackedTarget *realityDeadlineRecordingConn

	cfg := &RealityConfig{
		Type:                 "tcp",
		Dest:                 targetLn.Addr().String(),
		ServerNames:          map[string]bool{"example.com": true},
		PrivateKey:           priv,
		ShortIds:             map[[8]byte]bool{{1}: true},
		HandshakeTimeout:     2 * time.Second,
		FallbackReadDeadline: 80 * time.Millisecond,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			wrapped := &realityDeadlineRecordingConn{Conn: raw}
			targetTrackerMu.Lock()
			trackedTarget = wrapped
			targetTrackerMu.Unlock()
			return wrapped, nil
		},
	}

	serverDone := make(chan error, 1)
	var trackedUnderlying *realityDeadlineRecordingConn
	go func() {
		raw, err := frontLn.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		trackedUnderlying = &realityDeadlineRecordingConn{Conn: raw}
		_, err = RealityServer(context.Background(), trackedUnderlying, cfg)
		serverDone <- err
	}()

	client, err := net.Dial("tcp", frontLn.Addr().String())
	if err != nil {
		t.Fatalf("dial frontend: %v", err)
	}
	defer client.Close()

	// Plain HTTP triggers fallback before ServerHello; leave client write open so
	// fallback termination relies on target FIN setting FallbackReadDeadline.
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("client write: %v", err)
	}
	resp, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("expected fallback response from target")
	}

	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("RealityServer hung after fallback half-close (FallbackReadDeadline may have been cleared)")
	}
	<-targetDone

	trackedUnderlying.assertNoZeroClearAfterReadDeadline(t, "underlying")
	targetTrackerMu.Lock()
	tgt := trackedTarget
	targetTrackerMu.Unlock()
	if tgt != nil {
		tgt.assertNoZeroClearAfterReadDeadline(t, "target")
	}
}
