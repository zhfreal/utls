package tls

import (
	"io"
	"net"
	"strings"
	"testing"
)

func TestDecompressCertBoundsAndZstdLimits(t *testing.T) {
	newClient := func() (*clientHandshakeStateTLS13, func()) {
		client, peer := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(io.Discard, peer)
		}()
		c := &Conn{conn: client, config: &Config{}}
		hs := &clientHandshakeStateTLS13{
			c: c,
			uconn: &UConn{
				certCompressionAlgs: []CertCompressionAlgo{
					CertCompressionZlib,
					CertCompressionBrotli,
					CertCompressionZstd,
				},
			},
		}
		cleanup := func() {
			_ = client.Close()
			_ = peer.Close()
			<-done
		}
		return hs, cleanup
	}

	t.Run("zero uncompressed length rejected", func(t *testing.T) {
		hs, cleanup := newClient()
		defer cleanup()

		_, err := hs.decompressCert(utlsCompressedCertificateMsg{
			algorithm:                    uint16(CertCompressionZstd),
			uncompressedLength:           0,
			compressedCertificateMessage: []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x01, 0x00, 0x00},
		})
		if err == nil || !strings.Contains(err.Error(), "invalid uncompressed certificate length") {
			t.Fatalf("expected invalid uncompressed certificate length error, got %v", err)
		}
	})

	t.Run("oversized uncompressed length rejected before allocation", func(t *testing.T) {
		hs, cleanup := newClient()
		defer cleanup()

		for _, length := range []uint32{maxHandshakeCertificateMsg + 1, 0xFFFFFF} {
			_, err := hs.decompressCert(utlsCompressedCertificateMsg{
				algorithm:                    uint16(CertCompressionZstd),
				uncompressedLength:           length,
				compressedCertificateMessage: []byte{0x01},
			})
			if err == nil || !strings.Contains(err.Error(), "invalid uncompressed certificate length") {
				t.Fatalf("length=%d: expected invalid uncompressed certificate length error, got %v", length, err)
			}
		}
	})

	t.Run("zstd huge window descriptor rejected", func(t *testing.T) {
		hs, cleanup := newClient()
		defer cleanup()

		// Zstd frame header: magic 0xFD2FB528, FHD=0x00, Window_Descriptor=0x98 (512 MiB window).
		hugeWindowFrame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x98, 0x00, 0x00, 0x00}
		_, err := hs.decompressCert(utlsCompressedCertificateMsg{
			algorithm:                    uint16(CertCompressionZstd),
			uncompressedLength:           64,
			compressedCertificateMessage: hugeWindowFrame,
		})
		if err == nil {
			t.Fatal("expected zstd frame with 512 MiB window descriptor to fail")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "window") {
			t.Fatalf("expected window size error, got %v", err)
		}
	})
}
