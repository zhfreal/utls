package tls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

const (
	realityMldsa65CertPaddingLen = 3309 // Sized to match ML-DSA-65 signature size
)

var realityServerCertMldsa65 = onceValues(func() (ed25519Priv ed25519.PrivateKey, signedCert []byte) {
	empty3309 := make([]byte, realityMldsa65CertPaddingLen)
	certificate := x509.Certificate{SerialNumber: &big.Int{}, ExtraExtensions: []pkix.Extension{{Id: []int{0, 0}, Value: empty3309}}}
	_, ed25519Priv, _ = ed25519.GenerateKey(rand.Reader)
	signedCert, _ = x509.CreateCertificate(rand.Reader, &certificate, &certificate, ed25519.PublicKey(ed25519Priv[ed25519.PublicKeySize:]), ed25519Priv)
	return
})
