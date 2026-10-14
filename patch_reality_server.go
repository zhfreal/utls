package tls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

var realityServerCertMldsa65 = onceValues(func() (ed25519Priv ed25519.PrivateKey, signedCert []byte) {
	empty3309 := make([]byte, 3309)
	certificate := x509.Certificate{SerialNumber: &big.Int{}, ExtraExtensions: []pkix.Extension{{Id: []int{0, 0}, Value: empty3309}}}
	_, ed25519Priv, _ = ed25519.GenerateKey(rand.Reader)
	signedCert, _ = x509.CreateCertificate(rand.Reader, &certificate, &certificate, ed25519.PublicKey(ed25519Priv[32:]), ed25519Priv)
	return
})
