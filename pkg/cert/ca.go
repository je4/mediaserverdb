package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"emperror.dev/errors"
	"encoding/pem"
	"math/big"
	"time"
)

func CreateCA(duration time.Duration, name *pkix.Name, keyType KeyType) (caPEM []byte, caPrivKeyPEM []byte, err error) {
	if keyType == "" {
		keyType = DefaultKeyType()
	}
	if name == nil {
		name = DefaultName()
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixMilli()),
		Subject:               *name,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPubKey, caPrivKey, err := GenerateKey(keyType)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "cannot generate private key")
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPubKey, caPrivKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "cannot create certificate")
	}

	// pem encode
	caPEMBuffer := new(bytes.Buffer)
	if err := pem.Encode(caPEMBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return nil, nil, errors.Wrapf(err, "cannot encode certificate")
	}
	caPEM = caPEMBuffer.Bytes()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(caPrivKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "cannot marshal private key")
	}
	caPrivKeyPEMBuffer := new(bytes.Buffer)
	if err := pem.Encode(caPrivKeyPEMBuffer, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return nil, nil, errors.Wrapf(err, "cannot encode private key")
	}
	caPrivKeyPEM = caPrivKeyPEMBuffer.Bytes()

	return
}
