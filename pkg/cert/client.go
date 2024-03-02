package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"emperror.dev/errors"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"time"
)

func CreateClientCertificate(duration time.Duration, caPEM []byte, caPrivKeyPEM []byte, ips []net.IP, dnsNames []string, email, uri []string, name *pkix.Name, keyType KeyType) (certPEM []byte, certPrivKeyPEM []byte, err error) {
	if keyType == "" {
		return nil, nil, errors.New("keyType is required")
	}
	if caPEM == nil || caPrivKeyPEM == nil {
		return nil, nil, errors.New("CA certificate and private key are required")
	}
	if name == nil {
		return nil, nil, errors.New("name is required")
	}
	if len(ips) == 0 {
		return nil, nil, errors.New("IP address is required")
	}
	if len(dnsNames) == 0 {
		return nil, nil, errors.New("DNS name is required")
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, nil, errors.New("cannot decode CA PEM")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot parse CA certificate")
	}
	caPrivKeyBlock, _ := pem.Decode(caPrivKeyPEM)
	if caPrivKeyBlock == nil {
		return nil, nil, errors.New("cannot decode CA private key PEM")
	}
	caPrivKey, err := x509.ParsePKCS8PrivateKey(caPrivKeyBlock.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot parse CA private key")
	}

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMilli()),
		Subject:      *name,
		IPAddresses:  ips,
		DNSNames:     dnsNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(duration),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if len(uri) > 0 {
		cert.URIs = make([]*url.URL, len(uri))
		for i, u := range uri {
			cert.URIs[i], err = url.Parse(u)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "cannot parse URI %s", u)
			}
		}
	}
	if len(email) > 0 {
		cert.EmailAddresses = email
	}

	certPubKey, certPrivKey, err := GenerateKey(keyType)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot generate private key")
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, certPubKey, caPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot create certificate")
	}

	certPEMBuffer := new(bytes.Buffer)
	pem.Encode(certPEMBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certPEM = certPEMBuffer.Bytes()

	certprivKeyBytes, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "cannot marshal private key")
	}
	certPrivKeyPEMBuffer := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEMBuffer, &pem.Block{
		Type:  PEMKeyType(certPrivKey),
		Bytes: certprivKeyBytes,
	})
	certPrivKeyPEM = certPrivKeyPEMBuffer.Bytes()

	return
}
