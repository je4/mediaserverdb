package tls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"emperror.dev/errors"
	"github.com/je4/mediaserverdb/v2/pkg/cert"
	"net"
	"time"
)

func CreateServerTLSConfig(
	duration time.Duration,
	caPEM []byte,
	caPrivKeyPEM []byte,
	ips []net.IP,
	dnsNames []string,
	name *pkix.Name,
	keyType cert.KeyType) (*tls.Config, error) {
	certPEM, certPrivKeyPEM, err := cert.CreateServerCertificate(
		duration,
		caPEM,
		caPrivKeyPEM,
		ips,
		dnsNames,
		name,
		keyType)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server certificate")
	}
	serverCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server certificate")
	}
	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &serverCert, nil
		},
	}

	return serverTLSConf, nil
}

func CreateServerMTLSConfigDefault() (*tls.Config, error) {
	tlsConfig, err := CreateServerTLSConfigDefault()
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server TLS config")
	}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(cert.DefaultCACrt)
	tlsConfig.ClientCAs = caCertPool
	return tlsConfig, nil
}

func CreateServerTLSConfigDefault() (*tls.Config, error) {
	name := cert.DefaultName()
	name.CommonName = "dummyServer"
	return CreateServerTLSConfig(
		time.Hour*24*365*10,
		cert.DefaultCACrt,
		cert.DefaultCAKey,
		cert.DefaultIPAddresses(),
		cert.DefaultDNSNames(),
		name,
		cert.DefaultKeyType(),
	)
}

func CreateClientMTLSConfig(
	duration time.Duration,
	caPEM []byte,
	caPrivKeyPEM []byte,
	ips []net.IP,
	dnsNames []string,
	email string,
	uri string,
	name *pkix.Name,
	keyType cert.KeyType) (*tls.Config, error) {
	certPEM, certPrivKeyPEM, err := cert.CreateClientCertificate(
		duration,
		caPEM,
		caPrivKeyPEM,
		ips,
		dnsNames,
		email,
		uri,
		name,
		keyType)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server certificate")
	}
	clientCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server certificate")
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "cannot get system cert pool")
	}
	certPool.AppendCertsFromPEM(cert.DefaultCACrt)

	clientTLSConf := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	return clientTLSConf, nil
}

func CreateClientMTLSConfigDefault() (*tls.Config, error) {
	name := cert.DefaultName()
	name.CommonName = "dummyClient"
	return CreateClientMTLSConfig(time.Hour*24*365*10,
		cert.DefaultCACrt,
		cert.DefaultCAKey,
		cert.DefaultIPAddresses(),
		cert.DefaultDNSNames(),
		"",
		"",
		name,
		cert.DefaultKeyType(),
	)
}
