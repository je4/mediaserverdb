package tls

import (
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"github.com/je4/mediaserverdb/v2/pkg/cert"
	"time"
)

func CreateServerTLSConfig(serverCert tls.Certificate) (*tls.Config, error) {
	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &serverCert, nil
		},
	}

	return serverTLSConf, nil
}

func CreateServerMTLSConfig(cert tls.Certificate) (*tls.Config, error) {
	tlsConfig, err := CreateServerTLSConfig(cert)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	tlsConfig.VerifyPeerCertificate = func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) < 1 {
			return errors.New("no verified chains")
		}
		if len(verifiedChains[0]) < 1 {
			return errors.New("no verified chain 0")
		}
		c := verifiedChains[0][0]
		if err := c.VerifyHostname("localhost"); err != nil {
			return errors.Wrap(err, "cannot verify hostname")
		}
		return nil
	}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	return tlsConfig, nil
}
func CreateServerMTLSConfigDefault() (*tls.Config, error) {
	name := cert.DefaultName()
	name.CommonName = "dummyServer"
	certPEM, certPrivKeyPEM, err := cert.CreateServerCertificate(
		time.Hour*24*365*10,
		cert.DefaultCACrt,
		cert.DefaultCAKey,
		cert.DefaultIPAddresses(),
		cert.DefaultDNSNames(),
		name,
		cert.DefaultKeyType(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server certificate")
	}
	serverCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server certificate")
	}
	tlsConfig, err := CreateServerMTLSConfig(serverCert)
	if err != nil {
		return nil, errors.WithStack(err)
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
	certPEM, certPrivKeyPEM, err := cert.CreateServerCertificate(
		time.Hour*24*365*10,
		cert.DefaultCACrt,
		cert.DefaultCAKey,
		cert.DefaultIPAddresses(),
		cert.DefaultDNSNames(),
		name,
		cert.DefaultKeyType(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server certificate")
	}
	serverCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create server certificate")
	}
	return CreateServerTLSConfig(serverCert)
}

func CreateClientMTLSConfig(clientCert tls.Certificate) (*tls.Config, error) {
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
	certPEM, certPrivKeyPEM, err := cert.CreateClientCertificate(
		time.Hour*24*365*10,
		cert.DefaultCACrt,
		cert.DefaultCAKey,
		cert.DefaultIPAddresses(),
		cert.DefaultDNSNames(),
		"",
		"",
		name,
		cert.DefaultKeyType(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create client certificate")
	}
	clientCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create client certificate")
	}
	return CreateClientMTLSConfig(clientCert)
}
