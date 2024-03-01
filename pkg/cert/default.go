package cert

import (
	"crypto/x509/pkix"
	_ "embed"
	"net"
)

//go:embed dummyCA.crt
var DefaultCACrt []byte

//go:embed dummyCA.key
var DefaultCAKey []byte

func DefaultKeyType() KeyType {
	return ECDSAP384
}

func DefaultName() *pkix.Name {
	name := &pkix.Name{
		Organization:  []string{"University of Basel"},
		Country:       []string{"CH"},
		Province:      []string{"Basel City"},
		Locality:      []string{"Basel"},
		StreetAddress: []string{"Schönbeinstrasse 18-20"},
		PostalCode:    []string{"4056"},
	}
	return name
}

func DefaultDNSNames() []string {
	return []string{"localhost"}
}

func DefaultIPAddresses() []net.IP {
	return []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
}
