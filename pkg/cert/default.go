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

var DefaultKeyType KeyType = ECDSAP384

var DefaultName = &pkix.Name{
	Organization:  []string{"University Library Basel"},
	Country:       []string{"CH"},
	Province:      []string{"Basel City"},
	Locality:      []string{"Basel"},
	StreetAddress: []string{"Schönbeinstrasse 18-20"},
	PostalCode:    []string{"4056"},
}

var DefaultDNSNames = []string{"localhost"}

var DefaultIPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
