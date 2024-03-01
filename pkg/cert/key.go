package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"emperror.dev/errors"
	"log"
)

type KeyType string

const (
	ED25519   KeyType = "ed25519"
	RSA2048   KeyType = "rsa2048"
	RSA3072   KeyType = "rsa3072"
	RSA4096   KeyType = "rsa4096"
	ECDSAP224 KeyType = "ecdsaP224"
	ECDSAP256 KeyType = "ecdsaP256"
	ECDSAP384 KeyType = "ecdsaP384"
	ECDSAP521 KeyType = "ecdsaP521"
)

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func PEMKeyType(priv any) string {
	switch priv.(type) {
	case *rsa.PrivateKey:
		return "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		return "EC PRIVATE KEY"
	case ed25519.PrivateKey:
		return "PRIVATE KEY"
	default:
		return "UNKNOWN PRIVATE KEY"
	}
}

func GenerateKey(keyType KeyType) (pub any, priv any, err error) {
	switch keyType {
	case ED25519:
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
	case RSA2048:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	case ECDSAP224:
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case ECDSAP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case ECDSAP521:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		log.Fatalf("Unrecognized key type: %s", keyType)
	}
	if err != nil {
		return nil, nil, errors.Wrapf(err, "cannot generate private key for %s", keyType)
	}
	if pub == nil {
		pub = publicKey(priv)
	}
	return
}
