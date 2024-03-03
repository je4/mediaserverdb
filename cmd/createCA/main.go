package main

import (
	"github.com/je4/mediaserverdb/v2/pkg/cert"
	"os"
	"time"
)

func main() {
	name := cert.DefaultName
	name.CommonName = "DummyCA"
	ca, caPrivKey, err := cert.CreateCA(time.Hour*24*365*10, name, cert.DefaultKeyType)
	if err != nil {
		panic(err)
	}
	os.WriteFile("ca.crt", ca, 0644)
	os.WriteFile("ca.key", caPrivKey, 0644)
}
