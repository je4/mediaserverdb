package dummy

import (
	"context"
	"crypto/x509"
	"github.com/je4/mediaserverdb/v2/pkg/client"
	pb "github.com/je4/mediaserverdb/v2/pkg/proto"
	"github.com/je4/trustutil/v2/pkg/certutil"
	"github.com/je4/trustutil/v2/pkg/grpchelper"
	"github.com/je4/trustutil/v2/pkg/tlsutil"
	"github.com/rs/zerolog"
	"testing"
	"time"
)

func TestServer(t *testing.T) {
	serverTLSConfig, err := tlsutil.CreateServerTLSConfigDefault(true, nil)
	if err != nil {
		t.Fatalf("cannot create tls config: %v", err)
	}
	serverCertChan, err := tlsutil.UpgradeTLSConfigServerExchanger(serverTLSConfig)
	if err != nil {
		t.Fatalf("cannot upgrade tls config: %v", err)
	}
	_ = serverCertChan

	serverTLSConfig.ClientCAs = x509.NewCertPool()
	if !serverTLSConfig.ClientCAs.AppendCertsFromPEM(certutil.DefaultCACrt) {
		t.Fatalf("cannot append ca cert")
	}
	logger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
	srv, err := grpchelper.NewServer("localhost:12345", serverTLSConfig, &logger)
	if err != nil {
		t.Fatalf("cannot create server: %v", err)
	}
	pb.RegisterDBControllerServer(srv, NewDummy(&logger))
	srv.Startup()
	defer srv.Shutdown()

	time.Sleep(1 * time.Second)

	clientTLSConfig, err := tlsutil.CreateClientMTLSConfigDefault([]string{"grpc:DBController"})
	if err != nil {
		t.Fatalf("cannot create tls config: %v", err)
	}
	clientTLSConfig.RootCAs = x509.NewCertPool()
	if !clientTLSConfig.RootCAs.AppendCertsFromPEM(certutil.DefaultCACrt) {
		t.Fatalf("cannot append ca cert")
	}
	c, closer, err := client.CreateClient("localhost:12345", clientTLSConfig)
	if err != nil {
		t.Fatalf("cannot create client: %v", err)
	}
	defer closer.Close()
	item := &pb.NewItem{
		Identifier: &pb.ItemIdentifier{
			Collection: "test",
			Signature:  "test",
		},
		Urn:           "test:test",
		Public:        false,
		Parent:        nil,
		PublicActions: nil,
	}
	resp, err := c.CreateItem(context.Background(), item)
	if err != nil {
		t.Fatalf("cannot create item: %v", err)
	}
	t.Logf("response: %v", resp)

	client2, closer2, err := client.CreateClient("localhost:12345", nil)
	if err != nil {
		t.Fatalf("cannot create client: %v", err)
	}
	defer closer2.Close()
	resp2, err := client2.CreateItem(context.Background(), item)
	if err != nil {
		t.Logf("cannot create item: %v", err)
	} else {
		t.Fatalf("unexpected response: %v", resp2)
	}

	resp, err = c.CreateItem(context.Background(), item)
	if err != nil {
		t.Fatalf("cannot create item: %v", err)
	}
	t.Logf("response: %v", resp)
}