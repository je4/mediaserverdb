package client

import (
	"emperror.dev/errors"
	pb "github.com/je4/mediaserverdb/v2/pkg/proto"
	"google.golang.org/grpc"
	"io"
)

func CreateClient(serverAddr string, opts ...grpc.DialOption) (pb.DBControllerClient, io.Closer, error) {
	conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "cannot connect to %s", serverAddr)
	}

	client := pb.NewDBControllerClient(conn)
	return client, conn, nil
}
