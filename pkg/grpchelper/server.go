package grpchelper

import (
	"context"
	"emperror.dev/errors"
	pb "github.com/je4/mediaserverdb/v2/pkg/proto"
	"google.golang.org/grpc"
	"net"
)

func NewServer(addr string, srv pb.DBControllerServer, opts ...grpc.ServerOption) (*Server, error) {
	listenConfig := &net.ListenConfig{
		Control:   nil,
		KeepAlive: 0,
	}
	lis, err := listenConfig.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot listen on %s", addr)
	}
	grpcServer := grpc.NewServer(opts...)
	server := &Server{
		Server:   grpcServer,
		listener: lis,
	}
	return server, nil
}

type Server struct {
	*grpc.Server
	listener net.Listener
}

func (s *Server) Startup() error {
	return s.Server.Serve(s.listener)
}

func (s *Server) Shutdown() error {
	s.Server.GracefulStop()
	return errors.Wrap(s.listener.Close(), "cannot close listener")
}
