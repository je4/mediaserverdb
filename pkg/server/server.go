package server

import (
	"github.com/je4/mediaserverdb/v2/pkg/grpchelper"
	pb "github.com/je4/mediaserverdb/v2/pkg/proto"
)

func Register(registrar grpchelper.Server, server pb.DBControllerServer) {
	pb.RegisterDBControllerServer(registrar, server)
}
