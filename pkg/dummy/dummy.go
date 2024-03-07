package dummy

import (
	"context"
	"github.com/je4/mediaserverdb/v2/pkg/proto"
	"github.com/je4/utils/v2/pkg/zLogger"
)

func NewDummy(logger zLogger.ZLogger) *Dummy {
	return &Dummy{
		logger: logger,
	}
}

type Dummy struct {
	proto.UnimplementedDBControllerServer
	logger zLogger.ZLogger
}

func (d *Dummy) CreateItem(ctx context.Context, item *proto.NewItem) (*proto.DefaultResponse, error) {
	return &proto.DefaultResponse{
		Status:  proto.ResultStatus_OK,
		Message: "all fine",
		Data:    nil,
	}, nil
}

var _ proto.DBControllerServer = (*Dummy)(nil)
