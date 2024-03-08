package dummy

import (
	"context"
	"github.com/je4/mediaserverdb/v2/pkg/mediaserverdbproto"
	"github.com/je4/utils/v2/pkg/zLogger"
)

func NewDummy(logger zLogger.ZLogger) *Dummy {
	return &Dummy{
		logger: logger,
	}
}

type Dummy struct {
	mediaserverdbproto.UnimplementedDBControllerServer
	logger zLogger.ZLogger
}

func (d *Dummy) CreateItem(ctx context.Context, item *mediaserverdbproto.NewItem) (*mediaserverdbproto.DefaultResponse, error) {
	return &mediaserverdbproto.DefaultResponse{
		Status:  mediaserverdbproto.ResultStatus_OK,
		Message: "all fine",
		Data:    nil,
	}, nil
}

var _ mediaserverdbproto.DBControllerServer = (*Dummy)(nil)
