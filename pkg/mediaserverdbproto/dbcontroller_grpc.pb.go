// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.25.3
// source: dbcontroller.proto

package mediaserverdbproto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	DBController_Ping_FullMethodName          = "/mediaserverdbproto.DBController/Ping"
	DBController_GetItem_FullMethodName       = "/mediaserverdbproto.DBController/GetItem"
	DBController_GetStorage_FullMethodName    = "/mediaserverdbproto.DBController/GetStorage"
	DBController_GetCollection_FullMethodName = "/mediaserverdbproto.DBController/GetCollection"
	DBController_CreateItem_FullMethodName    = "/mediaserverdbproto.DBController/CreateItem"
	DBController_DeleteItem_FullMethodName    = "/mediaserverdbproto.DBController/DeleteItem"
	DBController_GetIngestItem_FullMethodName = "/mediaserverdbproto.DBController/GetIngestItem"
	DBController_ExistsItem_FullMethodName    = "/mediaserverdbproto.DBController/ExistsItem"
)

// DBControllerClient is the client API for DBController service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type DBControllerClient interface {
	Ping(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*DefaultResponse, error)
	GetItem(ctx context.Context, in *ItemIdentifier, opts ...grpc.CallOption) (*Item, error)
	GetStorage(ctx context.Context, in *StorageIdentifier, opts ...grpc.CallOption) (*Storage, error)
	GetCollection(ctx context.Context, in *CollectionIdentifier, opts ...grpc.CallOption) (*Collection, error)
	CreateItem(ctx context.Context, in *NewItem, opts ...grpc.CallOption) (*DefaultResponse, error)
	DeleteItem(ctx context.Context, in *ItemIdentifier, opts ...grpc.CallOption) (*DefaultResponse, error)
	GetIngestItem(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*IngestItem, error)
	ExistsItem(ctx context.Context, in *ItemIdentifier, opts ...grpc.CallOption) (*DefaultResponse, error)
}

type dBControllerClient struct {
	cc grpc.ClientConnInterface
}

func NewDBControllerClient(cc grpc.ClientConnInterface) DBControllerClient {
	return &dBControllerClient{cc}
}

func (c *dBControllerClient) Ping(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*DefaultResponse, error) {
	out := new(DefaultResponse)
	err := c.cc.Invoke(ctx, DBController_Ping_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *dBControllerClient) GetItem(ctx context.Context, in *ItemIdentifier, opts ...grpc.CallOption) (*Item, error) {
	out := new(Item)
	err := c.cc.Invoke(ctx, DBController_GetItem_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *dBControllerClient) GetStorage(ctx context.Context, in *StorageIdentifier, opts ...grpc.CallOption) (*Storage, error) {
	out := new(Storage)
	err := c.cc.Invoke(ctx, DBController_GetStorage_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *dBControllerClient) GetCollection(ctx context.Context, in *CollectionIdentifier, opts ...grpc.CallOption) (*Collection, error) {
	out := new(Collection)
	err := c.cc.Invoke(ctx, DBController_GetCollection_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *dBControllerClient) CreateItem(ctx context.Context, in *NewItem, opts ...grpc.CallOption) (*DefaultResponse, error) {
	out := new(DefaultResponse)
	err := c.cc.Invoke(ctx, DBController_CreateItem_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *dBControllerClient) DeleteItem(ctx context.Context, in *ItemIdentifier, opts ...grpc.CallOption) (*DefaultResponse, error) {
	out := new(DefaultResponse)
	err := c.cc.Invoke(ctx, DBController_DeleteItem_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *dBControllerClient) GetIngestItem(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*IngestItem, error) {
	out := new(IngestItem)
	err := c.cc.Invoke(ctx, DBController_GetIngestItem_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *dBControllerClient) ExistsItem(ctx context.Context, in *ItemIdentifier, opts ...grpc.CallOption) (*DefaultResponse, error) {
	out := new(DefaultResponse)
	err := c.cc.Invoke(ctx, DBController_ExistsItem_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DBControllerServer is the server API for DBController service.
// All implementations must embed UnimplementedDBControllerServer
// for forward compatibility
type DBControllerServer interface {
	Ping(context.Context, *emptypb.Empty) (*DefaultResponse, error)
	GetItem(context.Context, *ItemIdentifier) (*Item, error)
	GetStorage(context.Context, *StorageIdentifier) (*Storage, error)
	GetCollection(context.Context, *CollectionIdentifier) (*Collection, error)
	CreateItem(context.Context, *NewItem) (*DefaultResponse, error)
	DeleteItem(context.Context, *ItemIdentifier) (*DefaultResponse, error)
	GetIngestItem(context.Context, *emptypb.Empty) (*IngestItem, error)
	ExistsItem(context.Context, *ItemIdentifier) (*DefaultResponse, error)
	mustEmbedUnimplementedDBControllerServer()
}

// UnimplementedDBControllerServer must be embedded to have forward compatible implementations.
type UnimplementedDBControllerServer struct {
}

func (UnimplementedDBControllerServer) Ping(context.Context, *emptypb.Empty) (*DefaultResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Ping not implemented")
}
func (UnimplementedDBControllerServer) GetItem(context.Context, *ItemIdentifier) (*Item, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetItem not implemented")
}
func (UnimplementedDBControllerServer) GetStorage(context.Context, *StorageIdentifier) (*Storage, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStorage not implemented")
}
func (UnimplementedDBControllerServer) GetCollection(context.Context, *CollectionIdentifier) (*Collection, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCollection not implemented")
}
func (UnimplementedDBControllerServer) CreateItem(context.Context, *NewItem) (*DefaultResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateItem not implemented")
}
func (UnimplementedDBControllerServer) DeleteItem(context.Context, *ItemIdentifier) (*DefaultResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteItem not implemented")
}
func (UnimplementedDBControllerServer) GetIngestItem(context.Context, *emptypb.Empty) (*IngestItem, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetIngestItem not implemented")
}
func (UnimplementedDBControllerServer) ExistsItem(context.Context, *ItemIdentifier) (*DefaultResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ExistsItem not implemented")
}
func (UnimplementedDBControllerServer) mustEmbedUnimplementedDBControllerServer() {}

// UnsafeDBControllerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to DBControllerServer will
// result in compilation errors.
type UnsafeDBControllerServer interface {
	mustEmbedUnimplementedDBControllerServer()
}

func RegisterDBControllerServer(s grpc.ServiceRegistrar, srv DBControllerServer) {
	s.RegisterService(&DBController_ServiceDesc, srv)
}

func _DBController_Ping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DBControllerServer).Ping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DBController_Ping_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DBControllerServer).Ping(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _DBController_GetItem_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ItemIdentifier)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DBControllerServer).GetItem(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DBController_GetItem_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DBControllerServer).GetItem(ctx, req.(*ItemIdentifier))
	}
	return interceptor(ctx, in, info, handler)
}

func _DBController_GetStorage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StorageIdentifier)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DBControllerServer).GetStorage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DBController_GetStorage_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DBControllerServer).GetStorage(ctx, req.(*StorageIdentifier))
	}
	return interceptor(ctx, in, info, handler)
}

func _DBController_GetCollection_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CollectionIdentifier)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DBControllerServer).GetCollection(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DBController_GetCollection_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DBControllerServer).GetCollection(ctx, req.(*CollectionIdentifier))
	}
	return interceptor(ctx, in, info, handler)
}

func _DBController_CreateItem_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NewItem)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DBControllerServer).CreateItem(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DBController_CreateItem_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DBControllerServer).CreateItem(ctx, req.(*NewItem))
	}
	return interceptor(ctx, in, info, handler)
}

func _DBController_DeleteItem_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ItemIdentifier)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DBControllerServer).DeleteItem(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DBController_DeleteItem_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DBControllerServer).DeleteItem(ctx, req.(*ItemIdentifier))
	}
	return interceptor(ctx, in, info, handler)
}

func _DBController_GetIngestItem_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DBControllerServer).GetIngestItem(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DBController_GetIngestItem_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DBControllerServer).GetIngestItem(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _DBController_ExistsItem_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ItemIdentifier)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DBControllerServer).ExistsItem(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DBController_ExistsItem_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DBControllerServer).ExistsItem(ctx, req.(*ItemIdentifier))
	}
	return interceptor(ctx, in, info, handler)
}

// DBController_ServiceDesc is the grpc.ServiceDesc for DBController service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var DBController_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "mediaserverdbproto.DBController",
	HandlerType: (*DBControllerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Ping",
			Handler:    _DBController_Ping_Handler,
		},
		{
			MethodName: "GetItem",
			Handler:    _DBController_GetItem_Handler,
		},
		{
			MethodName: "GetStorage",
			Handler:    _DBController_GetStorage_Handler,
		},
		{
			MethodName: "GetCollection",
			Handler:    _DBController_GetCollection_Handler,
		},
		{
			MethodName: "CreateItem",
			Handler:    _DBController_CreateItem_Handler,
		},
		{
			MethodName: "DeleteItem",
			Handler:    _DBController_DeleteItem_Handler,
		},
		{
			MethodName: "GetIngestItem",
			Handler:    _DBController_GetIngestItem_Handler,
		},
		{
			MethodName: "ExistsItem",
			Handler:    _DBController_ExistsItem_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "dbcontroller.proto",
}
