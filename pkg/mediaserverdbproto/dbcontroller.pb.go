// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.25.3
// source: dbcontroller.proto

package mediaserverdbproto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_dbcontroller_proto protoreflect.FileDescriptor

var file_dbcontroller_proto_rawDesc = []byte{
	0x0a, 0x12, 0x64, 0x62, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x12, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x72, 0x64, 0x62, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0a, 0x69, 0x74, 0x65, 0x6d, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x15, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x32, 0x60, 0x0a, 0x0c, 0x44,
	0x42, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x12, 0x50, 0x0a, 0x0a, 0x43,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x49, 0x74, 0x65, 0x6d, 0x12, 0x1b, 0x2e, 0x6d, 0x65, 0x64, 0x69,
	0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x64, 0x62, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x4e,
	0x65, 0x77, 0x49, 0x74, 0x65, 0x6d, 0x1a, 0x23, 0x2e, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x64, 0x62, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x44, 0x65, 0x66, 0x61,
	0x75, 0x6c, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x83, 0x01,
	0x0a, 0x1b, 0x63, 0x68, 0x2e, 0x75, 0x6e, 0x69, 0x62, 0x61, 0x73, 0x2e, 0x75, 0x62, 0x2e, 0x6d,
	0x65, 0x64, 0x69, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x64, 0x62, 0x42, 0x09, 0x49,
	0x74, 0x65, 0x6d, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6a, 0x65, 0x34, 0x2f, 0x6d, 0x65, 0x64, 0x69, 0x61,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x64, 0x62, 0x2f, 0x76, 0x32, 0x2f, 0x70, 0x6b, 0x67, 0x2f,
	0x6d, 0x65, 0x64, 0x69, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x64, 0x62, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0xa2, 0x02, 0x03, 0x55, 0x42, 0x42, 0xaa, 0x02, 0x18, 0x55, 0x6e, 0x69, 0x62, 0x61,
	0x73, 0x2e, 0x55, 0x42, 0x2e, 0x4d, 0x65, 0x64, 0x69, 0x61, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x2e, 0x44, 0x42, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_dbcontroller_proto_goTypes = []interface{}{
	(*NewItem)(nil),         // 0: mediaserverdbproto.NewItem
	(*DefaultResponse)(nil), // 1: mediaserverdbproto.DefaultResponse
}
var file_dbcontroller_proto_depIdxs = []int32{
	0, // 0: mediaserverdbproto.DBController.CreateItem:input_type -> mediaserverdbproto.NewItem
	1, // 1: mediaserverdbproto.DBController.CreateItem:output_type -> mediaserverdbproto.DefaultResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_dbcontroller_proto_init() }
func file_dbcontroller_proto_init() {
	if File_dbcontroller_proto != nil {
		return
	}
	file_item_proto_init()
	file_defaultResponse_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_dbcontroller_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_dbcontroller_proto_goTypes,
		DependencyIndexes: file_dbcontroller_proto_depIdxs,
	}.Build()
	File_dbcontroller_proto = out.File
	file_dbcontroller_proto_rawDesc = nil
	file_dbcontroller_proto_goTypes = nil
	file_dbcontroller_proto_depIdxs = nil
}
