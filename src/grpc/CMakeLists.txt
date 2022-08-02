
# Find Protobuf installation
# Looks for protobuf-config.cmake file installed by Protobuf's cmake installation.
set(protobuf_MODULE_COMPATIBLE TRUE)
find_package(Protobuf CONFIG REQUIRED)
message(STATUS "Using protobuf ${protobuf_VERSION}")

set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)

# Find gRPC installation
# Looks for gRPCConfig.cmake file installed by gRPC's cmake installation.
find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")

set(_GRPC_GRPCPP_UNSECURE gRPC::grpc++_unsecure)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)

# Proto file
get_filename_component(arion_proto "${CMAKE_CURRENT_SOURCE_DIR}/../../arion-master/schema/proto3/*.proto" ABSOLUTE)
get_filename_component(arion_proto_path "${arion_proto}" PATH)

set(arion_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/arionmaster.pb.cc")
set(arion_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/arionmaster.pb.h")
set(arion_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/arionmaster.grpc.pb.cc")
set(arion_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/arionmaster.grpc.pb.h")
add_custom_command(
      OUTPUT "${arion_proto_srcs}" "${arion_proto_hdrs}" "${arion_grpc_srcs}" "${arion_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${arion_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${arion_proto}"
      DEPENDS "${arion_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
 
ADD_LIBRARY(grpc ${arion_proto_srcs} ${arion_proto_hdrs} ${arion_grpc_srcs} ${arion_grpc_hdrs})