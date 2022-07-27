set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../build/bin)

set(SOURCES
    ./comm/grpc_client.cpp
    )

#FIND_LIBRARY(LIBUUID_LIBRARIES uuid)
#link_libraries(/usr/lib/x86_64-linux-gnu/libuuid.so)
link_libraries(/usr/lib/x86_64-linux-gnu/libevent_pthreads.so)
link_libraries(/usr/lib/x86_64-linux-gnu/libpthread.so)
link_libraries(/var/local/git/marl/marl/build/libmarl.a)             #this was built by machine-init.sh
link_libraries(/var/local/git/zeta/src/extern/libbpf/src/libbpf.a)   #this was built by machine-init.sh
link_libraries(/usr/lib/x86_64-linux-gnu/libelf.a)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/proto3)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/grpc)
include_directories(/var/local/git/marl/marl/include)
include_directories(/var/local/git/zeta/src/extern/libbpf/src) #libbpf.h

# Find Protobuf installation
# Looks for protobuf-config.cmake file installed by Protobuf's cmake installation.
set(protobuf_MODULE_COMPATIBLE TRUE)
find_package(Protobuf CONFIG REQUIRED)
message(STATUS "Using protobuf ${protobuf_VERSION}")

# Find gRPC installation
# Looks for gRPCConfig.cmake file installed by gRPC's cmake installation.
find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")

set(_GRPC_GRPCPP_UNSECURE gRPC::grpc++_unsecure)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)

add_library(ArionAgentLib STATIC ${SOURCES})
#target_link_libraries(ArionAgentLib event)
target_link_libraries(ArionAgentLib ssl)
target_link_libraries(ArionAgentLib crypto)
target_link_libraries(ArionAgentLib rt)

add_executable(ArionAgent main.cpp)
target_link_libraries(ArionAgent ArionAgentLib)
target_link_libraries(ArionAgent proto)
target_link_libraries(ArionAgent grpc)
target_link_libraries(ArionAgent ${PROTOBUF_LIBRARY})
target_link_libraries(ArionAgent ${_GRPC_GRPCPP_UNSECURE})

add_dependencies(ArionAgentLib proto grpc)
add_subdirectory(proto3)
add_subdirectory(grpc)
