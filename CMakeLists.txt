cmake_minimum_required(VERSION 3.14)

# Project name
project(ChatApp CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find gRPC and Protobuf
find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)

# Include directories
include_directories(
    ${Protobuf_INCLUDE_DIRS}
    ${gRPC_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/gRPC-impl/proto
    ${CMAKE_SOURCE_DIR}/user_auth
)

# Source files
set(PROTO_SRC
    gRPC-impl/proto/chat.pb.cc
    gRPC-impl/proto/chat.grpc.pb.cc
)

set(SERVER_SRC
    gRPC-impl/server_grpc.cpp
    gRPC-impl/server_grpc.h  # Includes global storage & data structures
    gRPC-impl/chat_service_impl.h
    ${PROTO_SRC}
)

set(CLIENT_SRC
    gRPC-impl/client_grpc.cpp
    gRPC-impl/client_grpc.h
    ${PROTO_SRC}
)

set(AUTH_SRC
    user_auth/user_auth.cpp
    user_auth/user_auth.h
)

# gRPC Server executable
add_executable(chat_server ${SERVER_SRC} ${AUTH_SRC})
target_link_libraries(chat_server gRPC::grpc++ protobuf::libprotobuf)

# gRPC Client executable
add_executable(chat_client ${CLIENT_SRC} ${AUTH_SRC})
target_link_libraries(chat_client gRPC::grpc++ protobuf::libprotobuf)
