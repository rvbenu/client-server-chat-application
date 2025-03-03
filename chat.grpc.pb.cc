// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: chat.proto

#include "chat.pb.h"
#include "chat.grpc.pb.h"

#include <functional>
#include <grpcpp/support/async_stream.h>
#include <grpcpp/support/async_unary_call.h>
#include <grpcpp/impl/channel_interface.h>
#include <grpcpp/impl/client_unary_call.h>
#include <grpcpp/support/client_callback.h>
#include <grpcpp/support/message_allocator.h>
#include <grpcpp/support/method_handler.h>
#include <grpcpp/impl/rpc_service_method.h>
#include <grpcpp/support/server_callback.h>
#include <grpcpp/impl/server_callback_handlers.h>
#include <grpcpp/server_context.h>
#include <grpcpp/impl/service_type.h>
#include <grpcpp/support/sync_stream.h>
namespace chat {

static const char* ChatService_method_names[] = {
  "/chat.ChatService/Register",
  "/chat.ChatService/Login",
  "/chat.ChatService/RetrieveUndeliveredMessages",
  "/chat.ChatService/DeleteMessage",
  "/chat.ChatService/ChatStream",
  "/chat.ChatService/SearchUsers",
};

std::unique_ptr< ChatService::Stub> ChatService::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< ChatService::Stub> stub(new ChatService::Stub(channel, options));
  return stub;
}

ChatService::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options)
  : channel_(channel), rpcmethod_Register_(ChatService_method_names[0], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_Login_(ChatService_method_names[1], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_RetrieveUndeliveredMessages_(ChatService_method_names[2], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_DeleteMessage_(ChatService_method_names[3], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_ChatStream_(ChatService_method_names[4], options.suffix_for_stats(),::grpc::internal::RpcMethod::BIDI_STREAMING, channel)
  , rpcmethod_SearchUsers_(ChatService_method_names[5], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status ChatService::Stub::Register(::grpc::ClientContext* context, const ::chat::RegisterRequest& request, ::chat::RegisterResponse* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::RegisterRequest, ::chat::RegisterResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_Register_, context, request, response);
}

void ChatService::Stub::async::Register(::grpc::ClientContext* context, const ::chat::RegisterRequest* request, ::chat::RegisterResponse* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::RegisterRequest, ::chat::RegisterResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Register_, context, request, response, std::move(f));
}

void ChatService::Stub::async::Register(::grpc::ClientContext* context, const ::chat::RegisterRequest* request, ::chat::RegisterResponse* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Register_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::RegisterResponse>* ChatService::Stub::PrepareAsyncRegisterRaw(::grpc::ClientContext* context, const ::chat::RegisterRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::RegisterResponse, ::chat::RegisterRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_Register_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::RegisterResponse>* ChatService::Stub::AsyncRegisterRaw(::grpc::ClientContext* context, const ::chat::RegisterRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncRegisterRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::Login(::grpc::ClientContext* context, const ::chat::LoginRequest& request, ::chat::LoginResponse* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::LoginRequest, ::chat::LoginResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_Login_, context, request, response);
}

void ChatService::Stub::async::Login(::grpc::ClientContext* context, const ::chat::LoginRequest* request, ::chat::LoginResponse* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::LoginRequest, ::chat::LoginResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Login_, context, request, response, std::move(f));
}

void ChatService::Stub::async::Login(::grpc::ClientContext* context, const ::chat::LoginRequest* request, ::chat::LoginResponse* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Login_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::LoginResponse>* ChatService::Stub::PrepareAsyncLoginRaw(::grpc::ClientContext* context, const ::chat::LoginRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::LoginResponse, ::chat::LoginRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_Login_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::LoginResponse>* ChatService::Stub::AsyncLoginRaw(::grpc::ClientContext* context, const ::chat::LoginRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncLoginRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::RetrieveUndeliveredMessages(::grpc::ClientContext* context, const ::chat::UndeliveredMessagesRequest& request, ::chat::UndeliveredMessagesResponse* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::UndeliveredMessagesRequest, ::chat::UndeliveredMessagesResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_RetrieveUndeliveredMessages_, context, request, response);
}

void ChatService::Stub::async::RetrieveUndeliveredMessages(::grpc::ClientContext* context, const ::chat::UndeliveredMessagesRequest* request, ::chat::UndeliveredMessagesResponse* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::UndeliveredMessagesRequest, ::chat::UndeliveredMessagesResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_RetrieveUndeliveredMessages_, context, request, response, std::move(f));
}

void ChatService::Stub::async::RetrieveUndeliveredMessages(::grpc::ClientContext* context, const ::chat::UndeliveredMessagesRequest* request, ::chat::UndeliveredMessagesResponse* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_RetrieveUndeliveredMessages_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::UndeliveredMessagesResponse>* ChatService::Stub::PrepareAsyncRetrieveUndeliveredMessagesRaw(::grpc::ClientContext* context, const ::chat::UndeliveredMessagesRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::UndeliveredMessagesResponse, ::chat::UndeliveredMessagesRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_RetrieveUndeliveredMessages_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::UndeliveredMessagesResponse>* ChatService::Stub::AsyncRetrieveUndeliveredMessagesRaw(::grpc::ClientContext* context, const ::chat::UndeliveredMessagesRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncRetrieveUndeliveredMessagesRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::DeleteMessage(::grpc::ClientContext* context, const ::chat::DeleteMessageRequest& request, ::chat::DeleteMessageResponse* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::DeleteMessageRequest, ::chat::DeleteMessageResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_DeleteMessage_, context, request, response);
}

void ChatService::Stub::async::DeleteMessage(::grpc::ClientContext* context, const ::chat::DeleteMessageRequest* request, ::chat::DeleteMessageResponse* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::DeleteMessageRequest, ::chat::DeleteMessageResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_DeleteMessage_, context, request, response, std::move(f));
}

void ChatService::Stub::async::DeleteMessage(::grpc::ClientContext* context, const ::chat::DeleteMessageRequest* request, ::chat::DeleteMessageResponse* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_DeleteMessage_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::DeleteMessageResponse>* ChatService::Stub::PrepareAsyncDeleteMessageRaw(::grpc::ClientContext* context, const ::chat::DeleteMessageRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::DeleteMessageResponse, ::chat::DeleteMessageRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_DeleteMessage_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::DeleteMessageResponse>* ChatService::Stub::AsyncDeleteMessageRaw(::grpc::ClientContext* context, const ::chat::DeleteMessageRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncDeleteMessageRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::ClientReaderWriter< ::chat::ChatMessage, ::chat::ChatMessage>* ChatService::Stub::ChatStreamRaw(::grpc::ClientContext* context) {
  return ::grpc::internal::ClientReaderWriterFactory< ::chat::ChatMessage, ::chat::ChatMessage>::Create(channel_.get(), rpcmethod_ChatStream_, context);
}

void ChatService::Stub::async::ChatStream(::grpc::ClientContext* context, ::grpc::ClientBidiReactor< ::chat::ChatMessage,::chat::ChatMessage>* reactor) {
  ::grpc::internal::ClientCallbackReaderWriterFactory< ::chat::ChatMessage,::chat::ChatMessage>::Create(stub_->channel_.get(), stub_->rpcmethod_ChatStream_, context, reactor);
}

::grpc::ClientAsyncReaderWriter< ::chat::ChatMessage, ::chat::ChatMessage>* ChatService::Stub::AsyncChatStreamRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq, void* tag) {
  return ::grpc::internal::ClientAsyncReaderWriterFactory< ::chat::ChatMessage, ::chat::ChatMessage>::Create(channel_.get(), cq, rpcmethod_ChatStream_, context, true, tag);
}

::grpc::ClientAsyncReaderWriter< ::chat::ChatMessage, ::chat::ChatMessage>* ChatService::Stub::PrepareAsyncChatStreamRaw(::grpc::ClientContext* context, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncReaderWriterFactory< ::chat::ChatMessage, ::chat::ChatMessage>::Create(channel_.get(), cq, rpcmethod_ChatStream_, context, false, nullptr);
}

::grpc::Status ChatService::Stub::SearchUsers(::grpc::ClientContext* context, const ::chat::SearchUsersRequest& request, ::chat::SearchUsersResponse* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::SearchUsersRequest, ::chat::SearchUsersResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_SearchUsers_, context, request, response);
}

void ChatService::Stub::async::SearchUsers(::grpc::ClientContext* context, const ::chat::SearchUsersRequest* request, ::chat::SearchUsersResponse* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::SearchUsersRequest, ::chat::SearchUsersResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_SearchUsers_, context, request, response, std::move(f));
}

void ChatService::Stub::async::SearchUsers(::grpc::ClientContext* context, const ::chat::SearchUsersRequest* request, ::chat::SearchUsersResponse* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_SearchUsers_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::SearchUsersResponse>* ChatService::Stub::PrepareAsyncSearchUsersRaw(::grpc::ClientContext* context, const ::chat::SearchUsersRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::SearchUsersResponse, ::chat::SearchUsersRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_SearchUsers_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::SearchUsersResponse>* ChatService::Stub::AsyncSearchUsersRaw(::grpc::ClientContext* context, const ::chat::SearchUsersRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncSearchUsersRaw(context, request, cq);
  result->StartCall();
  return result;
}

ChatService::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::RegisterRequest, ::chat::RegisterResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::RegisterRequest* req,
             ::chat::RegisterResponse* resp) {
               return service->Register(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::LoginRequest, ::chat::LoginResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::LoginRequest* req,
             ::chat::LoginResponse* resp) {
               return service->Login(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[2],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::UndeliveredMessagesRequest, ::chat::UndeliveredMessagesResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::UndeliveredMessagesRequest* req,
             ::chat::UndeliveredMessagesResponse* resp) {
               return service->RetrieveUndeliveredMessages(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[3],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::DeleteMessageRequest, ::chat::DeleteMessageResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::DeleteMessageRequest* req,
             ::chat::DeleteMessageResponse* resp) {
               return service->DeleteMessage(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[4],
      ::grpc::internal::RpcMethod::BIDI_STREAMING,
      new ::grpc::internal::BidiStreamingHandler< ChatService::Service, ::chat::ChatMessage, ::chat::ChatMessage>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             ::grpc::ServerReaderWriter<::chat::ChatMessage,
             ::chat::ChatMessage>* stream) {
               return service->ChatStream(ctx, stream);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[5],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::SearchUsersRequest, ::chat::SearchUsersResponse, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::SearchUsersRequest* req,
             ::chat::SearchUsersResponse* resp) {
               return service->SearchUsers(ctx, req, resp);
             }, this)));
}

ChatService::Service::~Service() {
}

::grpc::Status ChatService::Service::Register(::grpc::ServerContext* context, const ::chat::RegisterRequest* request, ::chat::RegisterResponse* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::Login(::grpc::ServerContext* context, const ::chat::LoginRequest* request, ::chat::LoginResponse* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::RetrieveUndeliveredMessages(::grpc::ServerContext* context, const ::chat::UndeliveredMessagesRequest* request, ::chat::UndeliveredMessagesResponse* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::DeleteMessage(::grpc::ServerContext* context, const ::chat::DeleteMessageRequest* request, ::chat::DeleteMessageResponse* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::ChatStream(::grpc::ServerContext* context, ::grpc::ServerReaderWriter< ::chat::ChatMessage, ::chat::ChatMessage>* stream) {
  (void) context;
  (void) stream;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::SearchUsers(::grpc::ServerContext* context, const ::chat::SearchUsersRequest* request, ::chat::SearchUsersResponse* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace chat

