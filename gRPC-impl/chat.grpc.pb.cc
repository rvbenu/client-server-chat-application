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
  "/chat.ChatService/SendMessage",
  "/chat.ChatService/RetrieveOfflineMessages",
  "/chat.ChatService/MessageHistory",
  "/chat.ChatService/ListUsers",
  "/chat.ChatService/DeleteMessage",
  "/chat.ChatService/DeleteAccount",
  "/chat.ChatService/Quit",
};

std::unique_ptr< ChatService::Stub> ChatService::NewStub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options) {
  (void)options;
  std::unique_ptr< ChatService::Stub> stub(new ChatService::Stub(channel, options));
  return stub;
}

ChatService::Stub::Stub(const std::shared_ptr< ::grpc::ChannelInterface>& channel, const ::grpc::StubOptions& options)
  : channel_(channel), rpcmethod_Register_(ChatService_method_names[0], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_Login_(ChatService_method_names[1], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_SendMessage_(ChatService_method_names[2], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_RetrieveOfflineMessages_(ChatService_method_names[3], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_MessageHistory_(ChatService_method_names[4], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_ListUsers_(ChatService_method_names[5], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_DeleteMessage_(ChatService_method_names[6], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_DeleteAccount_(ChatService_method_names[7], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  , rpcmethod_Quit_(ChatService_method_names[8], options.suffix_for_stats(),::grpc::internal::RpcMethod::NORMAL_RPC, channel)
  {}

::grpc::Status ChatService::Stub::Register(::grpc::ClientContext* context, const ::chat::RegisterRequest& request, ::chat::StatusReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::RegisterRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_Register_, context, request, response);
}

void ChatService::Stub::async::Register(::grpc::ClientContext* context, const ::chat::RegisterRequest* request, ::chat::StatusReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::RegisterRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Register_, context, request, response, std::move(f));
}

void ChatService::Stub::async::Register(::grpc::ClientContext* context, const ::chat::RegisterRequest* request, ::chat::StatusReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Register_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::StatusReply>* ChatService::Stub::PrepareAsyncRegisterRaw(::grpc::ClientContext* context, const ::chat::RegisterRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::StatusReply, ::chat::RegisterRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_Register_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::StatusReply>* ChatService::Stub::AsyncRegisterRaw(::grpc::ClientContext* context, const ::chat::RegisterRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncRegisterRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::Login(::grpc::ClientContext* context, const ::chat::LoginRequest& request, ::chat::LoginReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::LoginRequest, ::chat::LoginReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_Login_, context, request, response);
}

void ChatService::Stub::async::Login(::grpc::ClientContext* context, const ::chat::LoginRequest* request, ::chat::LoginReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::LoginRequest, ::chat::LoginReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Login_, context, request, response, std::move(f));
}

void ChatService::Stub::async::Login(::grpc::ClientContext* context, const ::chat::LoginRequest* request, ::chat::LoginReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Login_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::LoginReply>* ChatService::Stub::PrepareAsyncLoginRaw(::grpc::ClientContext* context, const ::chat::LoginRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::LoginReply, ::chat::LoginRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_Login_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::LoginReply>* ChatService::Stub::AsyncLoginRaw(::grpc::ClientContext* context, const ::chat::LoginRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncLoginRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::SendMessage(::grpc::ClientContext* context, const ::chat::MessageRequest& request, ::chat::StatusReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::MessageRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_SendMessage_, context, request, response);
}

void ChatService::Stub::async::SendMessage(::grpc::ClientContext* context, const ::chat::MessageRequest* request, ::chat::StatusReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::MessageRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_SendMessage_, context, request, response, std::move(f));
}

void ChatService::Stub::async::SendMessage(::grpc::ClientContext* context, const ::chat::MessageRequest* request, ::chat::StatusReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_SendMessage_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::StatusReply>* ChatService::Stub::PrepareAsyncSendMessageRaw(::grpc::ClientContext* context, const ::chat::MessageRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::StatusReply, ::chat::MessageRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_SendMessage_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::StatusReply>* ChatService::Stub::AsyncSendMessageRaw(::grpc::ClientContext* context, const ::chat::MessageRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncSendMessageRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::RetrieveOfflineMessages(::grpc::ClientContext* context, const ::chat::OfflineRequest& request, ::chat::OfflineReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::OfflineRequest, ::chat::OfflineReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_RetrieveOfflineMessages_, context, request, response);
}

void ChatService::Stub::async::RetrieveOfflineMessages(::grpc::ClientContext* context, const ::chat::OfflineRequest* request, ::chat::OfflineReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::OfflineRequest, ::chat::OfflineReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_RetrieveOfflineMessages_, context, request, response, std::move(f));
}

void ChatService::Stub::async::RetrieveOfflineMessages(::grpc::ClientContext* context, const ::chat::OfflineRequest* request, ::chat::OfflineReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_RetrieveOfflineMessages_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::OfflineReply>* ChatService::Stub::PrepareAsyncRetrieveOfflineMessagesRaw(::grpc::ClientContext* context, const ::chat::OfflineRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::OfflineReply, ::chat::OfflineRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_RetrieveOfflineMessages_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::OfflineReply>* ChatService::Stub::AsyncRetrieveOfflineMessagesRaw(::grpc::ClientContext* context, const ::chat::OfflineRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncRetrieveOfflineMessagesRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::MessageHistory(::grpc::ClientContext* context, const ::chat::HistoryRequest& request, ::chat::HistoryReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::HistoryRequest, ::chat::HistoryReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_MessageHistory_, context, request, response);
}

void ChatService::Stub::async::MessageHistory(::grpc::ClientContext* context, const ::chat::HistoryRequest* request, ::chat::HistoryReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::HistoryRequest, ::chat::HistoryReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_MessageHistory_, context, request, response, std::move(f));
}

void ChatService::Stub::async::MessageHistory(::grpc::ClientContext* context, const ::chat::HistoryRequest* request, ::chat::HistoryReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_MessageHistory_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::HistoryReply>* ChatService::Stub::PrepareAsyncMessageHistoryRaw(::grpc::ClientContext* context, const ::chat::HistoryRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::HistoryReply, ::chat::HistoryRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_MessageHistory_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::HistoryReply>* ChatService::Stub::AsyncMessageHistoryRaw(::grpc::ClientContext* context, const ::chat::HistoryRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncMessageHistoryRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::ListUsers(::grpc::ClientContext* context, const ::chat::UserListRequest& request, ::chat::UserListReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::UserListRequest, ::chat::UserListReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_ListUsers_, context, request, response);
}

void ChatService::Stub::async::ListUsers(::grpc::ClientContext* context, const ::chat::UserListRequest* request, ::chat::UserListReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::UserListRequest, ::chat::UserListReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_ListUsers_, context, request, response, std::move(f));
}

void ChatService::Stub::async::ListUsers(::grpc::ClientContext* context, const ::chat::UserListRequest* request, ::chat::UserListReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_ListUsers_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::UserListReply>* ChatService::Stub::PrepareAsyncListUsersRaw(::grpc::ClientContext* context, const ::chat::UserListRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::UserListReply, ::chat::UserListRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_ListUsers_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::UserListReply>* ChatService::Stub::AsyncListUsersRaw(::grpc::ClientContext* context, const ::chat::UserListRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncListUsersRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::DeleteMessage(::grpc::ClientContext* context, const ::chat::DeleteMessageRequest& request, ::chat::StatusReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::DeleteMessageRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_DeleteMessage_, context, request, response);
}

void ChatService::Stub::async::DeleteMessage(::grpc::ClientContext* context, const ::chat::DeleteMessageRequest* request, ::chat::StatusReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::DeleteMessageRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_DeleteMessage_, context, request, response, std::move(f));
}

void ChatService::Stub::async::DeleteMessage(::grpc::ClientContext* context, const ::chat::DeleteMessageRequest* request, ::chat::StatusReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_DeleteMessage_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::StatusReply>* ChatService::Stub::PrepareAsyncDeleteMessageRaw(::grpc::ClientContext* context, const ::chat::DeleteMessageRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::StatusReply, ::chat::DeleteMessageRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_DeleteMessage_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::StatusReply>* ChatService::Stub::AsyncDeleteMessageRaw(::grpc::ClientContext* context, const ::chat::DeleteMessageRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncDeleteMessageRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::DeleteAccount(::grpc::ClientContext* context, const ::chat::AccountRequest& request, ::chat::StatusReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::AccountRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_DeleteAccount_, context, request, response);
}

void ChatService::Stub::async::DeleteAccount(::grpc::ClientContext* context, const ::chat::AccountRequest* request, ::chat::StatusReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::AccountRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_DeleteAccount_, context, request, response, std::move(f));
}

void ChatService::Stub::async::DeleteAccount(::grpc::ClientContext* context, const ::chat::AccountRequest* request, ::chat::StatusReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_DeleteAccount_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::StatusReply>* ChatService::Stub::PrepareAsyncDeleteAccountRaw(::grpc::ClientContext* context, const ::chat::AccountRequest& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::StatusReply, ::chat::AccountRequest, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_DeleteAccount_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::StatusReply>* ChatService::Stub::AsyncDeleteAccountRaw(::grpc::ClientContext* context, const ::chat::AccountRequest& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncDeleteAccountRaw(context, request, cq);
  result->StartCall();
  return result;
}

::grpc::Status ChatService::Stub::Quit(::grpc::ClientContext* context, const ::chat::Empty& request, ::chat::StatusReply* response) {
  return ::grpc::internal::BlockingUnaryCall< ::chat::Empty, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), rpcmethod_Quit_, context, request, response);
}

void ChatService::Stub::async::Quit(::grpc::ClientContext* context, const ::chat::Empty* request, ::chat::StatusReply* response, std::function<void(::grpc::Status)> f) {
  ::grpc::internal::CallbackUnaryCall< ::chat::Empty, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Quit_, context, request, response, std::move(f));
}

void ChatService::Stub::async::Quit(::grpc::ClientContext* context, const ::chat::Empty* request, ::chat::StatusReply* response, ::grpc::ClientUnaryReactor* reactor) {
  ::grpc::internal::ClientCallbackUnaryFactory::Create< ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(stub_->channel_.get(), stub_->rpcmethod_Quit_, context, request, response, reactor);
}

::grpc::ClientAsyncResponseReader< ::chat::StatusReply>* ChatService::Stub::PrepareAsyncQuitRaw(::grpc::ClientContext* context, const ::chat::Empty& request, ::grpc::CompletionQueue* cq) {
  return ::grpc::internal::ClientAsyncResponseReaderHelper::Create< ::chat::StatusReply, ::chat::Empty, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(channel_.get(), cq, rpcmethod_Quit_, context, request);
}

::grpc::ClientAsyncResponseReader< ::chat::StatusReply>* ChatService::Stub::AsyncQuitRaw(::grpc::ClientContext* context, const ::chat::Empty& request, ::grpc::CompletionQueue* cq) {
  auto* result =
    this->PrepareAsyncQuitRaw(context, request, cq);
  result->StartCall();
  return result;
}

ChatService::Service::Service() {
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[0],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::RegisterRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::RegisterRequest* req,
             ::chat::StatusReply* resp) {
               return service->Register(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[1],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::LoginRequest, ::chat::LoginReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::LoginRequest* req,
             ::chat::LoginReply* resp) {
               return service->Login(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[2],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::MessageRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::MessageRequest* req,
             ::chat::StatusReply* resp) {
               return service->SendMessage(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[3],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::OfflineRequest, ::chat::OfflineReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::OfflineRequest* req,
             ::chat::OfflineReply* resp) {
               return service->RetrieveOfflineMessages(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[4],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::HistoryRequest, ::chat::HistoryReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::HistoryRequest* req,
             ::chat::HistoryReply* resp) {
               return service->MessageHistory(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[5],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::UserListRequest, ::chat::UserListReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::UserListRequest* req,
             ::chat::UserListReply* resp) {
               return service->ListUsers(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[6],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::DeleteMessageRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::DeleteMessageRequest* req,
             ::chat::StatusReply* resp) {
               return service->DeleteMessage(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[7],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::AccountRequest, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::AccountRequest* req,
             ::chat::StatusReply* resp) {
               return service->DeleteAccount(ctx, req, resp);
             }, this)));
  AddMethod(new ::grpc::internal::RpcServiceMethod(
      ChatService_method_names[8],
      ::grpc::internal::RpcMethod::NORMAL_RPC,
      new ::grpc::internal::RpcMethodHandler< ChatService::Service, ::chat::Empty, ::chat::StatusReply, ::grpc::protobuf::MessageLite, ::grpc::protobuf::MessageLite>(
          [](ChatService::Service* service,
             ::grpc::ServerContext* ctx,
             const ::chat::Empty* req,
             ::chat::StatusReply* resp) {
               return service->Quit(ctx, req, resp);
             }, this)));
}

ChatService::Service::~Service() {
}

::grpc::Status ChatService::Service::Register(::grpc::ServerContext* context, const ::chat::RegisterRequest* request, ::chat::StatusReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::Login(::grpc::ServerContext* context, const ::chat::LoginRequest* request, ::chat::LoginReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::SendMessage(::grpc::ServerContext* context, const ::chat::MessageRequest* request, ::chat::StatusReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::RetrieveOfflineMessages(::grpc::ServerContext* context, const ::chat::OfflineRequest* request, ::chat::OfflineReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::MessageHistory(::grpc::ServerContext* context, const ::chat::HistoryRequest* request, ::chat::HistoryReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::ListUsers(::grpc::ServerContext* context, const ::chat::UserListRequest* request, ::chat::UserListReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::DeleteMessage(::grpc::ServerContext* context, const ::chat::DeleteMessageRequest* request, ::chat::StatusReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::DeleteAccount(::grpc::ServerContext* context, const ::chat::AccountRequest* request, ::chat::StatusReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}

::grpc::Status ChatService::Service::Quit(::grpc::ServerContext* context, const ::chat::Empty* request, ::chat::StatusReply* response) {
  (void) context;
  (void) request;
  (void) response;
  return ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED, "");
}


}  // namespace chat

