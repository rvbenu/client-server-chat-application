#ifndef CHAT_SERVICE_IMPL_H
#define CHAT_SERVICE_IMPL_H

#include <grpcpp/grpcpp.h>
#include "chat.grpc.pb.h"

/**
 * @brief Implementation of the ChatService gRPC service.
 */
class ChatServiceImpl final : public chat::ChatService::Service {
public:
    grpc::Status Register(grpc::ServerContext* context, const chat::RegisterRequest* request,
                          chat::StatusReply* reply) override;

    grpc::Status Login(grpc::ServerContext* context, const chat::LoginRequest* request,
                       chat::LoginReply* reply) override;

    grpc::Status SendMessage(grpc::ServerContext* context, const chat::MessageRequest* request,
                             chat::StatusReply* reply) override;

    grpc::Status RetrieveOfflineMessages(grpc::ServerContext* context, const chat::OfflineRequest* request,
                                         chat::OfflineReply* reply) override;

    grpc::Status MessageHistory(grpc::ServerContext* context, const chat::HistoryRequest* request,
                                chat::HistoryReply* reply) override;

    grpc::Status ListUsers(grpc::ServerContext* context, const chat::UserListRequest* request,
                           chat::UserListReply* reply) override;

    grpc::Status DeleteMessage(grpc::ServerContext* context, const chat::DeleteMessageRequest* request,
                               chat::StatusReply* reply) override;

    grpc::Status DeleteAccount(grpc::ServerContext* context, const chat::AccountRequest* request,
                               chat::StatusReply* reply) override;

    grpc::Status Quit(grpc::ServerContext* context, const chat::Empty* request,
                      chat::StatusReply* reply) override;
};

#endif // CHAT_SERVICE_IMPL_H
