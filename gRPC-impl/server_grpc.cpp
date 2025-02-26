#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <fstream>
#include <grpcpp/grpcpp.h>
#include "chat.grpc.pb.h"
#include "chat_service_impl.h"
#include "server.h"
#include "user_auth/user_auth.h"  // For Argon2 functions

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

/**
 * @brief Implementation of Register RPC.
 */
Status ChatServiceImpl::Register(ServerContext* context, const chat::RegisterRequest* request,
                                 chat::StatusReply* reply) {
    std::lock_guard<std::mutex> lock(userMapMutex);
    if (userMap.find(request->username()) != userMap.end()) {
        reply->set_success(false);
        reply->set_error_message("Username already exists.");
        return Status::OK;
    }
    UserInfo newUser;
    newUser.password = request->password(); // Password already hashed by the client.
    newUser.isOnline = true;
    userMap[request->username()] = std::move(newUser);
    std::cout << "[INFO] User '" << request->username() << "' registered via gRPC.\n";
    reply->set_success(true);
    return Status::OK;
}

/**
 * @brief Implementation of Login RPC.
 */
Status ChatServiceImpl::Login(ServerContext* context, const chat::LoginRequest* request,
                              chat::LoginReply* reply) {
    std::lock_guard<std::mutex> lock(userMapMutex);
    auto it = userMap.find(request->username());
    if (it == userMap.end() || !argon2CheckPassword(it->second.password, request->password())) {
        reply->set_success(false);
        reply->set_error_message("Invalid username or password.");
        return Status::OK;
    }
    it->second.isOnline = true;
    std::cout << "[INFO] User '" << request->username() << "' logged in via gRPC.\n";
    reply->set_success(true);
    reply->set_unread_messages(it->second.offlineMessages.size());
    return Status::OK;
}

/**
 * @brief Implementation of SendMessage RPC.
 */
Status ChatServiceImpl::SendMessage(ServerContext* context, const chat::MessageRequest* request,
                                    chat::StatusReply* reply) {
    std::string message_id;
    {
        std::lock_guard<std::mutex> lock(messagesMutex);
        messageCounter++;
        message_id = std::to_string(messageCounter);
        messages[messageCounter] = { message_id, request->message(),
                                     request->sender(), request->recipient() };
    }
    bool validRecipient = false;
    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        auto it = userMap.find(request->recipient());
        if (it != userMap.end()) {
            validRecipient = true;
            if (!it->second.isOnline) {
                Message offlineMsg = { message_id, request->message(), request->sender(), request->recipient() };
                it->second.offlineMessages.push_back(offlineMsg);
                std::cout << "[INFO] Stored offline message for '" << request->recipient() << "'.\n";
            }
        }
    }
    if (!validRecipient) {
        reply->set_success(false);
        reply->set_error_message("Invalid recipient.");
    } else {
        reply->set_success(true);
    }
    return Status::OK;
}

/**
 * @brief Implementation of RetrieveOfflineMessages RPC.
 */
Status ChatServiceImpl::RetrieveOfflineMessages(ServerContext* context, const chat::OfflineRequest* request,
                                                chat::OfflineReply* reply) {
    std::vector<Message> messagesToSend;
    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        auto it = userMap.find(request->username());
        if (it != userMap.end()) {
            int count = 0;
            for (const auto &msg : it->second.offlineMessages) {
                messagesToSend.push_back(msg);
                if (++count >= request->count())
                    break;
            }
            if (request->mark_as_read() && count > 0)
                it->second.offlineMessages.erase(it->second.offlineMessages.begin(),
                                                 it->second.offlineMessages.begin() + count);
        }
    }
    for (const auto &msg : messagesToSend) {
        chat::MessageData* m = reply->add_messages();
        m->set_id(msg.id);
        m->set_sender(msg.sender);
        m->set_recipient(msg.recipient);
        m->set_content(msg.content);
    }
    return Status::OK;
}

/**
 * @brief Implementation of MessageHistory RPC.
 */
Status ChatServiceImpl::MessageHistory(ServerContext* context, const chat::HistoryRequest* request,
                                       chat::HistoryReply* reply) {
    std::vector<std::pair<int, Message>> historyMessages;
    {
        std::lock_guard<std::mutex> lock(messagesMutex);
        for (const auto &kv : messages) {
            const Message &msg = kv.second;
            if (msg.sender == request->username() || msg.recipient == request->username())
                historyMessages.push_back(kv);
        }
    }
    std::sort(historyMessages.begin(), historyMessages.end(),
              [](const std::pair<int, Message>& a, const std::pair<int, Message>& b) {
                  return a.first < b.first;
              });
    for (const auto &p : historyMessages) {
        chat::MessageData* m = reply->add_messages();
        m->set_id(p.second.id);
        m->set_sender(p.second.sender);
        m->set_recipient(p.second.recipient);
        m->set_content(p.second.content);
    }
    return Status::OK;
}

/**
 * @brief Implementation of ListUsers RPC.
 */
Status ChatServiceImpl::ListUsers(ServerContext* context, const chat::UserListRequest* request,
                                  chat::UserListReply* reply) {
    std::lock_guard<std::mutex> lock(userMapMutex);
    for (const auto &kv : userMap) {
        if (request->pattern().empty() ||
            (kv.first.find(request->pattern()) != std::string::npos))
            reply->add_usernames(kv.first);
    }
    return Status::OK;
}

/**
 * @brief Implementation of DeleteMessage RPC.
 */
Status ChatServiceImpl::DeleteMessage(ServerContext* context, const chat::DeleteMessageRequest* request,
                                      chat::StatusReply* reply) {
    bool deleted = false;
    {
        std::lock_guard<std::mutex> lock(messagesMutex);
        for (auto it = messages.begin(); it != messages.end(); ++it) {
            if (it->second.id == request->message_id() &&
                it->second.recipient == request->username()) {
                messages.erase(it);
                deleted = true;
                break;
            }
        }
    }
    reply->set_success(deleted);
    if (!deleted)
        reply->set_error_message("Message not found or unauthorized.");
    return Status::OK;
}

/**
 * @brief Implementation of DeleteAccount RPC.
 */
Status ChatServiceImpl::DeleteAccount(ServerContext* context, const chat::AccountRequest* request,
                                      chat::StatusReply* reply) {
    bool accountDeleted = false;
    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        auto it = userMap.find(request->username());
        if (it != userMap.end()) {
            userMap.erase(it);
            accountDeleted = true;
            std::cout << "[INFO] Deleted account for user " << request->username() << "\n";
        }
    }
    if (accountDeleted) {
        std::lock_guard<std::mutex> lock(messagesMutex);
        for(auto it = messages.begin(); it != messages.end(); ) {
            if(it->second.sender == request->username() || it->second.recipient == request->username()){
                it = messages.erase(it);
            } else {
                ++it;
            }
        }
    }
    reply->set_success(accountDeleted);
    if (!accountDeleted)
        reply->set_error_message("Account deletion failed.");
    return Status::OK;
}

/**
 * @brief Implementation of Quit RPC.
 */
Status ChatServiceImpl::Quit(ServerContext* context, const chat::Empty* request,
                             chat::StatusReply* reply) {
    reply->set_success(true);
    return Status::OK;
}

/**
 * @brief Helper function to read the entire contents of a file.
 * 
 * Used to load TLS certificates.
 * 
 * @param filename The file to read.
 * @return std::string Contents of the file.
 */
std::string ReadFile(const std::string &filename) {
    std::ifstream file(filename);
    if (!file)
        return "";
    return std::string((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
}

/**
 * @brief Starts the gRPC server with TLS credentials.
 * 
 * The server loads its certificate and key from disk and listens on the provided address.
 * 
 * @param server_address The address (e.g., "0.0.0.0:50051").
 */
void RunServer(const std::string& server_address) {
    ChatServiceImpl service;

    ServerBuilder builder;
    
    // Configure TLS credentials using gRPC's integrated support.
    grpc::SslServerCredentialsOptions sslOpts;
    std::string server_cert = ReadFile("server.crt");
    std::string server_key  = ReadFile("server.key");
    grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp = { server_key, server_cert };
    sslOpts.pem_key_cert_pairs.push_back(pkcp);

    auto creds = grpc::SslServerCredentials(sslOpts);
    builder.AddListeningPort(server_address, creds);
    
    builder.RegisterService(&service);
    
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "[INFO] gRPC Server listening on " << server_address << "\n";
    server->Wait();
}

int main(int argc, char* argv[]) {
    std::string server_address = "0.0.0.0:50051"; // Default address.
    RunServer(server_address);
    return 0;
}
