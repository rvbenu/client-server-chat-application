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
#include "user_auth/user_auth.h"  // For argon2HashPassword(), argon2CheckPassword()
#include "../server.h"              // Global containers: userMap, messages, messageCounter, userMapMutex, messagesMutex

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using chat::ChatService;
using chat::RegisterRequest;
using chat::LoginRequest;
using chat::MessageRequest;
using chat::OfflineRequest;
using chat::HistoryRequest;
using chat::UserListRequest;
using chat::DeleteMessageRequest;
using chat::AccountRequest;
using chat::Empty;
using chat::LoginReply;
using chat::StatusReply;
using chat::OfflineReply;
using chat::HistoryReply;
using chat::UserListReply;
using chat::MessageData;

// Implementation using gRPC (with TLS)
class ChatServiceImpl final : public ChatService::Service {
public:
    // Registration RPC
    Status Register(ServerContext* context, const RegisterRequest* request,
                    StatusReply* reply) override {
        std::lock_guard<std::mutex> lock(userMapMutex);
        if (userMap.find(request->username()) != userMap.end()) {
            reply->set_success(false);
            reply->set_error_message("Username already exists.");
            return Status::OK;
        }
        // Create a new user and hash the password (using your Argon2 function)
        UserInfo newUser;
        newUser.password = argon2HashPassword(request->password());
        newUser.isOnline = true;
        userMap[request->username()] = std::move(newUser);
        std::cout << "[INFO] User '" << request->username() << "' registered via gRPC.\n";
        reply->set_success(true);
        return Status::OK;
    }

    // Login RPC
    Status Login(ServerContext* context, const LoginRequest* request,
                 LoginReply* reply) override {
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
        return Status::OK;
    }

    // SendMessage RPC
    Status SendMessage(ServerContext* context, const MessageRequest* request,
                       StatusReply* reply) override {
        std::string message_id;
        {
            std::lock_guard<std::mutex> lock(messagesMutex);
            messageCounter++;
            message_id = std::to_string(messageCounter);
            // Save message to global container
            messages[messageCounter] = { message_id, request->message(),
                                         request->sender(), request->recipient() };
        }
        bool validRecipient = false;
        {
            std::lock_guard<std::mutex> lock(userMapMutex);
            auto it = userMap.find(request->recipient());
            if (it != userMap.end()) {
                validRecipient = true;
                // If recipient is offline, add to offline messages
                if (!it->second.isOnline) {
                    Message offlineMsg = { message_id, request->message(), request->sender(), request->recipient() };
                    it->second.offlineMessages.push_back(offlineMsg);
                    std::cout << "[INFO] Stored offline message for '" << request->recipient() << "'.\n";
                }
                // (Optional) If recipient is online, you can push a notification via a streaming RPC.
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

    // RetrieveOfflineMessages RPC
    Status RetrieveOfflineMessages(ServerContext* context, const OfflineRequest* request,
                                   OfflineReply* reply) override {
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
                // Remove delivered messages
                if (count > 0)
                    it->second.offlineMessages.erase(it->second.offlineMessages.begin(),
                                                     it->second.offlineMessages.begin() + count);
            }
        }
        for (const auto &msg : messagesToSend) {
            MessageData* m = reply->add_messages();
            m->set_id(msg.id);
            m->set_sender(msg.sender);
            m->set_recipient(msg.recipient);
            m->set_content(msg.content);
        }
        return Status::OK;
    }

    // MessageHistory RPC
    Status MessageHistory(ServerContext* context, const HistoryRequest* request,
                          HistoryReply* reply) override {
        std::vector<std::pair<int, Message>> historyMessages;
        {
            std::lock_guard<std::mutex> lock(messagesMutex);
            for (const auto &kv : messages) {
                const Message &msg = kv.second;
                if (msg.sender == request->username() || msg.recipient == request->username())
                    historyMessages.push_back(kv);
            }
        }
        // Sort by message ID (assuming lower IDs are older)
        std::sort(historyMessages.begin(), historyMessages.end(),
                  [](const std::pair<int, Message>& a, const std::pair<int, Message>& b) {
                      return a.first < b.first;
                  });
        for (const auto &p : historyMessages) {
            MessageData* m = reply->add_messages();
            m->set_id(p.second.id);
            m->set_sender(p.second.sender);
            m->set_recipient(p.second.recipient);
            m->set_content(p.second.content);
        }
        return Status::OK;
    }

    // ListUsers RPC
    Status ListUsers(ServerContext* context, const UserListRequest* request,
                     UserListReply* reply) override {
        std::lock_guard<std::mutex> lock(userMapMutex);
        for (const auto &kv : userMap) {
            if (request->pattern().empty() ||
                (kv.first.find(request->pattern()) != std::string::npos))
                reply->add_usernames(kv.first);
        }
        return Status::OK;
    }

    // DeleteMessage RPC
    Status DeleteMessage(ServerContext* context, const DeleteMessageRequest* request,
                         StatusReply* reply) override {
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

    // DeleteAccount RPC
    Status DeleteAccount(ServerContext* context, const AccountRequest* request,
                         StatusReply* reply) override {
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
        reply->set_success(accountDeleted);
        if (!accountDeleted)
            reply->set_error_message("Account deletion failed.");
        return Status::OK;
    }

    // Quit RPC (for cleanup, if needed)
    Status Quit(ServerContext* context, const Empty* request,
                StatusReply* reply) override {
        // (Perform any cleanup if needed.)
        reply->set_success(true);
        return Status::OK;
    }
};

//-----------------------------------------------------------------------------
// Helper to read a file into a string (for TLS credentials)
//-----------------------------------------------------------------------------
std::string ReadFile(const std::string &filename) {
    std::ifstream file(filename);
    if (!file)
        return "";
    return std::string((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
}

//-----------------------------------------------------------------------------
// Main: Start the gRPC server with TLS credentials
//-----------------------------------------------------------------------------
void RunServer(const std::string& server_address) {
    ChatServiceImpl service;

    ServerBuilder builder;
    
    // Configure TLS credentials
    grpc::SslServerCredentialsOptions sslOpts;
    std::string server_cert = ReadFile("server.crt");
    std::string server_key  = ReadFile("server.key");
    // Optionally, include a root certificate for client auth:
    // std::string root_cert   = ReadFile("ca.crt");
    grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp = { server_key, server_cert };
    sslOpts.pem_key_cert_pairs.push_back(pkcp);
    // sslOpts.pem_root_certs = root_cert; // if needed for client certificate verification

    auto creds = grpc::SslServerCredentials(sslOpts);
    builder.AddListeningPort(server_address, creds);
    
    builder.RegisterService(&service);
    
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "[INFO] gRPC Server listening on " << server_address << "\n";
    server->Wait();
}

int main(int argc, char* argv[]) {
    std::string server_address = "0.0.0.0:50051"; // default
    RunServer(server_address);
    return 0;
}
