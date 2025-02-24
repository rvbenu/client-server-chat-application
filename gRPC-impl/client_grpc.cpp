#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <grpcpp/grpcpp.h>
#include "chat.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using chat::ChatService;
using chat::RegisterRequest;
using chat::LoginRequest;
using chat::MessageRequest;
using chat::OfflineRequest;
using chat::OfflineReply;
using chat::HistoryRequest;
using chat::HistoryReply;
using chat::UserListRequest;
using chat::UserListReply;
using chat::DeleteMessageRequest;
using chat::AccountRequest;
using chat::Empty;
using chat::StatusReply;
using chat::LoginReply;

//-----------------------------------------------------------------------------
// ChatClient: Wraps gRPC stub and provides helper methods for each RPC.
//-----------------------------------------------------------------------------
class ChatClient {
public:
    ChatClient(std::shared_ptr<Channel> channel)
        : stub_(ChatService::NewStub(channel)) {}

    bool Register(const std::string& username, const std::string& password) {
        RegisterRequest request;
        request.set_username(username);
        request.set_password(password);
        StatusReply reply;
        ClientContext context;
        Status status = stub_->Register(&context, request, &reply);
        if (status.ok() && reply.success()) {
            std::cout << "[CLIENT] Registration successful." << std::endl;
            return true;
        } else {
            std::cerr << "[CLIENT] Registration failed: " << reply.error_message() << std::endl;
            return false;
        }
    }

    bool Login(const std::string& username, const std::string& password) {
        LoginRequest request;
        request.set_username(username);
        request.set_password(password);
        LoginReply reply;
        ClientContext context;
        Status status = stub_->Login(&context, request, &reply);
        if (status.ok() && reply.success()) {
            std::cout << "[CLIENT] Login successful." << std::endl;
            return true;
        } else {
            std::cerr << "[CLIENT] Login failed: " << reply.error_message() << std::endl;
            return false;
        }
    }

    bool SendMessage(const std::string& sender, const std::string& recipient, const std::string& message) {
        MessageRequest request;
        request.set_sender(sender);
        request.set_recipient(recipient);
        request.set_message(message);
        StatusReply reply;
        ClientContext context;
        Status status = stub_->SendMessage(&context, request, &reply);
        if (status.ok() && reply.success()) {
            std::cout << "[CLIENT] Message sent successfully." << std::endl;
            return true;
        } else {
            std::cerr << "[CLIENT] Failed to send message: " << reply.error_message() << std::endl;
            return false;
        }
    }

    void RetrieveOfflineMessages(const std::string& username, int count) {
        OfflineRequest request;
        request.set_username(username);
        request.set_count(count);
        OfflineReply reply;
        ClientContext context;
        Status status = stub_->RetrieveOfflineMessages(&context, request, &reply);
        if (status.ok()) {
            std::cout << "[CLIENT] Retrieved offline messages:" << std::endl;
            for (const auto &msg : reply.messages()) {
                std::cout << "  From: " << msg.sender() 
                          << " | To: " << msg.recipient()
                          << " | Message: " << msg.content()
                          << " [ID: " << msg.id() << "]" << std::endl;
            }
        } else {
            std::cerr << "[CLIENT] Failed to retrieve offline messages." << std::endl;
        }
    }

    void MessageHistory(const std::string& username) {
        HistoryRequest request;
        request.set_username(username);
        HistoryReply reply;
        ClientContext context;
        Status status = stub_->MessageHistory(&context, request, &reply);
        if (status.ok()) {
            std::cout << "[CLIENT] Message history:" << std::endl;
            for (const auto &msg : reply.messages()) {
                std::cout << "  From: " << msg.sender() 
                          << " | To: " << msg.recipient()
                          << " | Message: " << msg.content()
                          << " [ID: " << msg.id() << "]" << std::endl;
            }
        } else {
            std::cerr << "[CLIENT] Failed to retrieve message history." << std::endl;
        }
    }

    void ListUsers(const std::string& pattern) {
        UserListRequest request;
        request.set_pattern(pattern);
        UserListReply reply;
        ClientContext context;
        Status status = stub_->ListUsers(&context, request, &reply);
        if (status.ok()) {
            std::cout << "[CLIENT] Users matching '" << pattern << "':" << std::endl;
            for (const auto &user : reply.usernames()) {
                std::cout << "  " << user << std::endl;
            }
        } else {
            std::cerr << "[CLIENT] Failed to list users." << std::endl;
        }
    }

    bool DeleteMessage(const std::string& username, const std::string& message_id) {
        DeleteMessageRequest request;
        request.set_username(username);
        request.set_message_id(message_id);
        StatusReply reply;
        ClientContext context;
        Status status = stub_->DeleteMessage(&context, request, &reply);
        if (status.ok() && reply.success()) {
            std::cout << "[CLIENT] Message deleted successfully." << std::endl;
            return true;
        } else {
            std::cerr << "[CLIENT] Failed to delete message: " << reply.error_message() << std::endl;
            return false;
        }
    }

    bool DeleteAccount(const std::string& username) {
        AccountRequest request;
        request.set_username(username);
        StatusReply reply;
        ClientContext context;
        Status status = stub_->DeleteAccount(&context, request, &reply);
        if (status.ok() && reply.success()) {
            std::cout << "[CLIENT] Account deleted successfully." << std::endl;
            return true;
        } else {
            std::cerr << "[CLIENT] Failed to delete account: " << reply.error_message() << std::endl;
            return false;
        }
    }

    bool Quit() {
        Empty request;
        StatusReply reply;
        ClientContext context;
        Status status = stub_->Quit(&context, request, &reply);
        if (status.ok() && reply.success()) {
            std::cout << "[CLIENT] Quit successfully." << std::endl;
            return true;
        } else {
            std::cerr << "[CLIENT] Quit failed." << std::endl;
            return false;
        }
    }

private:
    std::unique_ptr<ChatService::Stub> stub_;
};

//-----------------------------------------------------------------------------
// Main Client Function: Reads commands from standard input and calls RPCs.
//-----------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <server_address> <server_port>\n";
        return 1;
    }
    std::string server_address = argv[1] + std::string(":") + argv[2];

    // Set up TLS credentials for the client.
    grpc::SslCredentialsOptions sslOpts;
    // (Optional) Set sslOpts.pem_root_certs to verify the server certificate.
    auto channel = grpc::CreateChannel(server_address, grpc::SslCredentials(sslOpts));
    ChatClient client(channel);

    std::cout << "[CLIENT] Connected to gRPC server at " << server_address << "\n";
    std::cout << "Commands:\n";
    std::cout << "  L <username> <password>        : Login\n";
    std::cout << "  R <username> <password>        : Register\n";
    std::cout << "  s <sender> <recipient> <message>: Send Message\n";
    std::cout << "  r <username> <count>           : Retrieve Offline Messages\n";
    std::cout << "  h <username>                   : Message History\n";
    std::cout << "  l <pattern>                    : List Users\n";
    std::cout << "  d <username> <message_id>      : Delete Message\n";
    std::cout << "  D <username>                   : Delete Account\n";
    std::cout << "  q                              : Quit\n";

    std::string input;
    while (std::getline(std::cin, input)) {
        if (input.empty()) continue;
        std::istringstream iss(input);
        std::string command;
        iss >> command;
        if (command == "L") {
            std::string username, password;
            iss >> username >> password;
            client.Login(username, password);
        } else if (command == "R") {
            std::string username, password;
            iss >> username >> password;
            client.Register(username, password);
        } else if (command == "s") {
            std::string sender, recipient, message;
            iss >> sender >> recipient;
            std::getline(iss, message);
            if (!message.empty() && message[0] == ' ')
                message.erase(0, 1);
            client.SendMessage(sender, recipient, message);
        } else if (command == "r") {
            std::string username;
            int count;
            iss >> username >> count;
            client.RetrieveOfflineMessages(username, count);
        } else if (command == "h") {
            std::string username;
            iss >> username;
            client.MessageHistory(username);
        } else if (command == "l") {
            std::string pattern;
            iss >> pattern;
            client.ListUsers(pattern);
        } else if (command == "d") {
            std::string username, message_id;
            iss >> username >> message_id;
            client.DeleteMessage(username, message_id);
        } else if (command == "D") {
            std::string username;
            iss >> username;
            client.DeleteAccount(username);
            break; // Exit after account deletion.
        } else if (command == "q") {
            client.Quit();
            break;
        } else {
            std::cerr << "[CLIENT] Unknown command: " << command << "\n";
        }
    }
    return 0;
}
