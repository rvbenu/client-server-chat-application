#include <iostream>
#include <sstream>
#include <string>
#include <grpcpp/grpcpp.h>
#include "client_grpc.h"
#include "user_auth/user_auth.h"  // Use Argon2 functions for password hashing

// Implementation of ChatClient methods
ChatClient::ChatClient(std::shared_ptr<grpc::Channel> channel)
    : stub_(chat::ChatService::NewStub(channel)) {}

bool ChatClient::Register(const std::string& username, const std::string& password) {
    chat::RegisterRequest request;
    request.set_username(username);
    std::string hashedPassword = argon2HashPassword(password);
    request.set_password(hashedPassword);
    chat::StatusReply reply;
    grpc::ClientContext context;
    grpc::Status status = stub_->Register(&context, request, &reply);
    if (status.ok() && reply.success()) {
        std::cout << "[CLIENT] Registration successful." << std::endl;
        return true;
    } else {
        std::cerr << "[CLIENT] Registration failed: " << reply.error_message() << std::endl;
        return false;
    }
}

bool ChatClient::Login(const std::string& username, const std::string& password) {
    chat::LoginRequest request;
    request.set_username(username);
    std::string hashedPassword = argon2HashPassword(password);
    request.set_password(hashedPassword);
    chat::LoginReply reply;
    grpc::ClientContext context;
    grpc::Status status = stub_->Login(&context, request, &reply);
    if (status.ok() && reply.success()) {
        std::cout << "[CLIENT] Login successful. Unread messages: " << reply.unread_messages() << std::endl;
        return true;
    } else {
        std::cerr << "[CLIENT] Login failed: " << reply.error_message() << std::endl;
        return false;
    }
}

bool ChatClient::SendMessage(const std::string& sender, const std::string& recipient, const std::string& message) {
    chat::MessageRequest request;
    request.set_sender(sender);
    request.set_recipient(recipient);
    request.set_message(message);
    chat::StatusReply reply;
    grpc::ClientContext context;
    grpc::Status status = stub_->SendMessage(&context, request, &reply);
    if (status.ok() && reply.success()) {
        std::cout << "[CLIENT] Message sent successfully." << std::endl;
        return true;
    } else {
        std::cerr << "[CLIENT] Failed to send message: " << reply.error_message() << std::endl;
        return false;
    }
}

void ChatClient::RetrieveOfflineMessages(const std::string& username, int count) {
    chat::OfflineRequest request;
    request.set_username(username);
    request.set_count(count);
    request.set_mark_as_read(true);
    chat::OfflineReply reply;
    grpc::ClientContext context;
    grpc::Status status = stub_->RetrieveOfflineMessages(&context, request, &reply);
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

void ChatClient::MessageHistory(const std::string& username) {
    chat::HistoryRequest request;
    request.set_username(username);
    chat::HistoryReply reply;
    grpc::ClientContext context;
    grpc::Status status = stub_->MessageHistory(&context, request, &reply);
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

void ChatClient::ListUsers(const std::string& pattern) {
    chat::UserListRequest request;
    request.set_pattern(pattern);
    chat::UserListReply reply;
    grpc::ClientContext context;
    grpc::Status status = stub_->ListUsers(&context, request, &reply);
    if (status.ok()) {
        std::cout << "[CLIENT] Users matching '" << pattern << "':" << std::endl;
        for (const auto &user : reply.usernames()) {
            std::cout << "  " << user << std::endl;
        }
    } else {
        std::cerr << "[CLIENT] Failed to list users." << std::endl;
    }
}

bool ChatClient::DeleteMessage(const std::string& username, const std::string& message_id) {
    chat::DeleteMessageRequest request;
    request.set_username(username);
    request.set_message_id(message_id);
    chat::StatusReply reply;
    grpc::ClientContext context;
    grpc::Status status = stub_->DeleteMessage(&context, request, &reply);
    if (status.ok() && reply.success()) {
        std::cout << "[CLIENT] Message deleted successfully." << std::endl;
        return true;
    } else {
        std::cerr << "[CLIENT] Failed to delete message: " << reply.error_message() << std::endl;
        return false;
    }
}

bool ChatClient::DeleteAccount(const std::string& username) {
    chat::AccountRequest request;
    request.set_username(username);
    chat::StatusReply reply;
    grpc::ClientContext context;
    grpc::Status status = stub_->DeleteAccount(&context, request, &reply);
    if (status.ok() && reply.success()) {
        std::cout << "[CLIENT] Account deleted successfully." << std::endl;
        return true;
    } else {
        std::cerr << "[CLIENT] Failed to delete account: " << reply.error_message() << std::endl;
        return false;
    }
}

bool ChatClient::Quit() {
    chat::Empty request;
    chat::StatusReply reply;
    grpc::ClientContext context;
    grpc::Status status = stub_->Quit(&context, request, &reply);
    if (status.ok() && reply.success()) {
        std::cout << "[CLIENT] Quit successfully." << std::endl;
        return true;
    } else {
        std::cerr << "[CLIENT] Quit failed." << std::endl;
        return false;
    }
}

// Main client function
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <server_address> <server_port>\n";
        return 1;
    }
    std::string server_address = argv[1] + std::string(":") + argv[2];

    // Set up TLS credentials using gRPC's integrated support.
    grpc::SslCredentialsOptions sslOpts;
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
