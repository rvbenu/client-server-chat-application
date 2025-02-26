#ifndef CLIENT_GRPC_H
#define CLIENT_GRPC_H

#include <memory>
#include <string>
#include "chat.grpc.pb.h"

/**
 * @brief ChatClient wraps the gRPC stub and provides helper methods to interact with the ChatService.
 */
class ChatClient {
public:
    /**
     * @brief Constructs a ChatClient using the given gRPC channel.
     * 
     * @param channel Shared pointer to a gRPC channel.
     */
    ChatClient(std::shared_ptr<grpc::Channel> channel);

    /**
     * @brief Registers a new user.
     * 
     * @param username The desired username.
     * @param password The plaintext password.
     * @return true if registration succeeds.
     */
    bool Register(const std::string& username, const std::string& password);

    /**
     * @brief Logs in an existing user.
     * 
     * @param username The username.
     * @param password The plaintext password.
     * @return true if login succeeds.
     */
    bool Login(const std::string& username, const std::string& password);

    /**
     * @brief Sends a message from a sender to a recipient.
     * 
     * @param sender The sender's username.
     * @param recipient The recipient's username.
     * @param message The message content.
     * @return true if the message is sent successfully.
     */
    bool SendMessage(const std::string& sender, const std::string& recipient, const std::string& message);

    /**
     * @brief Retrieves offline messages for a user.
     * 
     * @param username The username.
     * @param count Number of messages to retrieve.
     */
    void RetrieveOfflineMessages(const std::string& username, int count);

    /**
     * @brief Retrieves the complete message history for a user.
     * 
     * @param username The username.
     */
    void MessageHistory(const std::string& username);

    /**
     * @brief Lists users whose usernames match a given pattern.
     * 
     * @param pattern The pattern to match.
     */
    void ListUsers(const std::string& pattern);

    /**
     * @brief Deletes a specific message.
     * 
     * @param username The username.
     * @param message_id The ID of the message to delete.
     * @return true if deletion is successful.
     */
    bool DeleteMessage(const std::string& username, const std::string& message_id);

    /**
     * @brief Deletes a user account.
     * 
     * @param username The username.
     * @return true if account deletion is successful.
     */
    bool DeleteAccount(const std::string& username);

    /**
     * @brief Signals the server to quit.
     * 
     * @return true if the quit command succeeds.
     */
    bool Quit();

private:
    std::unique_ptr<chat::ChatService::Stub> stub_;
};

#endif // CLIENT_GRPC_H
