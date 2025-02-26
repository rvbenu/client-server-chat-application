#ifndef SERVER_GRPC_H
#define SERVER_GRPC_H

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

/**
 * @brief Structure representing a chat message.
 */
struct Message {
    std::string id;         ///< Unique message identifier.
    std::string content;    ///< The message content.
    std::string sender;     ///< Sender's username.
    std::string recipient;  ///< Recipient's username.
};

/**
 * @brief Structure representing user information.
 */
struct UserInfo {
    std::string password;            ///< The hashed password.
    bool isOnline;                   ///< Online status.
    std::vector<Message> offlineMessages; ///< Offline messages waiting for the user.
};

// Global containers for users and messages.
extern std::unordered_map<std::string, UserInfo> userMap;  ///< Maps username to user info.
extern std::unordered_map<int, Message> messages;          ///< Maps message ID to message.
extern int messageCounter;                                 ///< Global counter for message IDs.

// Mutexes to protect the global containers.
extern std::mutex userMapMutex;
extern std::mutex messagesMutex;


/**
 * @brief Starts the gRPC server.
 *
 * @param server_address The address on which the server listens (e.g., "0.0.0.0:50051").
 */
void RunServer(const std::string& server_address);

#endif // SERVER_GRPC_H
