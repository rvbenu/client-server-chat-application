/*
 * server.cpp
 *
 * This server:
 * - Accepts a port number from the command line (default = 54000 if omitted).
 * - Listens for incoming client connections.
 * - Spawns a thread for each client.
 * - Uses a length-prefixed binary protocol with nlohmann::json + MessagePack.
 *
 * Compilation:
 *   clang++ -std=c++17 -pthread server.cpp -o server
 *
 * Usage:
 *   ./server <port>
 *   If <port> is omitted, defaults to 54000.
 */

#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <string>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

// Include the local json.hpp file from nlohmann/json
#include "json.hpp"
using json = nlohmann::json;

// Data Structures

// UserInfo holds data for each user: password, online status, socket, and offline messages.
struct UserInfo {
    std::string password;                      // In a production environment, store a hashed password.
    bool isOnline = false;                    // True if the user is currently connected.
    int socketFd = -1;                        // Socket file descriptor if the user is online.
    std::vector<std::string> offlineMessages; // Messages received while the user was offline.
};

// userMap stores all users by username. Access to userMap is protected by userMapMutex.
static std::unordered_map<std::string, UserInfo> userMap;
static std::mutex userMapMutex;

// Binary/JSON Functions

// Reads a 4-byte length prefix from the socket, then reads the exact number of bytes indicated.
// Returns the binary data as a string. Returns an empty string on error or disconnection.
std::string readLengthPrefixedData(int sockFd) {
    std::string buffer;
    uint32_t lengthNetworkOrder = 0;
    
    // Receive the 4-byte length prefix.
    ssize_t bytesReceived = recv(sockFd, &lengthNetworkOrder, sizeof(lengthNetworkOrder), 0);
    if (bytesReceived <= 0) {
        return buffer; // Return empty string on error or disconnect.
    }

    // Convert length from network byte order to host byte order.
    uint32_t lengthHostOrder = ntohl(lengthNetworkOrder);
    if (lengthHostOrder == 0) {
        return buffer; // Return empty string if message length is zero.
    }

    // Resize buffer to hold the incoming message.
    buffer.resize(lengthHostOrder, '\0');
    size_t totalRead = 0;

    // Continuously read from the socket until the entire message is received.
    while (totalRead < lengthHostOrder) {
        ssize_t chunk = recv(sockFd, &buffer[totalRead], lengthHostOrder - totalRead, 0);
        if (chunk <= 0) {
            buffer.clear(); // Clear buffer on error or disconnect.
            return buffer;
        }
        totalRead += chunk;
    }

    return buffer; // Successfully received the complete message.
}

// Converts binary data received from the socket into a JSON object using MessagePack.
// Returns an empty JSON object on failure.
json binaryToJson(int sockFd) {
    std::string data = readLengthPrefixedData(sockFd);
    if (data.empty()) {
        return json(); // Return empty JSON on failure.
    }
    try {
        std::vector<uint8_t> msgpackData(data.begin(), data.end());
        return json::from_msgpack(msgpackData);
    } catch (const std::exception& ex) {
        std::cerr << "MessagePack parse failed: " << ex.what() << std::endl;
        return json(); // Return empty JSON on parse failure.
    }
}

// Serializes a JSON object to MessagePack, prefixes it with its length, and sends it over the socket.
// Returns true if the entire message is sent successfully, false otherwise.
bool jsonToBinary(int sockFd, const json& j) {
    try {
        // Serialize JSON to MessagePack format.
        std::vector<uint8_t> msgpackData = json::to_msgpack(j);
        uint32_t lengthHostOrder = static_cast<uint32_t>(msgpackData.size());
        uint32_t lengthNetworkOrder = htonl(lengthHostOrder);

        // Send the 4-byte length prefix.
        ssize_t sent = send(sockFd, &lengthNetworkOrder, sizeof(lengthNetworkOrder), 0);
        if (sent != sizeof(lengthNetworkOrder)) {
            std::cerr << "Failed to send length prefix." << std::endl;
            return false;
        }

        // Send the binary MessagePack data.
        size_t totalSent = 0;
        while (totalSent < msgpackData.size()) {
            ssize_t chunk = send(sockFd, msgpackData.data() + totalSent, msgpackData.size() - totalSent, 0);
            if (chunk <= 0) {
                std::cerr << "Failed to send binary data chunk." << std::endl;
                return false;
            }
            totalSent += chunk;
        }
        return true; // Successfully sent the entire message.
    } catch (const std::exception& ex) {
        std::cerr << "to_msgpack failed: " << ex.what() << std::endl;
        return false; // Return false on serialization failure.
    }
}

// Helper Functions

// Sends all stored offline messages for a user. After sending, the messages are cleared.
void deliverOfflineMessages(const std::string& username, int sockFd) {
    std::vector<std::string> messages;
    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        auto it = userMap.find(username);
        if (it == userMap.end()) {
            return; // User does not exist.
        }
        // Move offline messages to a temporary vector.
        messages = std::move(it->second.offlineMessages);
        it->second.offlineMessages.clear();
    }

    // Send each offline message as a separate JSON object.
    for (const auto& msg : messages) {
        json j;
        j["op"] = "RECEIVE_MSG_OFFLINE";
        j["content"] = msg;
        jsonToBinary(sockFd, j);
    }
}

// Checks if a username exists and sends a response indicating its existence.
bool checkIfUserExists(int sockFd, const std::string& username) {
    bool exists = false;
    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        exists = (userMap.find(username) != userMap.end());
    }
    json response;
    response["op"] = "CHECK_USER_RES";
    response["exists"] = exists;
    return jsonToBinary(sockFd, response);
}

// Handles user login or registration based on the operation type.
// On success, marks the user as online and delivers any offline messages.
bool loginOrRegister(int sockFd, const std::string& username, const std::string& password, const std::string& op) {
    bool success = false;
    std::string status = "FAIL";

    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        if (op == "LOGIN") {
            auto it = userMap.find(username);
            if (it != userMap.end() && it->second.password == password) {
                it->second.isOnline = true;
                it->second.socketFd = sockFd;
                success = true;
                status = "SUCCESS";
            }
        } else if (op == "REGISTER") {
            auto it = userMap.find(username);
            if (it == userMap.end()) {
                UserInfo newUser;
                newUser.password = password;
                newUser.isOnline = true;
                newUser.socketFd = sockFd;
                userMap[username] = std::move(newUser);
                success = true;
                status = "SUCCESS";
            }
        }
    }

    json response;
    response["op"] = (op == "LOGIN") ? "LOGIN_RES" : "REGISTER_RES";
    response["status"] = status;
    bool ok = jsonToBinary(sockFd, response);

    if (success) {
        deliverOfflineMessages(username, sockFd);
    }
    return ok;
}

// Lists all users or those matching a search term and sends the list to the client.
bool listUsers(int sockFd, const std::string& searchTerm) {
    std::vector<std::string> matches;
    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        for (const auto& pair : userMap) {
            const std::string& uname = pair.first;
            if (searchTerm.empty() || uname.find(searchTerm) != std::string::npos) {
                matches.push_back(uname);
            }
        }
    }
    json response;
    response["op"] = "LIST_USERS_RES";
    response["users"] = matches;
    return jsonToBinary(sockFd, response);
}

// Sends a message from the sender to the recipient. If the recipient is offline,
// the message is stored for later delivery.
bool sendUserMessage(const std::string& sender, const std::string& recipient, const std::string& content) {
    std::string formatted = "[FROM " + sender + "]: " + content;
    std::lock_guard<std::mutex> lock(userMapMutex);
    auto it = userMap.find(recipient);
    if (it == userMap.end()) {
        return false; // Recipient does not exist.
    }
    if (it->second.isOnline) {
        int recSock = it->second.socketFd;
        json j;
        j["op"] = "RECEIVE_MSG";
        j["from"] = sender;
        j["content"] = content;
        return jsonToBinary(recSock, j);
    } else {
        it->second.offlineMessages.push_back(formatted);
        return true; // Message queued for offline delivery.
    }
}

// Handles message deletion requests. Currently, it simply acknowledges the request.
// Implement actual deletion logic based on how messages are stored.
bool deleteMessages(int sockFd, const std::string& username, const std::string& ids) {
    json response;
    response["op"] = "DELETE_MSG_RES";
    response["status"] = "SUCCESS";
    response["ids"] = ids;
    return jsonToBinary(sockFd, response);
}

// Thread Function

// Handles communication with a connected client. Processes incoming requests
// and sends appropriate responses based on the operation type.
void handleClient(int sockFd) {
    std::string currentUser;
    bool isAuthenticated = false;

    while (true) {
        json request = binaryToJson(sockFd);
        if (request.empty()) {
            std::cout << "Client disconnected or error." << std::endl;
            break;
        }

        std::string op;
        try {
            op = request.at("op").get<std::string>();
        } catch (...) {
            std::cerr << "JSON does not have 'op' field." << std::endl;
            continue;
        }

        if (op == "CHECK_USER") {
            std::string uname = request.value("username", "");
            if (!uname.empty()) {
                checkIfUserExists(sockFd, uname);
            }
        } else if (op == "LOGIN" || op == "REGISTER") {
            std::string uname = request.value("username", "");
            std::string pwd = request.value("password", "");
            if (!uname.empty() && !pwd.empty()) {
                loginOrRegister(sockFd, uname, pwd, op);
            }
        } else if (op == "LIST_USERS") {
            if (!isAuthenticated) {
                json err;
                err["op"] = "ERROR";
                err["message"] = "Not authenticated";
                jsonToBinary(sockFd, err);
                continue;
            }
            std::string searchTerm = request.value("search", "");
            listUsers(sockFd, searchTerm);
        } else if (op == "SEND_MSG") {
            if (!isAuthenticated) {
                json err;
                err["op"] = "ERROR";
                err["message"] = "Not authenticated";
                jsonToBinary(sockFd, err);
                continue;
            }
            std::string recipient = request.value("recipient", "");
            std::string content = request.value("content", "");
            if (!recipient.empty() && !content.empty()) {
                sendUserMessage(currentUser, recipient, content);
                
                // Acknowledge the message sending.
                json ack;
                ack["op"] = "SEND_MSG_RES";
                ack["status"] = "SUCCESS";
                jsonToBinary(sockFd, ack);
            }
        } else if (op == "DELETE_MSG") {
            if (!isAuthenticated) {
                json err;
                err["op"] = "ERROR";
                err["message"] = "Not authenticated";
                jsonToBinary(sockFd, err);
                continue;
            }
            std::string ids = request.value("ids", "");
            deleteMessages(sockFd, currentUser, ids);
        } else if (op == "QUIT") {
            std::cout << "Client requested quit." << std::endl;
            break;
        } else {
            // Unknown operation.
            json err;
            err["op"] = "ERROR";
            err["message"] = "Unrecognized operation: " + op;
            jsonToBinary(sockFd, err);
        }

        // Update authentication status if necessary.
        if ((op == "LOGIN" || op == "REGISTER") && request.value("status", "") == "SUCCESS") {
            std::lock_guard<std::mutex> lock(userMapMutex);
            auto it = userMap.find(request.value("username", ""));
            if (it != userMap.end() && it->second.password == request.value("password", "")) {
                isAuthenticated = true;
                currentUser = request.value("username", "");
            }
        }
    }

    // Mark the user as offline upon disconnection.
    if (!currentUser.empty()) {
        std::lock_guard<std::mutex> lock(userMapMutex);
        auto it = userMap.find(currentUser);
        if (it != userMap.end()) {
            it->second.isOnline = false;
            it->second.socketFd = -1;
        }
    }

    close(sockFd); // Close the client's socket.
}

// Main Function

int main(int argc, char* argv[]) {
    // Default port is 54000 if not specified.
    int port = 54000;
    if (argc >= 2) {
        port = std::atoi(argv[1]);
        if (port <= 0) {
            std::cerr << "Invalid port number. Using default port 54000." << std::endl;
            port = 54000;
        }
    }

    // Create a TCP socket.
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == -1) {
        perror("socket failed");
        return EXIT_FAILURE;
    }

    // Allow the socket to be reused immediately after the program terminates.
    int opt = 1;
    if (setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(serverSock);
        return EXIT_FAILURE;
    }

    // Bind the socket to the specified port on all available interfaces.
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;          // IPv4
    serverAddr.sin_addr.s_addr = INADDR_ANY;  // Bind to all interfaces
    serverAddr.sin_port = htons(port);        // Host to network byte order

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind failed");
        close(serverSock);
        return EXIT_FAILURE;
    }

    // Listen for incoming connections.
    if (listen(serverSock, SOMAXCONN) < 0) {
        perror("listen failed");
        close(serverSock);
        return EXIT_FAILURE;
    }

    std::cout << "Server listening on port " << port << "..." << std::endl;

    // Accept loop: continuously accept new client connections.
    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientSock < 0) {
            perror("accept failed");
            continue; // Continue accepting new connections.
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        std::cout << "New client connected from " << clientIP << ":" << ntohs(clientAddr.sin_port) << std::endl;

        // Launch a new thread to handle the connected client.
        std::thread clientThread(handleClient, clientSock);
        clientThread.detach(); // Detach the thread to allow independent execution.
    }

    close(serverSock); // Close the server socket (unreachable code in this example).
    return 0;
}
