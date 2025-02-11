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
 *   clang++ -std=c++17 -pthread -I server.cpp -o server
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
#include "json.hpp"

using json = nlohmann::json;

// Data Structures

struct UserInfo {
    std::string password;
    bool isOnline = false;
    int socketFd = -1;
    std::vector<std::string> offlineMessages;
};

static std::unordered_map<std::string, UserInfo> userMap;
static std::mutex userMapMutex;

// Binary/JSON Functions

// Reads a 4-byte length prefix from the socket, then reads the exact number of bytes
// indicated by that length. Returns the binary data as a string. If an error occurs,
// an empty string is returned.
std::string readLengthPrefixedData(int sockFd) {
    std::string buffer;
    uint32_t lengthNetworkOrder = 0;
    ssize_t bytesReceived = recv(sockFd, &lengthNetworkOrder, sizeof(lengthNetworkOrder), 0);
    if (bytesReceived <= 0) {
        return buffer;
    }

    uint32_t lengthHostOrder = ntohl(lengthNetworkOrder);
    if (lengthHostOrder == 0) {
        return buffer;
    }

    buffer.resize(lengthHostOrder, '\0');
    size_t totalRead = 0;
    while (totalRead < lengthHostOrder) {
        ssize_t chunk = recv(sockFd, &buffer[totalRead], lengthHostOrder - totalRead, 0);
        if (chunk <= 0) {
            buffer.clear();
            return buffer;
        }
        totalRead += chunk;
    }
    return buffer;
}

// Reads binary data from the socket, interprets it as MessagePack, and converts it into a JSON object.
// If an error occurs during reading or parsing, an empty JSON object is returned.
json binaryToJson(int sockFd) {
    std::string data = readLengthPrefixedData(sockFd);
    if (data.empty()) {
        return json();
    }
    try {
        std::vector<uint8_t> msgpackData(data.begin(), data.end());
        return json::from_msgpack(msgpackData);
    } catch (const std::exception& ex) {
        std::cerr << "MessagePack parse failed: " << ex.what() << std::endl;
        return json();
    }
}

// Converts a JSON object to MessagePack format, sends a 4-byte length prefix, then sends the binary data.
// Returns true if the entire message is sent successfully, otherwise returns false.
bool jsonToBinary(int sockFd, const json& j) {
    try {
        std::vector<uint8_t> msgpackData = json::to_msgpack(j);
        uint32_t lengthHostOrder = static_cast<uint32_t>(msgpackData.size());
        uint32_t lengthNetworkOrder = htonl(lengthHostOrder);

        ssize_t sent = send(sockFd, &lengthNetworkOrder, sizeof(lengthNetworkOrder), 0);
        if (sent != sizeof(lengthNetworkOrder)) {
            std::cerr << "Failed to send length prefix." << std::endl;
            return false;
        }

        size_t totalSent = 0;
        while (totalSent < msgpackData.size()) {
            ssize_t chunk = send(sockFd, msgpackData.data() + totalSent, msgpackData.size() - totalSent, 0);
            if (chunk <= 0) {
                std::cerr << "Failed to send binary data chunk." << std::endl;
                return false;
            }
            totalSent += chunk;
        }
        return true;
    } catch (const std::exception& ex) {
        std::cerr << "to_msgpack failed: " << ex.what() << std::endl;
        return false;
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
            return;
        }
        messages = std::move(it->second.offlineMessages);
        it->second.offlineMessages.clear();
    }

    for (const auto& msg : messages) {
        json j;
        j["op"] = "RECEIVE_MSG_OFFLINE";
        j["content"] = msg;
        jsonToBinary(sockFd, j);
    }
}

// Checks if a username exists in userMap and sends a response indicating whether it exists.
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

// Handles login or registration. If successful, the user is marked online and any offline messages are delivered.
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

// Thread Function

// Runs in a thread, continuously handling client requests. Breaks on "QUIT" or disconnection.
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
        } else if (op == "QUIT") {
            break;
        }
    }

    close(sockFd);
}

int main(int argc, char* argv[]) {
    std::cout << "Server is running..." << std::endl;
}
