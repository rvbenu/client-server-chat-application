/*
 * server.cpp
 *
 * This server:
 *  - Accepts a port number from the command line (default=54000 if omitted).
 *  - Listens for incoming client connections (plain TCP).
 *  - Spawns a thread for each client.
 *  - Uses Argon2-based password hashing for secure password storage.
 *  - Uses a custom wire protocol with Packet-based key-value pairs (no JSON).
 *
 * Compilation:
 *   g++ -std=c++17 -pthread server.cpp custom_wire_protocol.cpp -largon2 -lssl -lcrypto -o server
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

// Argon2 and OpenSSL RAND
#include "argon2.h"
#include "rand.h"

// Our wire protocol interface (Packet struct, sendPacket, receivePacket)
#include "wire_protocol.h"

// Argon2 parameters
static const uint32_t T_COST = 2;          // number of iterations
static const uint32_t M_COST = (1 << 16);  // memory usage (64MB)
static const uint32_t PARALLELISM = 1;
static const size_t SALT_LEN = 16;
static const size_t HASH_LEN = 32;
static const size_t ENCODED_LEN = 128;

/**
 * @brief A simple user record with Argon2 hashed password, online state, and offline messages.
 */
struct UserInfo {
    std::string password;                      // Argon2 hashed (encoded) password
    bool isOnline = false;                     // True if user is connected
    int socketFd = -1;                         // Socket file descriptor
    std::vector<std::string> offlineMessages;  // queued messages while offline
};

// Global data structures
static std::unordered_map<std::string, UserInfo> userMap;
static std::mutex userMapMutex;

/**
 * @brief Generate an Argon2 hash for a plaintext password.
 * @param password The user's plaintext password
 * @return The Argon2-encoded hash string, or "" on error
 */
std::string argon2HashPassword(const std::string &password) {
    // Generate random salt
    unsigned char salt[SALT_LEN];
    if (RAND_bytes(salt, SALT_LEN) != 1) {
        std::cerr << "[ERROR] RAND_bytes failed to generate salt.\n";
        return "";
    }
    char encoded[ENCODED_LEN];
    int ret = argon2_hash(
        T_COST, M_COST, PARALLELISM,
        password.data(), password.size(),
        salt, SALT_LEN,
        nullptr, HASH_LEN,
        encoded, ENCODED_LEN,
        Argon2_id, ARGON2_VERSION_13
    );
    if (ret != ARGON2_OK) {
        std::cerr << "[ERROR] argon2_hash: " << argon2_error_message(ret) << std::endl;
        return "";
    }
    return std::string(encoded);
}

/**
 * @brief Verify a plaintext password against an Argon2-encoded hash.
 * @param encodedHash The Argon2 encoded hash stored in userMap
 * @param password The plaintext password
 * @return true if correct, false otherwise
 */
bool argon2CheckPassword(const std::string &encodedHash, const std::string &password) {
    int ret = argon2_verify(encodedHash.c_str(), password.data(), password.size(), Argon2_id);
    return (ret == ARGON2_OK);
}

/**
 * @brief Deliver offline messages to the user after successful login.
 */
void deliverOfflineMessages(const std::string &username, int sockFd) {
    std::vector<std::string> messages;
    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        auto it = userMap.find(username);
        if (it == userMap.end()) return;
        messages = std::move(it->second.offlineMessages);
        it->second.offlineMessages.clear();
    }
    for (auto &msg : messages) {
        Packet pkt;
        pkt.fields["op"]      = "RECEIVE_MSG_OFFLINE";
        pkt.fields["content"] = msg;
        sendPacket(sockFd, pkt);
    }
}

/**
 * @brief Check if a username exists and respond with "CHECK_USER_RES" = { "exists":"true"/"false" }.
 */
bool checkIfUserExists(int sockFd, const std::string &username) {
    bool exists = false;
    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        exists = (userMap.find(username) != userMap.end());
    }
    Packet resp;
    resp.fields["op"]     = "CHECK_USER_RES";
    resp.fields["exists"] = exists ? "true" : "false";
    return sendPacket(sockFd, resp);
}

/**
 * @brief Registration => hash password with Argon2, store encoded
 *        Login => verify Argon2
 */
bool loginOrRegister(int sockFd, const std::string &username, const std::string &password, const std::string &op) {
    bool success = false;
    std::string status = "FAIL";

    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        if (op == "LOGIN") {
            // login => check Argon2
            auto it = userMap.find(username);
            if (it != userMap.end()) {
                if (argon2CheckPassword(it->second.password, password)) {
                    it->second.isOnline = true;
                    it->second.socketFd = sockFd;
                    success = true;
                    status = "SUCCESS";
                }
            }
        } else if (op == "REGISTER") {
            // register => hash Argon2
            auto it = userMap.find(username);
            if (it == userMap.end()) {
                std::string encoded = argon2HashPassword(password);
                if (!encoded.empty()) {
                    UserInfo newUser;
                    newUser.password = encoded;
                    newUser.isOnline = true;
                    newUser.socketFd = sockFd;
                    userMap[username] = std::move(newUser);
                    success = true;
                    status = "SUCCESS";
                }
            }
        }
    }

    // respond
    Packet resp;
    resp.fields["op"]     = (op == "LOGIN") ? "LOGIN_RES" : "REGISTER_RES";
    resp.fields["status"] = status;
    sendPacket(sockFd, resp);

    // If success and op=LOGIN => deliver offline
    if (success && op == "LOGIN") {
        deliverOfflineMessages(username, sockFd);
    }
    return success;
}

/**
 * @brief Lists all users or those matching a searchTerm, sends result in a Packet.
 */
bool listUsers(int sockFd, const std::string &searchTerm) {
    std::vector<std::string> matches;
    {
        std::lock_guard<std::mutex> lock(userMapMutex);
        for (auto &kv : userMap) {
            const std::string &uname = kv.first;
            if (searchTerm.empty() || uname.find(searchTerm) != std::string::npos) {
                matches.push_back(uname);
            }
        }
    }
    // Build comma-separated or store them in a single field
    std::string userList;
    for (size_t i = 0; i < matches.size(); i++) {
        userList += matches[i];
        if (i + 1 < matches.size()) userList += ",";
    }
    Packet pkt;
    pkt.fields["op"]    = "LIST_USERS_RES";
    pkt.fields["users"] = userList;
    return sendPacket(sockFd, pkt);
}

/**
 * @brief Send message from sender to recipient. If offline, queue it. If online, send a "RECEIVE_MSG".
 */
bool sendUserMessage(const std::string &sender, const std::string &recipient, const std::string &content) {
    std::string msg = "[FROM " + sender + "]: " + content;
    std::lock_guard<std::mutex> lock(userMapMutex);
    auto it = userMap.find(recipient);
    if (it == userMap.end()) {
        return false;
    }
    if (it->second.isOnline) {
        Packet pkt;
        pkt.fields["op"]      = "RECEIVE_MSG";
        pkt.fields["from"]    = sender;
        pkt.fields["content"] = content;
        sendPacket(it->second.socketFd, pkt);
    } else {
        it->second.offlineMessages.push_back(msg);
    }
    return true;
}

/**
 * @brief Delete messages (placeholder).
 */
bool deleteMessages(int sockFd, const std::string &username, const std::string &ids) {
    Packet pkt;
    pkt.fields["op"]     = "DELETE_MSG_RES";
    pkt.fields["status"] = "SUCCESS";
    pkt.fields["ids"]    = ids;
    return sendPacket(sockFd, pkt);
}

/**
 * @brief The main per-client thread. Receives Packets, handles ops.
 */
void handleClient(int sockFd) {
    bool isAuthenticated = false;
    std::string currentUser;

    while (true) {
        Packet pkt = receivePacket(sockFd);
        if (pkt.fields.empty()) {
            std::cout << "[INFO] Client disconnected or error.\n";
            break;
        }
        auto it = pkt.fields.find("op");
        if (it == pkt.fields.end()) {
            std::cerr << "[ERROR] Packet missing 'op'.\n";
            continue;
        }
        const std::string &op = it->second;

        if (op == "QUIT") {
            std::cout << "[INFO] Client requested QUIT.\n";
            break;
        } else if (!isAuthenticated) {
            if (op == "CHECK_USER") {
                // e.g. { "op":"CHECK_USER", "username":"bob" }
                auto unameIt = pkt.fields.find("username");
                if (unameIt != pkt.fields.end()) {
                    checkIfUserExists(sockFd, unameIt->second);
                }
            } else if (op == "LOGIN" || op == "REGISTER") {
                std::string uname = pkt.fields.count("username") ? pkt.fields.at("username") : "";
                std::string pwd   = pkt.fields.count("password") ? pkt.fields.at("password") : "";
                if (!uname.empty() && !pwd.empty()) {
                    if (loginOrRegister(sockFd, uname, pwd, op)) {
                        isAuthenticated = true;
                        currentUser = uname;
                    }
                }
            } else {
                Packet err;
                err.fields["op"]      = "ERROR";
                err.fields["message"] = "Not authenticated";
                sendPacket(sockFd, err);
            }
        } else {
            // authenticated
            if (op == "LIST_USERS") {
                std::string st = pkt.fields.count("search") ? pkt.fields.at("search") : "";
                listUsers(sockFd, st);
            } else if (op == "SEND_MSG") {
                std::string rec = pkt.fields.count("recipient") ? pkt.fields.at("recipient") : "";
                std::string ctt = pkt.fields.count("content")   ? pkt.fields.at("content")   : "";
                if (!rec.empty() && !ctt.empty()) {
                    sendUserMessage(currentUser, rec, ctt);
                    Packet ack;
                    ack.fields["op"]     = "SEND_MSG_RES";
                    ack.fields["status"] = "SUCCESS";
                    sendPacket(sockFd, ack);
                }
            } else if (op == "DELETE_MSG") {
                std::string ids = pkt.fields.count("ids") ? pkt.fields.at("ids") : "";
                deleteMessages(sockFd, currentUser, ids);
            } else {
                Packet err;
                err.fields["op"]      = "ERROR";
                err.fields["message"] = "Unknown operation: " + op;
                sendPacket(sockFd, err);
            }
        }
    }

    // Mark user offline
    if (!currentUser.empty()) {
        std::lock_guard<std::mutex> lock(userMapMutex);
        auto it = userMap.find(currentUser);
        if (it != userMap.end()) {
            it->second.isOnline = false;
            it->second.socketFd = -1;
        }
    }
    close(sockFd);
}

/**
 * @brief main
 *  1) Creates a TCP socket
 *  2) Binds to the desired port
 *  3) Listens for incoming connections
 *  4) For each connection, spawns handleClient in a thread
 */
int main(int argc, char* argv[]) {
    // Optionally, initialize OpenSSL for RAND_bytes
    // e.g. ERR_load_crypto_strings(); or OpenSSL_add_all_algorithms(); if needed

    int port = 54000;
    if (argc >= 2) {
        port = std::atoi(argv[1]);
        if (port <= 0) {
            std::cerr << "Invalid port. Using default 54000.\n";
            port = 54000;
        }
    }

    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        perror("socket failed");
        return EXIT_FAILURE;
    }
    int opt = 1;
    if (setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(serverSock);
        return EXIT_FAILURE;
    }

    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port        = htons(port);

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind failed");
        close(serverSock);
        return EXIT_FAILURE;
    }
    if (listen(serverSock, SOMAXCONN) < 0) {
        perror("listen failed");
        close(serverSock);
        return EXIT_FAILURE;
    }

    std::cout << "[INFO] Server listening on port " << port << "...\n";

    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientSock < 0) {
            perror("accept failed");
            continue;
        }
        char ipBuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), ipBuf, sizeof(ipBuf));
        std::cout << "[INFO] New client from " << ipBuf << ":" << ntohs(clientAddr.sin_port) << "\n";

        std::thread t(handleClient, clientSock);
        t.detach();
    }

    close(serverSock);
    return 0;
}
