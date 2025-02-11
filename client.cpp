/*
 * client.cpp
 *
 * This client:
 * - Connects to a specified server IP and port (both taken from command-line args).
 * - Uses a length-prefixed binary protocol with nlohmann::json + MessagePack.
 * - Authenticates with the server, then provides commands for listing users,
 *   sending messages, deleting messages, and quitting.
 *
 * Compilation:
 *   g++ -std=c++17 -pthread -I. client.cpp -o client
 * Usage:
 *   ./client <server IP> <port>
 *   Example: ./client 127.0.0.1 54000
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <iostream>
#include <thread>
#include <string>
#include <cstring>
#include <vector>
#include <cerrno>
#include <cstdlib>

// If you have a single-header "json.hpp", include it like this:
// #include "json.hpp"
// Otherwise, if installed system-wide, do:
// #include <nlohmann/json.hpp>

#include "json.hpp"
using json = nlohmann::json;

// Reads a 4-byte length prefix (network byte order) from the socket, then reads
// that many bytes into a string. Returns an empty string on error or disconnection.
std::string readLengthPrefixedData(int sockFd) {
    std::string buffer;
    uint32_t lengthNetworkOrder = 0;
    ssize_t n = recv(sockFd, &lengthNetworkOrder, sizeof(lengthNetworkOrder), 0);
    if (n <= 0) {
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

// Reads binary data from the socket, interprets it as MessagePack, and converts
// it into a JSON object. Returns an empty JSON object if reading or parsing fails.
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

// Converts a JSON object to MessagePack, sends a 4-byte length prefix, then sends
// the binary data. Returns true if successfully sent, false on error.
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
            ssize_t chunk = send(sockFd,
                                 msgpackData.data() + totalSent,
                                 msgpackData.size() - totalSent,
                                 0);
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

// Continuously reads JSON messages (as MessagePack) from the server.
// If reading fails, it ends the thread.
void receiverThreadFunc(int sockFd) {
    while (true) {
        json response = binaryToJson(sockFd);
        if (response.empty()) {
            std::cout << "Connection closed or read error. Receiver thread ending." << std::endl;
            break;
        }
        std::cout << "[SERVER] " << response.dump(2) << std::endl;
    }
}

// Prompts the user for a username. Checks if it exists on the server. Then prompts
// for a password and attempts LOGIN or REGISTER. Returns 0 on success, -1 on failure.
int clientAuthenticate(int sockFd) {
    std::cout << "Enter your username: ";
    std::string username;
    std::getline(std::cin, username);

    json checkUserReq;
    checkUserReq["op"]       = "CHECK_USER";
    checkUserReq["username"] = username;

    if (!jsonToBinary(sockFd, checkUserReq)) {
        return -1;
    }

    json checkUserRes = binaryToJson(sockFd);
    if (checkUserRes.empty()) {
        std::cerr << "No response to CHECK_USER." << std::endl;
        return -1;
    }

    bool exists = false;
    try {
        exists = checkUserRes.at("exists").get<bool>();
    } catch (...) {
        std::cerr << "Malformed CHECK_USER response." << std::endl;
        return -1;
    }

    std::cout << "Enter your password: ";
    std::string password;
    std::getline(std::cin, password);

    json authReq;
    authReq["op"]       = exists ? "LOGIN" : "REGISTER";
    authReq["username"] = username;
    authReq["password"] = password;

    if (!jsonToBinary(sockFd, authReq)) {
        return -1;
    }

    json authRes = binaryToJson(sockFd);
    if (authRes.empty()) {
        std::cerr << "No response to LOGIN/REGISTER." << std::endl;
        return -1;
    }

    try {
        std::string status = authRes.at("status").get<std::string>();
        if (status == "SUCCESS") {
            std::cout << "Authentication successful." << std::endl;
            return 0;
        } else {
            std::cerr << "Authentication failed: " << status << std::endl;
            return -1;
        }
    } catch (...) {
        std::cerr << "Malformed LOGIN/REGISTER response." << std::endl;
        return -1;
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server IP> <port>" << std::endl;
        return 1;
    }
    const char* serverIP = argv[1];
    const char* serverPort = argv[2];

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* addrResult = nullptr;
    int rv = getaddrinfo(serverIP, serverPort, &hints, &addrResult);
    if (rv != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return 1;
    }

    int clientSock = -1;
    for (auto p = addrResult; p != nullptr; p = p->ai_next) {
        clientSock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (clientSock == -1) {
            continue;
        }
        if (connect(clientSock, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        close(clientSock);
        clientSock = -1;
    }
    freeaddrinfo(addrResult);

    if (clientSock == -1) {
        std::cerr << "Unable to connect to " << serverIP << ":" << serverPort << std::endl;
        return 1;
    }
    std::cout << "Connected to " << serverIP << " on port " << serverPort << std::endl;

    if (clientAuthenticate(clientSock) != 0) {
        std::cerr << "Authentication failed. Exiting." << std::endl;
        close(clientSock);
        return 1;
    }

    std::thread receiver(receiverThreadFunc, clientSock);

    while (true) {
        std::cout << "\nCommands:\n"
                  << "  L: list users\n"
                  << "  S: send message\n"
                  << "  D: delete messages\n"
                  << "  Q: quit\n"
                  << "Enter Command: ";

        std::string command;
        if (!std::getline(std::cin, command)) {
            break;
        }

        if (command == "Q" || command == "q") {
            json quitMsg;
            quitMsg["op"] = "QUIT";
            jsonToBinary(clientSock, quitMsg);
            break;
        } else if (command == "L" || command == "l") {
            std::cout << "Enter search term (blank for all): ";
            std::string searchTerm;
            std::getline(std::cin, searchTerm);

            json listReq;
            listReq["op"]     = "LIST_USERS";
            listReq["search"] = searchTerm;
            jsonToBinary(clientSock, listReq);
        } else if (command == "S" || command == "s") {
            std::cout << "Recipient username: ";
            std::string recipient;
            std::getline(std::cin, recipient);

            std::cout << "Message text: ";
            std::string msgText;
            std::getline(std::cin, msgText);

            json sendReq;
            sendReq["op"]        = "SEND_MSG";
            sendReq["recipient"] = recipient;
            sendReq["content"]   = msgText;
            jsonToBinary(clientSock, sendReq);
        } else if (command == "D" || command == "d") {
            std::cout << "Enter message ID(s) to delete: ";
            std::string msgIds;
            std::getline(std::cin, msgIds);

            json deleteReq;
            deleteReq["op"]  = "DELETE_MSG";
            deleteReq["ids"] = msgIds;
            jsonToBinary(clientSock, deleteReq);
        } else {
            std::cerr << "Unrecognized command." << std::endl;
        }
    }

    close(clientSock);
    receiver.join();
    std::cout << "Client terminated." << std::endl;
    return 0;
}
