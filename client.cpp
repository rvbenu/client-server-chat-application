/*
 * client.cpp
 *
 * This client:
 * - Connects to a specified server IP and port (command-line).
 * - Uses a Packet-based wire protocol (no direct nlohmann::json).
 * - Authenticates with the server, then provides commands for listing users,
 *   sending messages, deleting messages, and quitting.
 *
 * To compile (with a chosen wire protocol .cpp):
 *   g++ -std=c++17 -pthread client.cpp custom_wire_protocol.cpp -o client
 * or
 *   g++ -std=c++17 -pthread client.cpp json_wire_protocol.cpp -o client
 *
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

// Include the wire protocol declarations: Packet, sendPacket, receivePacket
#include "wire_protocol.h"

/*
 * receiverThreadFunc
 *
 * Continuously reads Packets from the server using receivePacket, 
 * and displays their contents. If reading fails, the thread ends.
 */
void receiverThreadFunc(int sockFd) {
    while (true) {
        Packet pkt = receivePacket(sockFd);
        if (pkt.fields.empty()) {
            std::cout << "[INFO] Disconnected or read error. Receiver thread ending.\n";
            break;
        }
        // Print out the received fields in some structured way
        auto opIt = pkt.fields.find("op");
        if (opIt == pkt.fields.end()) {
            std::cerr << "[WARN] Received Packet missing 'op'.\n";
            continue;
        }
        const std::string &op = opIt->second;

        // Based on "op", decide how to display
        if (op == "RECEIVE_MSG" || op == "RECEIVE_MSG_OFFLINE") {
            // e.g. { op="RECEIVE_MSG", from="alice", content="Hello" }
            std::string from    = pkt.fields.count("from")    ? pkt.fields.at("from")    : "";
            std::string content = pkt.fields.count("content") ? pkt.fields.at("content") : "";
            if (op == "RECEIVE_MSG_OFFLINE") {
                std::cout << "[SERVER] Offline message from " << from << ": " << content << "\n";
            } else {
                std::cout << "[SERVER] Message from " << from << ": " << content << "\n";
            }
        }
        else if (op == "LIST_USERS_RES") {
            // Could be a comma-separated user list or something similar
            std::string users = pkt.fields.count("users") ? pkt.fields.at("users") : "";
            std::cout << "[SERVER] Users: " << users << "\n";
        }
        else if (op == "CHECK_USER_RES") {
            bool exists = (pkt.fields.count("exists") && pkt.fields.at("exists") == "true");
            std::cout << "[SERVER] checkIfUserExists => " << (exists ? "true" : "false") << "\n";
        }
        else if (op == "LOGIN_RES" || op == "REGISTER_RES") {
            std::string status = pkt.fields.count("status") ? pkt.fields.at("status") : "FAIL";
            std::cout << "[SERVER] " << op << " => status=" << status << "\n";
        }
        else if (op == "SEND_MSG_RES" || op == "DELETE_MSG_RES") {
            std::string st = pkt.fields.count("status") ? pkt.fields.at("status") : "???";
            std::cout << "[SERVER] " << op << " => " << st << "\n";
        }
        else if (op == "ERROR") {
            std::string message = pkt.fields.count("message") ? pkt.fields.at("message") : "Unknown error";
            std::cout << "[SERVER] ERROR: " << message << "\n";
        }
        else {
            // fallback
            std::cout << "[SERVER] Unknown op=" << op << "\n";
        }
    }
}

/*
 * clientAuthenticate
 *
 * Prompts for a username, checks if that user exists,
 * then prompts for a password and attempts LOGIN or REGISTER.
 * Returns 0 on success, -1 on failure.
 */
int clientAuthenticate(int sockFd) {
    std::cout << "Enter your username: ";
    std::string username;
    std::getline(std::cin, username);

    // 1) Check if user exists
    {
        Packet pkt;
        pkt.fields["op"]       = "CHECK_USER";
        pkt.fields["username"] = username;
        if (!sendPacket(sockFd, pkt)) {
            std::cerr << "[ERROR] Failed to send CHECK_USER.\n";
            return -1;
        }
        Packet resp = receivePacket(sockFd);
        if (resp.fields.empty()) {
            std::cerr << "[ERROR] No response to CHECK_USER.\n";
            return -1;
        }
        // parse "exists"
        auto exIt = resp.fields.find("exists");
        bool exists = (exIt != resp.fields.end() && exIt->second == "true");

        // 2) Prompt for password
        std::cout << "Enter your password: ";
        std::string password;
        std::getline(std::cin, password);

        // 3) Send LOGIN or REGISTER
        Packet authPkt;
        authPkt.fields["op"]       = exists ? "LOGIN" : "REGISTER";
        authPkt.fields["username"] = username;
        authPkt.fields["password"] = password;
        if (!sendPacket(sockFd, authPkt)) {
            std::cerr << "[ERROR] Failed to send LOGIN/REGISTER.\n";
            return -1;
        }
        // 4) Wait for response
        Packet authResp = receivePacket(sockFd);
        if (authResp.fields.empty()) {
            std::cerr << "[ERROR] No response to LOGIN/REGISTER.\n";
            return -1;
        }
        auto stIt = authResp.fields.find("status");
        if (stIt == authResp.fields.end()) {
            std::cerr << "[ERROR] Malformed LOGIN/REGISTER response.\n";
            return -1;
        }
        if (stIt->second == "SUCCESS") {
            std::cout << "Authentication successful.\n";
            return 0;
        } else {
            std::cerr << "Authentication failed: " << stIt->second << "\n";
            return -1;
        }
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server IP> <port>\n";
        return 1;
    }
    const char* serverIP   = argv[1];
    const char* serverPort = argv[2];

    // 1) Resolve server
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* addrResult = nullptr;
    int rv = getaddrinfo(serverIP, serverPort, &hints, &addrResult);
    if (rv != 0) {
        std::cerr << "[ERROR] getaddrinfo: " << gai_strerror(rv) << "\n";
        return 1;
    }

    int sockFd = -1;
    for (auto p = addrResult; p != nullptr; p = p->ai_next) {
        sockFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockFd == -1) continue;
        if (connect(sockFd, p->ai_addr, p->ai_addrlen) == 0) {
            // success
            break;
        }
        close(sockFd);
        sockFd = -1;
    }
    freeaddrinfo(addrResult);

    if (sockFd == -1) {
        std::cerr << "[ERROR] Unable to connect to " << serverIP << ":" << serverPort << "\n";
        return 1;
    }
    std::cout << "[INFO] Connected to " << serverIP << ":" << serverPort << "\n";

    // 2) Perform authentication
    if (clientAuthenticate(sockFd) != 0) {
        std::cerr << "[ERROR] Authentication failed. Exiting.\n";
        close(sockFd);
        return 1;
    }

    // 3) Start receiver thread
    std::thread receiver(receiverThreadFunc, sockFd);

    // 4) Main loop: commands
    while (true) {
        std::cout << "\nCommands:\n"
                  << "  L: list users\n"
                  << "  S: send message\n"
                  << "  D: delete messages\n"
                  << "  Q: quit\n"
                  << "Enter Command: ";
        std::string command;
        if (!std::getline(std::cin, command)) {
            // input ended
            break;
        }

        if (command == "Q" || command == "q") {
            Packet pkt;
            pkt.fields["op"] = "QUIT";
            sendPacket(sockFd, pkt);
            break;
        }
        else if (command == "L" || command == "l") {
            std::cout << "Enter search term (blank for all): ";
            std::string st;
            std::getline(std::cin, st);
            Packet pkt;
            pkt.fields["op"]     = "LIST_USERS";
            pkt.fields["search"] = st;
            sendPacket(sockFd, pkt);
        }
        else if (command == "S" || command == "s") {
            std::cout << "Recipient username: ";
            std::string recipient;
            std::getline(std::cin, recipient);

            std::cout << "Message text: ";
            std::string text;
            std::getline(std::cin, text);

            Packet pkt;
            pkt.fields["op"]        = "SEND_MSG";
            pkt.fields["recipient"] = recipient;
            pkt.fields["content"]   = text;
            sendPacket(sockFd, pkt);
        }
        else if (command == "D" || command == "d") {
            std::cout << "Enter message ID(s) to delete: ";
            std::string ids;
            std::getline(std::cin, ids);

            Packet pkt;
            pkt.fields["op"]  = "DELETE_MSG";
            pkt.fields["ids"] = ids;
            sendPacket(sockFd, pkt);
        }
        else {
            std::cerr << "[WARN] Unrecognized command.\n";
        }
    }

    // Cleanup
    close(sockFd);
    receiver.join();
    std::cout << "[INFO] Client terminated.\n";
    return 0;
}
