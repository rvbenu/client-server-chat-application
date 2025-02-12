#include "wire_protocol/json_wire_protocol.h"
#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>


// A helper function to connect a TCP socket to the given host:port.
// Returns the socket file descriptor. 
int connectToServer(const std::string& host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Set up hints for getaddrinfo
    struct addrinfo hints, *res, *p;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    // Convert port to string
    std::string portStr = std::to_string(port);

    // Resolve the hostname to an IP address
    int status = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
    if (status != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(status) << "\n";
        close(sock);
        return -1;
    }

    // Iterate through the results and connect to the first we can
    for (p = res; p != nullptr; p = p->ai_next) {
        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            perror("connect");
            continue;
        }
        break; // Successfully connected
    }

    freeaddrinfo(res); // Free the linked list

    if (p == nullptr) {
        std::cerr << "Failed to connect to " << host << " on port " << port << "\n";
        close(sock);
        return -1;
    }

    std::cout << "[CLIENT] Connected to " << host << ":" << port << "\n";
    return sock;
}


/**
 * @brief Sends a packet and then strictly waits for exactly one response packet.
 * This is used when authenticating the user (logging in/registering).  
 */
std::unique_ptr<BasePacket> sendPacketAndReceiveOne(int sock, const BasePacket& pkt) {
    // Serialize and send
    if (sendPacket(sock, pkt) != SUCCESS) {
        std::cerr << "[CLIENT] Failed to send packet with op_code='" << pkt.getOpCode() << "'\n";
        return nullptr;
    }

    // Attempt to receive exactly one response
    auto resp = receivePacket(sock);
    if (!resp) {
        std::cerr << "[CLIENT] No response or error from server.\n";
        return nullptr;
    }

    char op = resp->getOpCode();
    std::cout << "[CLIENT] Server responded with op_code='" << op << "'\n";
    return resp;
}

/**
 * @brief Sends a packet without waiting for a response.
 */
bool sendPacketNoResponse(int sock, const BasePacket& pkt) {
    if (sendPacket(sock, pkt) != SUCCESS) {
        std::cerr << "[CLIENT] Failed to send packet (op_code='" << pkt.getOpCode() << "').\n";
        return false;
    }
    return true;
}

/**
 * @brief Main interactive client flow:
 *  1) Connect to server.
 *  2) In a loop, ask user: register (R) or login (L).
 *     - Send the corresponding packet (RegisterPacket or LoginPacket).
 *     - Expect a ValidatePacket in return with `isValidated`.
 *     - If `isValidated == true`, break out of loop.
 *  3) After that, present the chat commands: s (send), l (list), d (delete), q (quit).
 */
int main(int argc, char* argv[]) {

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port>\n";
        return 1;
    }
    std::string serverIp = argv[1];
    int port = std::atoi(argv[2]);

    int sock = connectToServer(serverIp, port);
    if (sock < 0) {
        return 1;
    }

    // Step 1: Loop until validated
    bool authenticated = false;
    std::string username, password;

    while (!authenticated) {
        // Ask user to register (R) or login (L)
        char choice;
        while (true) {
            std::cout << "[CLIENT] Enter 'R' to register, 'L' to login: ";
            std::cin >> choice;
            if (choice == 'R' || choice == 'L') {
                break;
            }
            std::cout << "[CLIENT] Invalid choice. Please try again.\n";
        }

        // Ask for username and password
        std::cout << "[CLIENT] Enter username: ";
        std::cin >> username;
        std::cout << "[CLIENT] Enter password: ";
        std::cin >> password;

        // Send the appropriate packet and expect a ValidatePacket
        std::unique_ptr<BasePacket> resp;
        if (choice == 'R') {
            RegisterPacket pkt;
            pkt.username = username;
            pkt.password = password;
            resp = sendPacketAndReceiveOne(sock, pkt);
        } else {
            LoginPacket pkt;
            pkt.username = username;
            pkt.password = password;
            resp = sendPacketAndReceiveOne(sock, pkt);
        }

        // Check server response
        if (!resp) {
            // Possibly the connection is closed or error
            std::cerr << "[CLIENT] Could not receive ValidatePacket. Exiting.\n";
            close(sock);
            return 1;
        }

        // We expect op_code='v' (ValidatePacket)
        if (resp->getOpCode() != 'v') {
            std::cout << "[CLIENT] Expected ValidatePacket(op_code='v'), got '"
                      << resp->getOpCode() << "'. Try again.\n";
            continue;  // re-prompt for R/L
        }

        // Check if validated
        bool isValid = resp->getIsValidated();
        if (isValid) {
            std::cout << "[CLIENT] Auth successful! Entering chat.\n";
            authenticated = true;
        } else {
            std::cout << "[CLIENT] Auth failed. Try again.\n";
        }
    }

    // Step 2: User is in the chat. Provide commands: s, l, d, q
    std::cout << "[CLIENT] You are now in the chat. Commands:\n"
              << "   s => send message\n"
              << "   l => list users\n"
              << "   d => delete message\n"
              << "   q => quit\n";

    while (true) {
        std::cout << "[CLIENT] Enter command (s/l/d/q): ";
        char cmd;
        std::cin >> cmd;
        if (!std::cin.good()) {
            std::cout << "[CLIENT] EOF or error on input. Exiting.\n";
            break;
        }

        if (cmd == 's') {
            // Send a message
            SendPacket pkt;
            pkt.sender = username; // we assume the sender is the user who logged in

            std::cout << "Enter recipient: ";
            std::cin >> pkt.recipient;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            std::cout << "Enter message: ";
            std::string msg;
            std::getline(std::cin, msg);
            pkt.message = msg;

            // Send and maybe get a response
            auto resp = sendPacketAndReceiveOne(sock, pkt);
            if (resp) {
                if (resp->getOpCode() == 's') {
                    std::cout << "[CLIENT] Response from server:\n"
                              << "   Sender   : " << resp->getSender() << "\n"
                              << "   Message  : " << resp->getMessage() << "\n";
                }
            }

        } else if (cmd == 'l') {
            // List users
            ListUsersPacket pkt;
            pkt.sender = username;
            auto resp = sendPacketAndReceiveOne(sock, pkt);
            if (resp && resp->getOpCode() == 's') {
                // server might respond with a SendPacket containing user list
                std::cout << "[CLIENT] User list from server: " 
                          << resp->getMessage() << "\n";
            }

        } else if (cmd == 'd') {
            // Delete a message
            DeletePacket pkt;
            pkt.sender = username;

            std::cout << "Enter message_id to delete: ";
            std::string msg_id;
            std::cin >> msg_id;
            pkt.message_id = msg_id;

            // Not expecting a response? or we can do a response
            sendPacketNoResponse(sock, pkt);

        } else if (cmd == 'q') {
            // Quit
            QuitPacket pkt;
            sendPacketNoResponse(sock, pkt);
            std::cout << "[CLIENT] Quitting.\n";
            break;

        } else {
            std::cout << "[CLIENT] Unknown command: " << cmd << "\n";
        }
    }

    close(sock);
    return 0;
}
