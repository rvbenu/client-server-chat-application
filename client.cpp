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
#include <thread>
#include <atomic>
#include <mutex>

// Global variables for thread synchronization
std::atomic<bool> keepRunning(true);  // Flag to control listener thread
std::mutex coutMutex;                  // Mutex to synchronize console output

/**
 * @brief A helper function to connect a TCP socket to the given host and port.
 *        Returns the socket file descriptor.
 */
int connectToServer(const std::string& host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Set up hints for getaddrinfo
    struct addrinfo hints, *res, *p;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM;   // TCP

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
 *        This is used when authenticating the user (logging in/registering).
 */
std::unique_ptr<Packet> sendPacketAndReceiveOne(int sock, const Packet& pkt) {
    // Serialize and send
    if (sendPacket(sock, pkt) != SUCCESS) {
        std::cerr << "[CLIENT] Failed to send packet with op_code='" << pkt.op_code << "'\n";
        return nullptr;
    }

    // Attempt to receive exactly one response
    auto resp = receivePacket(sock);
    if (!resp) {
        std::cerr << "[CLIENT] No response or error from server.\n";
        return nullptr;
    }

    char op = resp->op_code;
    std::lock_guard<std::mutex> lock(coutMutex);  // Ensure synchronized output
    std::cout << "[CLIENT] Server responded with op_code='" << op << "'\n";
    return resp;
}

/**
 * @brief Sends a packet without waiting for a response.
 */
bool sendPacketNoResponse(int sock, const Packet& pkt) {
    if (sendPacket(sock, pkt) != SUCCESS) {
        std::cerr << "[CLIENT] Failed to send packet (op_code='" << pkt.op_code << "').\n";
        return false;
    }
    return true;
}

/**
 * @brief Listener thread function to continuously receive and display messages.
 */
void listenerThreadFunc(int sock) {
    while (keepRunning.load()) {
        auto pkt = receivePacket(sock);
        if (!pkt) {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "\n[CLIENT] Disconnected from server or error occurred.\n";
            keepRunning.store(false);
            break;
        }

        char op = pkt->op_code;

        // Handle incoming packets based on op_code
        if (op == 's') {  // SendPacket: a message from another user
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "\n[NEW MESSAGE] From: " << pkt->sender
                      << " | Message: " << pkt->message << "\n";
            std::cout << "[CLIENT] Enter command (s/l/d/q): ";  // Prompt again
        }
        else if (op == 'v') {  // ValidatePacket: validation response
            // This should be handled in the main thread, but just in case
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "\n[SERVER] Validation response received.\n";
        }
        else if (op == 'm') {  // Custom op_code 'm'
            // Handle as needed
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "\n[SERVER] Custom message received: " << pkt->message << "\n";
            std::cout << "[CLIENT] Enter command (s/l/d/q): ";
        }
        else {
            // Handle other op_codes or ignore
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "\n[SERVER] Received packet with op_code='" << op << "'\n";
            std::cout << "[CLIENT] Enter command (s/l/d/q): ";
        }
    }
}

/**
 * @brief Main interactive client flow:
 *  1) Connect to server.
 *  2) In a loop, ask user: register (R) or login (L).
 *     - Send the corresponding packet (op_code='R' or 'L') with username, password.
 *     - Expect a Packet with op_code='v' in return with `isValidated`.
 *     - If `isValidated == true`, break out of loop.
 *  3) After that, start a listener thread and present the chat commands: s (send), l (list), d (delete), q (quit).
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

    while (!authenticated && keepRunning.load()) {
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

        // Send the appropriate Packet and expect a Packet(op_code='v')
        std::unique_ptr<Packet> resp;
        if (choice == 'R') {
            // Packet with op_code='R' for registration
            Packet pkt;
            pkt.op_code   = 'R';
            pkt.username  = username;
            pkt.password  = password;
            resp = sendPacketAndReceiveOne(sock, pkt);
        } else {
            // Packet with op_code='L' for login
            Packet pkt;
            pkt.op_code   = 'L';
            pkt.username  = username;
            pkt.password  = password;
            resp = sendPacketAndReceiveOne(sock, pkt);
        }

        // Check server response
        if (!resp) {
            // Possibly the connection is closed or error
            std::cerr << "[CLIENT] Could not receive validation Packet. Exiting.\n";
            close(sock);
            return 1;
        }

        // We expect op_code='v' for validation
        if (resp->op_code != 'v') {
            std::cout << "[CLIENT] Expected op_code='v' for validation, got '"
                      << resp->op_code << "'. Try again.\n";
            continue;  // re-prompt for R/L
        }

        // Check if validated
        if (resp->isValidated) {
            std::cout << "[CLIENT] Auth successful! Entering chat.\n";
            authenticated = true;
        } else {
            std::cout << "[CLIENT] Auth failed. Try again.\n";
        }
    }

    if (!authenticated) {
        std::cerr << "[CLIENT] Authentication failed or disconnected.\n";
        close(sock);
        return 1;
    }

    // Step 2: Start listener thread
    std::thread listenerThread(listenerThreadFunc, sock);

    // Step 3: User is in the chat. Provide commands: s, l, d, q
    std::cout << "[CLIENT] You are now in the chat. Commands:\n"
              << "   s => send message\n"
              << "   l => list users\n"
              << "   d => delete message\n"
              << "   q => quit\n";

    while (keepRunning.load()) {
        std::cout << "[CLIENT] Enter command (s/l/d/q): ";
        char cmd;
        std::cin >> cmd;
        if (!std::cin.good()) {
            std::cout << "\n[CLIENT] EOF or error on input. Exiting.\n";
            keepRunning.store(false);
            break;
        }

        if (cmd == 's') {
            // Send a message => use op_code='s', plus sender, recipient, message
            Packet pkt;
            pkt.op_code = 's';
            pkt.sender  = username; // user who logged in

            std::cout << "Enter recipient: ";
            std::cin >> pkt.recipient;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            std::cout << "Enter message: ";
            std::string msg;
            std::getline(std::cin, msg);
            pkt.message = msg;

            // Send the message
            if (!sendPacketNoResponse(sock, pkt)) {
                std::cerr << "[CLIENT] Failed to send message.\n";
            }

        } else if (cmd == 'l') {
            // List users => use op_code='l', plus sender
            Packet pkt;
            pkt.op_code = 'l';
            pkt.sender  = username;

            // Send the request
            auto resp = sendPacketAndReceiveOne(sock, pkt);
            if (resp && resp->op_code == 's') {
                // server responds with a Packet(op_code='s') containing user list
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << "[CLIENT] User list from server: " 
                          << resp->message << "\n";
            }

        } else if (cmd == 'd') {
            // Delete a message => op_code='d', plus sender, message_id
            Packet pkt;
            pkt.op_code = 'd';
            pkt.sender  = username;

            std::cout << "Enter message_id to delete: ";
            std::string msg_id;
            std::cin >> msg_id;
            pkt.message_id = msg_id;

            // Send the delete request
            if (!sendPacketNoResponse(sock, pkt)) {
                std::cerr << "[CLIENT] Failed to send delete request.\n";
            }

        } else if (cmd == 'q') {
            // Quit => op_code='q'
            Packet pkt;
            pkt.op_code = 'q';
            if (!sendPacketNoResponse(sock, pkt)) {
                std::cerr << "[CLIENT] Failed to send quit request.\n";
            }
            std::cout << "[CLIENT] Quitting.\n";
            keepRunning.store(false);
            break;

        } else {
            std::cout << "[CLIENT] Unknown command: " << cmd << "\n";
        }
    }

    // Clean up
    keepRunning.store(false);  // Ensure listener thread stops
    if (listenerThread.joinable()) {
        listenerThread.join();
    }

    close(sock);
    return 0;
}
