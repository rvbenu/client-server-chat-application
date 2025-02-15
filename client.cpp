#include <openssl/ssl.h>
#include <openssl/err.h>

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
#include <netdb.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <sstream>
#include <queue>
#include <condition_variable>
#include <vector>


#include "wire_protocol/json_wire_protocol.h" 


// Global flag to control whether the client keeps running.
std::atomic<bool> keepRunning(true);

// Mutex to synchronize output to std::cout.
std::mutex coutMutex;

// -----------------------------
// Thread-Safe Packet Queue
// -----------------------------
// This queue holds incoming packets that require synchronous processing.
// The associated mutex and condition variable are used to protect and signal access.
std::queue<std::unique_ptr<Packet>> packetQueue;
std::mutex packetQueueMutex;
std::condition_variable packetQueueCondVar;

// -----------------------------
// Helper Function: connectToServer (raw socket)
// -----------------------------
/**
 * @brief Establishes a raw TCP connection to the specified host and port.
 *
 * This function uses getaddrinfo to resolve the host name and attempts to
 * connect using a socket. On success, returns the connected socket file descriptor.
 *
 * @param host The server hostname or IP address.
 * @param port The port number to connect to.
 * @return int The connected socket file descriptor, or -1 on error.
 */
int connectToServer(const std::string& host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    struct addrinfo hints, *res, *p;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string portStr = std::to_string(port);
    int status = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
    if (status != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(status) << "\n";
        close(sock);
        return -1;
    }
    // Try each address until a connection is successfully established.
    for (p = res; p != nullptr; p = p->ai_next) {
        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            perror("connect");
            continue;
        }
        break;
    }
    freeaddrinfo(res);
    if (p == nullptr) {
        std::cerr << "Failed to connect to " << host << " on port " << port << "\n";
        close(sock);
        return -1;
    }
    {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::cout << "[CLIENT] Connected to " << host << ":" << port << "\n";
    }
    return sock;
}

// -----------------------------
// Helper Function: connectToServerSSL
// -----------------------------
/**
 * @brief Establishes an SSL connection to the server.
 *
 * This function first creates a raw TCP connection using connectToServer,
 * then initializes an SSL object, associates it with the socket, and performs
 * the SSL/TLS handshake.
 *
 * @param host The server hostname or IP address.
 * @param port The port number to connect to.
 * @param ctx The initialized SSL context.
 * @return SSL* A pointer to the established SSL connection, or nullptr on error.
 */
SSL* connectToServerSSL(const std::string& host, int port, SSL_CTX* ctx) {
    int sock = connectToServer(host, port);
    if (sock < 0)
        return nullptr;

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "[CLIENT] Failed to create SSL object.\n";
        close(sock);
        return nullptr;
    }
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        std::cerr << "[CLIENT] SSL_connect failed.\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::cout << "[CLIENT] SSL connection established.\n";
    }
    return ssl;
}

// -----------------------------
// Helper Function: sendPacketNoResponse (SSL version)
// -----------------------------
/**
 * @brief Sends a packet over an SSL connection without expecting an immediate response.
 *
 * This function wraps the sendPacketSSL function and outputs an error message if sending fails.
 *
 * @param ssl The SSL connection to use for sending the packet.
 * @param pkt The packet to send.
 * @return true if the packet was sent successfully, false otherwise.
 */
bool sendPacketNoResponse(SSL* ssl, const Packet& pkt) {
    if (sendPacketSSL(ssl, pkt) != SUCCESS) {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::cerr << "[CLIENT] Failed to send packet (op_code='" << pkt.op_code << "').\n";
        return false;
    }
    return true;
}

// -----------------------------
// Listener Thread Function (SSL version)
// -----------------------------
/**
 * @brief Listener thread function for receiving packets from the server.
 *
 * This function continuously reads packets from the server using SSL.
 * Depending on the op_code, it either displays the packet content or
 * pushes it into the thread-safe packet queue for synchronous processing.
 *
 * @param ssl The SSL connection to listen on.
 */
void listenerThreadFunc(SSL* ssl) {
    while (keepRunning.load()) {
        auto pkt = receivePacketSSL(ssl);
        if (!pkt) {
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "\n[CLIENT] Disconnected from server or error occurred.\n";
            keepRunning.store(false);
            packetQueueCondVar.notify_all();
            break;
        }
        // Process the packet based on its op_code.
        if (pkt->op_code == 's') {
            // Chat message packet.
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "{\"type\":\"chat\","
                      << "\"sender\":\""    << pkt->sender    << "\","
                      << "\"message_id\":\""<< pkt->message_id<< "\","
                      << "\"recipient\":\"" << pkt->recipient << "\","
                      << "\"content\":\""   << pkt->message   << "\"}"
                      << std::endl;
        } else if (pkt->op_code == 'c') {
            // Confirmation packet.
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "{\"type\":\"confirmation\","
                      << "\"sender\":\""    << pkt->sender    << "\","
                      << "\"message_id\":\""<< pkt->message_id<< "\","
                      << "\"recipient\":\"" << pkt->recipient << "\","
                      << "\"content\":\""   << pkt->message   << "\"}"
                      << std::endl;
        } else if (pkt->op_code == 'h') {
            // History packet.
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "{\"type\":\"history\","
                      << "\"sender\":\""    << pkt->sender    << "\","
                      << "\"message_id\":\""<< pkt->message_id<< "\","
                      << "\"recipient\":\"" << pkt->recipient << "\","
                      << "\"content\":\""   << pkt->message   << "\"}"
                      << std::endl;
        } else if (pkt->op_code == 'x') {
            // Deletion notification.
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "{\"type\":\"delete\","
                      << "\"message_id\":\"" << pkt->message_id << "\"}"
                      << std::endl;
        } else if (pkt->op_code == 'Y') {
            // Account deletion confirmation.
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cout << "{\"type\":\"account_deleted\","
                      << "\"sender\":\"" << pkt->sender << "\"}"
                      << std::endl;
        } else {
            // For other op_codes (e.g., validation, user list responses),
            // push the packet into the packet queue for synchronous processing.
            {
                std::lock_guard<std::mutex> lock(packetQueueMutex);
                packetQueue.push(std::move(pkt));
                packetQueueCondVar.notify_all();
            }
        }
    }
}

// -----------------------------
// Helper Function: waitForPacketByOpCode
// -----------------------------
/**
 * @brief Waits for a packet with a specific op_code from the packet queue.
 *
 * This function blocks until a packet with the desired op_code is available,
 * or until the client is signaled to stop running.
 *
 * @param desiredOp The op_code to wait for.
 * @return std::unique_ptr<Packet> A pointer to the matching packet, or nullptr if stopping.
 */
std::unique_ptr<Packet> waitForPacketByOpCode(char desiredOp) {
    std::unique_ptr<Packet> result = nullptr;
    std::unique_lock<std::mutex> lock(packetQueueMutex);
    while (keepRunning.load()) {
        // Wait until there is a packet in the queue or the client is stopping.
        packetQueueCondVar.wait(lock, []{ return !packetQueue.empty() || !keepRunning.load(); });
        if (!keepRunning.load() && packetQueue.empty()) {
            break;
        }
        // Retrieve the packet from the front of the queue.
        auto pkt = std::move(packetQueue.front());
        packetQueue.pop();
        // If the packet matches the desired op_code, return it.
        if (pkt->op_code == desiredOp) {
            result = std::move(pkt);
            break;
        } else {
            // For packets that do not match, provide some feedback to the user.
            {
                std::lock_guard<std::mutex> coutLock(coutMutex);
                if (pkt->op_code == 's') {
                    std::cout << "\n[NEW MESSAGE] From: " << pkt->sender
                              << " | Message: " << pkt->message << "\n";
                } else {
                    std::cout << "\n[SERVER] Received packet with op_code='" << pkt->op_code << "'\n";
                }
                std::cout << "[CLIENT] Enter command (s/l/d/q/h): ";
            }
        }
    }
    return result;
}

// -----------------------------
// Main Client Function
// -----------------------------
/**
 * @brief Entry point for the client application.
 *
 * This function initializes OpenSSL, connects to the server using SSL,
 * starts the listener thread for incoming messages, and processes user
 * commands from the CLI/GUI. It supports login, registration, sending messages,
 * retrieving messages/history, listing users, deleting messages/accounts, and quitting.
 *
 * @param argc Number of command-line arguments.
 * @param argv Command-line arguments (expects server IP and port).
 * @return int Exit status code.
 */
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port>\n";
        return 1;
    }
    std::string serverIp = argv[1];
    int port = std::atoi(argv[2]);

    // Initialize OpenSSL for the client.
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Establish an SSL connection to the server.
    SSL* ssl = connectToServerSSL(serverIp, port, ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return 1;
    }

    // Start a separate thread to continuously listen for server packets.
    std::thread listenerThread(listenerThreadFunc, ssl);

    {
        std::lock_guard<std::mutex> lock(coutMutex);
        std::cout << "[CLIENT] Waiting for commands from GUI/CLI...\n";
    }

    // Main loop: read commands from standard input.
    std::string input;
    while (keepRunning.load() && std::getline(std::cin, input)) {
        if (input.empty())
            continue;
        // Use DELIMITER (ASCII Unit Separator) to split commands.
        const char DELIMITER = '\x1F';
        std::vector<std::string> tokens;
        std::stringstream ss(input);
        std::string token;
        while (std::getline(ss, token, DELIMITER)) {
            tokens.push_back(token);
        }
        if (tokens.empty())
            continue;

        // The first token indicates the command (op code).
        char op = tokens[0][0];
        if (op == 'L' || op == 'R') {
            // Login ('L') or Registration ('R') command.
            if (tokens.size() < 3) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cerr << "[CLIENT] Invalid login/register command.\n";
                continue;
            }
            std::string username = tokens[1];
            std::string password = tokens[2];
            Packet pkt;
            pkt.op_code  = op;
            pkt.username = username;
            pkt.password = password;
            if (!sendPacketNoResponse(ssl, pkt))
                continue;
            // Wait for a validation response ('v') from the server.
            auto resp = waitForPacketByOpCode('v');
            {
                std::lock_guard<std::mutex> lock(coutMutex);
                if (resp && resp->isValidated) {
                    std::cout << "[CLIENT] Authentication successful.\n";
                } else {
                    std::cerr << "[CLIENT] Authentication failed.\n";
                }
            }
        }
        else if (op == 's') {
            // Send message command.
            if (tokens.size() < 4) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cerr << "[CLIENT] Invalid send message command.\n";
                continue;
            }
            std::string sender    = tokens[1];
            std::string recipient = tokens[2];
            std::string message   = tokens[3];
            Packet pkt;
            pkt.op_code   = 's';
            pkt.sender    = sender;
            pkt.recipient = recipient;
            pkt.message   = message;
            sendPacketNoResponse(ssl, pkt);
        }
        else if (op == 'r') {
            // Retrieve offline messages command.
            if (tokens.size() < 3) {
                std::cerr << "[CLIENT] Invalid retrieve messages command.\n";
                continue;
            }
            std::string username = tokens[1];
            std::string countStr = tokens[2];
            Packet pkt;
            pkt.op_code  = 'r';
            pkt.sender   = username;
            pkt.message  = countStr;
            sendPacketNoResponse(ssl, pkt);
        }
        else if (op == 'h') {
            // History retrieval command.
            if (tokens.size() < 2) {
                std::cerr << "[CLIENT] Invalid history request command.\n";
                continue;
            }
            std::string username = tokens[1];
            Packet pkt;
            pkt.op_code = 'h';
            pkt.sender  = username;
            sendPacketNoResponse(ssl, pkt);
        }
        else if (op == 'l') {
            // List users command.
            if (tokens.size() < 2) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cerr << "[CLIENT] Invalid list users command.\n";
                continue;
            }
            std::string searchPattern = tokens[1];
            Packet pkt;
            pkt.op_code = 'l';
            pkt.sender  = searchPattern;
            if (!sendPacketNoResponse(ssl, pkt))
                continue;
            // Wait for the user list response ('u') from the server.
            auto resp = waitForPacketByOpCode('u');
            if (resp) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << "[CLIENT] User list from server: " << resp->message << "\n";
            }
        }
        else if (op == 'd') {
            // Delete message command.
            if (tokens.size() < 3) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cerr << "[CLIENT] Invalid delete message command.\n";
                continue;
            }
            std::string sender = tokens[1];
            std::string message_id = tokens[2];
            Packet pkt;
            pkt.op_code  = 'd';
            pkt.sender = sender;
            pkt.message_id = message_id;
            sendPacketNoResponse(ssl, pkt);
        }
        else if (op == 'D') {
            // Account deletion command.
            if (tokens.size() < 2) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cerr << "[CLIENT] Invalid account deletion command.\n";
                continue;
            }
            Packet pkt;
            pkt.op_code = 'D';
            std::string sender = tokens[1];
            pkt.sender = sender;
            sendPacketNoResponse(ssl, pkt);
            {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << "[CLIENT] Deleting account.\n";
            }
            keepRunning.store(false);
            break;
        }
        else if (op == 'q') {
            // Quit command.
            Packet pkt;
            pkt.op_code = 'q';
            sendPacketNoResponse(ssl, pkt);
            {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << "[CLIENT] Logging out.\n";
            }
            keepRunning.store(false);
            break;
        }
        else {
            // Unknown command.
            std::lock_guard<std::mutex> lock(coutMutex);
            std::cerr << "[CLIENT] Unknown command: " << op << "\n";
        }
    }
    // Signal all waiting threads to exit.
    keepRunning.store(false);
    packetQueueCondVar.notify_all();
    if (listenerThread.joinable())
        listenerThread.join();

    // Clean up SSL connection and context.
    int sock = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
