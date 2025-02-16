#include <iostream>         
#include <thread>          
#include <unordered_map> 
#include <vector>      
#include <mutex>    
#include <string>          
#include <cstring>       
#include <cerrno>        
#include <cstdlib>     
#include <algorithm>    
#include <netinet/in.h>  
#include <arpa/inet.h> 
#include <unistd.h>
#include <netdb.h> 
#include <sys/types.h>  
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "user_auth/user_auth.h"
#include "wire_protocol/packet.h"
#include "wire_protocol/json_wire_protocol.h"           // (UN)COMMENT TO CHANGE PROTOCOLS.
// #include "wire_protocol/custom_wire_protocol.h"      // (UN)COMMENT TO CHANGE PROTOCOLS.


// Structure about messages exchanged by users. 
struct Message {
    std::string id;         // Unique message identifier as string
    std::string content;    // The actual message content
    std::string sender;     // Sender's username
    std::string recipient;  // Recipient's username
};

// User information. 
struct UserInfo {
    std::string password;      // Hashed password (using argon2)
    bool isOnline = false;     // Online status flag (false by default)
    int socketFd = -1;         // File descriptor for the user's socket
    SSL* ssl = nullptr;        // Pointer to the user's SSL connection
    std::vector<Message> offlineMessages;  // Unread, offline messages 
};


// Global message counter for assigning unique IDs to messages.
static int messageCounter = 0;

// Global container to store all messages, mapped by a unique integer ID.
static std::unordered_map<int, Message> messages;

// Mutex to protect access to the messages map in multi-threaded environment.
static std::mutex messagesMutex;

// Global container to store user information, mapped by username.
static std::unordered_map<std::string, UserInfo> userMap;

// Mutex to protect access to the userMap.
static std::mutex userMapMutex;

// Forward declarations of user registration and login functions.
bool userRegister(SSL* ssl, const std::string &initialUsername, const std::string &initialPassword);
bool userLogin(SSL* ssl, const std::string &initialUsername, const std::string &initialPassword);

// ============================================================================
// SSL Context Initialization
// ============================================================================

/**
 * @brief Initializes the OpenSSL context and loads the server's certificate and private key.
 * 
 * @return SSL_CTX* A pointer to the initialized SSL context.
 */
SSL_CTX* initializeSSLContext() {
    // Initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create a new SSL context using the TLS server method
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        // If context creation fails, print errors and exit.
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Load the server's certificate from file (PEM format)
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // Load the server's private key from file (PEM format)
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// ============================================================================
// User Login Function (SSL version)
// ============================================================================

/**
 * @brief Handles user login over an SSL connection.
 * 
 * Repeatedly receives login attempts until a valid login is achieved or the client disconnects.
 * Also supports switching to user registration if requested.
 *  
 * @param ssl Pointer to the SSL connection.
 * @param initialUsername The initial username provided by the client.
 * @param initialPassword The initial password provided by the client.
 * @return true if login is successful; false otherwise.
 */
bool userLogin(SSL* ssl, const std::string &initialUsername, const std::string &initialPassword) {
    // Copy initial username and password for local processing.
    std::string username = initialUsername;
    std::string password = initialPassword;
    while (true) {
        bool success = false;
        {
            // Lock userMap while checking and updating user status.
            std::lock_guard<std::mutex> lock(userMapMutex);
            auto it = userMap.find(username);
            // If user exists and password is verified using Argon2, mark as online.
            if (it != userMap.end() && argon2CheckPassword(it->second.password, password)) {
                it->second.isOnline = true;
                it->second.ssl = ssl;
                success = true;
            }
        }
        // Prepare a validation packet to send back to the client.
        Packet v;
        v.op_code = 'v';
        v.isValidated = success;
        if (sendPacketSSL(ssl, v) != SUCCESS) {
            std::cerr << "[ERROR] Failed to send validation packet.\n";
            return false;
        }
        // If login is successful, log and return.
        if (success) {
            std::cout << "[INFO] User '" << username << "' logged in.\n";
            return true;
        }
        // Otherwise, wait for next packet for another login or registration attempt.
        auto nextPkt = receivePacketSSL(ssl);
        if (!nextPkt) {
            std::cerr << "[WARN] userLogin: client disconnected.\n";
            return false;
        }
        // Determine next action based on operation code from client.
        char nextOp = nextPkt->op_code;
        if (nextOp == 'L') {
            // New login attempt with updated credentials.
            username = nextPkt->username;
            password = nextPkt->password;
        }
        else if (nextOp == 'R') {
            // If registration is requested, switch to registration.
            if (userRegister(ssl, nextPkt->username, nextPkt->password))
                return true;
            else
                return false;
        } else {
            std::cerr << "[WARN] userLogin: unexpected op_code=" << nextOp << "\n";
            return false;
        }
    }
}

// ============================================================================
// User Registration Function (SSL version)
// ============================================================================

/**
 * @brief Handles new user registration over an SSL connection.
 * 
 * Repeatedly receives registration attempts until a new account is successfully created,
 * or the client switches to login.
 * 
 * @param ssl Pointer to the SSL connection.
 * @param initialUsername The initial username provided by the client.
 * @param initialPassword The initial password provided by the client.
 * @return true if registration is successful; false otherwise.
 */
bool userRegister(SSL* ssl, const std::string &initialUsername, const std::string &initialPassword) {
    // Copy initial username and password for local processing.
    std::string username = initialUsername;
    std::string password = initialPassword;
    while (true) {
        bool success = false;
        {
            // Lock the userMap while checking if the username is available.
            std::lock_guard<std::mutex> lock(userMapMutex);
            if (userMap.find(username) == userMap.end()) {
                // Create a new user with a hashed password.
                UserInfo newUser;
                newUser.password = argon2HashPassword(password);
                newUser.isOnline = true;
                newUser.ssl = ssl;
                // Insert the new user into the global user map.
                userMap[username] = std::move(newUser);
                success = true;
            }
        }
        // Send back a validation packet indicating success or failure.
        Packet v;
        v.op_code = 'v';
        v.isValidated = success;
        if (sendPacketSSL(ssl, v) != SUCCESS) {
            std::cerr << "[ERROR] Failed to send validation packet.\n";
            return false;
        }
        // If registration is successful, log and return.
        if (success) {
            std::cout << "[INFO] User '" << username << "' registered.\n";
            return true;
        }
        // Otherwise, wait for next packet to attempt registration or switch to login.
        auto nextPkt = receivePacketSSL(ssl);
        if (!nextPkt) {
            std::cerr << "[WARN] userRegister: client disconnected.\n";
            return false;
        }
        char nextOp = nextPkt->op_code;
        if (nextOp == 'R') {
            // New registration attempt with updated credentials.
            username = nextPkt->username;
            password = nextPkt->password;
        }
        else if (nextOp == 'L') {
            // If login is requested instead, switch to login.
            if (userLogin(ssl, nextPkt->username, nextPkt->password))
                return true;
            else
                return false;
        } else {
            std::cerr << "[WARN] userRegister: unexpected op_code=" << nextOp << "\n";
            return false;
        }
    }
}

// ============================================================================
// Main Client Handler Function (SSL version)
// ============================================================================

/**
 * @brief Handles communication with a connected client over an SSL connection.
 * 
 * This function processes different types of operations (op_codes) sent by the client,
 * including sending messages, retrieving offline messages, viewing message history,
 * listing users, deleting messages or accounts, and quitting the connection.
 * 
 * @param ssl Pointer to the client's SSL connection.
 */
void handleClient(SSL* ssl) {
    
    /** 
     * Whenever this function is called in a thread created in main, 
     * a fresh new connection is established between the server and the client. 
     * Thus, a client will never be authenticated by the start of this function. 
     * Thus, the first Packet the server expects is one with username and password 
     * fields not empty so that the client can be authenticated. 
     */
    bool isAuthenticated = false;  // Flag to indicate if the user has been authenticated.
    std::string currentUser;       // Stores the username of the authenticated user.

    // Main loop for processing client requests.
    while (true) {
        // Receive a packet from the client using SSL.
        auto pkt = receivePacketSSL(ssl);
        if (!pkt) {
            std::cout << "[INFO] Client disconnected or error occurred.\n";
            break;
        }
        char op = pkt->op_code;  // Operation code indicating the type of request.

        // If the client is not authenticated, handle login/registration requests.
        if (!isAuthenticated) {
            if (op == 'L' || op == 'R') {
                // Validate that username and password are not empty.
                if (!pkt->username.empty() && !pkt->password.empty()) {
                    // Depending on op_code, call the appropriate authentication function.
                    bool validated = (op == 'L') ?
                        userLogin(ssl, pkt->username, pkt->password) :
                        userRegister(ssl, pkt->username, pkt->password);
                    if (validated) {
                        isAuthenticated = true;
                        currentUser = pkt->username;
                        std::cout << "[INFO] " << currentUser << " is now authenticated.\n";
                    } else {
                        // If authentication fails, exit the loop.
                        break;
                    }
                } else {
                    // Warn if username or password is empty.
                    std::cerr << "[WARN] handleClient: empty username/password.\n";
                    Packet v;
                    v.op_code = 'v';
                    v.isValidated = false;
                    sendPacketSSL(ssl, v);
                    continue;
                }
            } else {
                // Ignore any operations until the client authenticates.
                continue;
            }
        } else {
            // The user is authenticated; process other operations.
            if (op == 's') {
                // 's' operation: Send a message from one user to another.
                std::string sender = pkt->sender;
                std::string recipient = pkt->recipient;
                std::string message = pkt->message;
                std::cout << "[INFO] Message from " << sender << " to " << recipient
                          << ": " << message << "\n";
                std::string message_id;
                {
                    // Lock the messages container while updating messageCounter and storing the message.
                    std::lock_guard<std::mutex> lock(messagesMutex);
                    messageCounter++;
                    message_id = std::to_string(messageCounter);
                    messages[messageCounter] = {message_id, message, sender, recipient};
                }
                bool validRecipient = false;
                {
                    // Lock the userMap to validate the recipient and process message delivery.
                    std::lock_guard<std::mutex> lock(userMapMutex);
                    auto it = userMap.find(recipient);
                    if (it != userMap.end()) {
                        validRecipient = true;
                        // If recipient is online, send the message immediately.
                        if (it->second.isOnline && it->second.ssl != nullptr) {
                            Packet forwardPkt;
                            forwardPkt.op_code = 's';
                            forwardPkt.sender = sender;
                            forwardPkt.recipient = recipient;
                            forwardPkt.message = message;
                            forwardPkt.message_id = message_id;
                            sendPacketSSL(it->second.ssl, forwardPkt);
                        } else {
                            // Otherwise, store the message as an offline message.
                            Message offMsg;
                            offMsg.id = message_id;
                            offMsg.sender = sender;
                            offMsg.recipient = recipient;
                            offMsg.content = message;
                            it->second.offlineMessages.push_back(offMsg);
                            std::cout << "[INFO] Stored offline message for '" << recipient << "'.\n";
                        }
                    }
                }
                // If the recipient is not valid, send an error packet back to the sender.
                if (!validRecipient) {
                    Packet errorPkt;
                    errorPkt.op_code = 's';
                    errorPkt.sender = "Server";
                    errorPkt.recipient = sender;
                    errorPkt.message = "Invalid recipient";
                    sendPacketSSL(ssl, errorPkt);
                }
                // Send a confirmation packet to the sender.
                Packet confPkt;
                confPkt.op_code = 'c';
                confPkt.sender = sender;
                confPkt.recipient = recipient;
                confPkt.message = message;
                confPkt.message_id = message_id;
                sendPacketSSL(ssl, confPkt);
            }
            else if (op == 'r') {
                // 'r' operation: Retrieve offline messages.
                std::string user = pkt->sender;
                int numToRetrieve = std::atoi(pkt->message.c_str());
                std::vector<Message> messagesToSend;
                {
                    // Lock userMap to safely access offline messages for the user.
                    std::lock_guard<std::mutex> lock(userMapMutex);
                    auto it = userMap.find(user);
                    if (it != userMap.end()) {
                        int count = 0;
                        // Retrieve up to numToRetrieve offline messages.
                        for (const auto &msg : it->second.offlineMessages) {
                            messagesToSend.push_back(msg);
                            if (++count >= numToRetrieve)
                                break;
                        }
                        // Remove the messages that are about to be sent.
                        if (count > 0)
                            it->second.offlineMessages.erase(it->second.offlineMessages.begin(),
                                                             it->second.offlineMessages.begin() + count);
                    }
                }
                // Send each offline message to the user.
                for (const auto &msg : messagesToSend) {
                    Packet forwardPkt;
                    forwardPkt.op_code = 's';
                    forwardPkt.message_id = msg.id;
                    forwardPkt.sender = msg.sender;
                    forwardPkt.recipient = msg.recipient;
                    forwardPkt.message = msg.content;
                    sendPacketSSL(ssl, forwardPkt);
                }
            }
            else if (op == 'h') {
                // 'h' operation: Retrieve message history (excluding offline messages already delivered).
                std::string username = pkt->sender;
                std::vector<std::string> offlineIds;
                {
                    // Lock userMap to collect IDs of offline messages.
                    std::lock_guard<std::mutex> lock(userMapMutex);
                    auto it = userMap.find(username);
                    if (it != userMap.end()) {
                        for (const auto &offMsg : it->second.offlineMessages)
                            offlineIds.push_back(offMsg.id);
                    }
                }
                std::vector<std::pair<int, Message>> historyMessages;
                {
                    // Lock messages map to extract the complete message history.
                    std::lock_guard<std::mutex> lock(messagesMutex);
                    for (const auto &kv : messages) {
                        const Message &msg = kv.second;
                        // Include messages if the user is either the sender or the recipient.
                        if (msg.sender == username || msg.recipient == username) {
                            bool skip = false;
                            // Skip messages that are still pending as offline messages.
                            for (const auto &id : offlineIds)
                                if (id == msg.id) { skip = true; break; }
                            if (!skip)
                                historyMessages.push_back(kv);
                        }
                    }
                }
                // Sort the history messages based on the message ID (assuming lower ID means older message).
                std::sort(historyMessages.begin(), historyMessages.end(),
                          [](const std::pair<int, Message>& a, const std::pair<int, Message>& b) {
                              return a.first < b.first;
                          });
                // Send the sorted history messages to the user.
                for (const auto &pair : historyMessages) {
                    Packet histPkt;
                    histPkt.op_code = 'h';
                    histPkt.sender = pair.second.sender;
                    histPkt.recipient = pair.second.recipient;
                    histPkt.message = pair.second.content;
                    histPkt.message_id = pair.second.id;
                    sendPacketSSL(ssl, histPkt);
                }
            }
            else if (op == 'l') {
                // 'l' operation: List users whose names match a given search pattern.
                std::string searchPattern = pkt->sender;
                std::string matchedUsers;
                {
                    // Lock userMap while searching for matching usernames.
                    std::lock_guard<std::mutex> lock(userMapMutex);
                    for (const auto &kv : userMap) {
                        // If the search pattern is empty or found within the username, include it.
                        if (searchPattern.empty() ||
                            (kv.first.find(searchPattern) != std::string::npos)) {
                            if (!matchedUsers.empty())
                                matchedUsers += ", ";
                            matchedUsers += kv.first;
                        }
                    }
                }
                std::cout << "[INFO] List users requested with pattern '" << searchPattern 
                          << "'. Found: " << matchedUsers << "\n";
                // Prepare a packet containing the list of matched users.
                Packet listPkt;
                listPkt.op_code = 'u';
                listPkt.sender = "Server";
                listPkt.message = matchedUsers;
                sendPacketSSL(ssl, listPkt);
            }
            else if (op == 'd') {
                // 'd' operation: Delete a message by ID.
                std::string requestingUser = pkt->sender;
                std::string msgId = pkt->message_id;
                int msgIDnumeric = std::atoi(msgId.c_str());
                bool deleted = false;
                Message deletedMsg;
                {
                    // Lock messages map while searching for and deleting the message.
                    std::lock_guard<std::mutex> lock(messagesMutex);
                    auto it = messages.find(msgIDnumeric);
                    // Delete only if the message exists and the requesting user is the recipient.
                    if (it != messages.end() && it->second.recipient == requestingUser) {
                        deletedMsg = it->second;
                        messages.erase(it);
                        deleted = true;
                    }
                }
                if (deleted) {
                    std::cout << "[INFO] Deleted message " << msgIDnumeric << " for " << requestingUser << "\n";
                    {
                        // Notify the sender about the deletion if they are online.
                        std::lock_guard<std::mutex> lock(userMapMutex);
                        auto it = userMap.find(deletedMsg.sender);
                        if (it != userMap.end() && it->second.isOnline && it->second.ssl != nullptr) {
                            Packet delNotif;
                            delNotif.op_code = 'x';  // deletion notification op code
                            delNotif.message_id = deletedMsg.id;
                            sendPacketSSL(it->second.ssl, delNotif);
                        }
                    }
                } else {
                    std::cout << "[WARN] Unable to delete message " << msgIDnumeric << "\n";
                }
            }
            else if (op == 'D') {
                // 'D' operation: Delete a user account.
                std::string username = pkt->sender;
                bool accountDeleted = false;
                {
                    // Lock userMap while searching for and deleting the user account.
                    std::lock_guard<std::mutex> lock(userMapMutex);
                    auto it = userMap.find(username);
                    if (it != userMap.end()) {
                        userMap.erase(it);
                        std::cout << "[INFO] Deleted account for user " << username << "\n";
                        accountDeleted = true;
                    } else {
                        std::cout << "[WARN] Account for user " << username << " not found.\n";
                    }
                }
                // Send a confirmation packet to the client regarding account deletion.
                Packet confirmPkt;
                confirmPkt.op_code = 'Y';
                confirmPkt.message = accountDeleted ? "Account deleted successfully" : "Account deletion failed";
                confirmPkt.username = "account_deleted";
                sendPacketSSL(ssl, confirmPkt);
                break;
            }
            else if (op == 'q') {
                // 'q' operation: Client requested to quit the session.
                std::cout << "[INFO] Client " << currentUser << " requested quit.\n";
                break;
            }
            else {
                // Unknown or unsupported op_code.
                std::cout << "[WARN] Unknown op_code: " << op << "\n";
            }
        }
    }
    // Cleanup: Mark the current user as offline.
    if (!currentUser.empty()) {
        std::lock_guard<std::mutex> lock(userMapMutex);
        auto it = userMap.find(currentUser);
        if (it != userMap.end()) {
            it->second.isOnline = false;
            it->second.ssl = nullptr;
        }
    }
    // Shutdown SSL connection and close the socket.
    int sockFd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockFd);
}

// ============================================================================
// Main Function: Server Entry Point
// ============================================================================

/**
 * @brief Main function to start the SSL server.
 * 
 * Sets up the server socket, initializes SSL, listens for incoming connections,
 * and creates a new thread to handle each client.
 * 
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments.
 * @return int Exit status code.
 */
int main(int argc, char* argv[]) {
    int port = 54000; // Default port if not specified by user.
    if (argc == 1)
        std::cout << "Using port " << port << "...\n";
    else if (argc == 2) {
        port = std::atoi(argv[1]);
        std::cout << "Using port " << port << "...\n";
    } else {
        std::cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }

    // Initialize the SSL context (loads certificate and private key).
    SSL_CTX* ctx = initializeSSLContext();

    // Create a TCP socket for the server.
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        perror("socket failed");
        return EXIT_FAILURE;
    }

    // Set socket options to allow reuse of the address.
    int opt = 1;
    if (setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(serverSock);
        return EXIT_FAILURE;
    }

    // Define and set up the server address structure.
    sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;               // IPv4
    serverAddr.sin_addr.s_addr = INADDR_ANY;         // Listen on any network interface
    serverAddr.sin_port = htons(port);               // Convert port to network byte order

    // Bind the socket to the specified address and port.
    if (bind(serverSock, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) {
        perror("bind failed");
        close(serverSock);
        return EXIT_FAILURE;
    }

    // Start listening for incoming connections.
    if (listen(serverSock, SOMAXCONN) < 0) {
        perror("listen failed");
        close(serverSock);
        return EXIT_FAILURE;
    }
    std::cout << "[INFO] Server listening on port " << port << "...\n";

    // Main server loop: accept and handle client connections.
    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        // Accept an incoming client connection.
        int clientSock = accept(serverSock, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
        if (clientSock < 0) {
            perror("accept failed");
            continue;
        }
        // Create a new SSL object for the client and associate it with the socket.
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientSock);
        // Perform the SSL/TLS handshake.
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(clientSock);
            continue;
        }
        // Log the new connection's IP address and port.
        char ipBuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), ipBuf, sizeof(ipBuf));
        std::cout << "[INFO] New client from " << ipBuf 
                  << ":" << ntohs(clientAddr.sin_port) << "\n";
        // Create a new thread to handle the client.
        std::thread t(handleClient, ssl);
        t.detach();  // Detach the thread to allow independent execution.
    }

    // Cleanup: close the server socket and free the SSL context.
    close(serverSock);
    SSL_CTX_free(ctx);
    return 0;
}
