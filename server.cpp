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

// User authentication (argon2CheckPassword, argon2HashPassword, etc.)
#include "user_auth/user_auth.h"

// The new unified Packet class and JSON wire protocol
#include "wire_protocol/json_wire_protocol.h"

/**
 * @brief A message record (indexed by an int ID).
 */
struct Message {
    std::string content;
    std::string sender;
    std::string recipient;
};

/**
 * @brief A simple user record for demonstration.
 */
struct UserInfo {
    std::string password;   // Argon2 hashed (encoded) password
    bool isOnline = false;  // True if user is connected
    int socketFd = -1;      // Socket file descriptor

    // We store queued messages for offline users here
    std::vector<Message> offlineMessages;
};

// Global map: message ID -> Message
static int messageCounter = 0;  // increments forever
static std::unordered_map<int, Message> messages;
static std::mutex messagesMutex;

// Global map: username -> UserInfo
static std::unordered_map<std::string, UserInfo> userMap;
static std::mutex userMapMutex;

// Forward declarations
bool userLogin(int sockFd, const std::string &initialUsername,
               const std::string &initialPassword, char opCode);

bool userRegister(int sockFd, const std::string &initialUsername,
                  const std::string &initialPassword, char opCode);

/**
 * @brief Attempt to log in the user in a loop:
 *  1) If user exists and password matches, send Packet(op_code='v', isValidated=true), mark online, return true.
 *  2) Otherwise, send Packet(op_code='v', isValidated=false).
 *     Then expect another packet (could be another Packet with op_code='L' or 'R').
 *     If 'R', calls userRegister; if 'L', tries login again; if no packet or error, return false.
 */
bool userLogin(int sockFd, const std::string &initialUsername,
               const std::string &initialPassword, char opCode) 
{
    std::string username = initialUsername;
    std::string password = initialPassword;

    while (true) {
        bool success = false;
        {
            std::lock_guard<std::mutex> lock(userMapMutex);
            auto it = userMap.find(username);
            if (it != userMap.end()) {
                // Check password
                if (argon2CheckPassword(it->second.password, password)) {
                    // Mark user online
                    it->second.isOnline = true;
                    it->second.socketFd = sockFd;
                    success = true;
                }
            }
        }

        // Send Packet with op_code='v' to indicate validation result
        Packet v;
        v.op_code = 'v';        // validate op code
        v.isValidated = success;
        sendPacket(sockFd, v);

        if (success) {
            std::cout << "[INFO] User '" << username << "' logged in.\n";

            // Show & deliver offline messages
            {
                std::lock_guard<std::mutex> lock(userMapMutex);
                auto &info = userMap[username];
                int offlineCount = (int)info.offlineMessages.size();
                if (offlineCount > 0) {
                    std::cout << "[INFO] " << username << " has " 
                              << offlineCount << " offline messages.\n";

                    // Deliver each offline message as a Packet with op_code='s'
                    for (const auto &offMsg : info.offlineMessages) {
                        Packet forwardPkt;
                        forwardPkt.op_code   = 's';
                        forwardPkt.sender    = offMsg.sender;
                        forwardPkt.recipient = offMsg.recipient;
                        forwardPkt.message   = offMsg.content;

                        // Send to the newly logged-in user
                        sendPacket(sockFd, forwardPkt);
                    }

                    // Clear them so they are not re-sent next time
                    info.offlineMessages.clear();
                }
            }

            return true; 
        }

        // Not successful => expect next packet
        auto nextPkt = receivePacket(sockFd);
        if (!nextPkt) {
            std::cerr << "[WARN] userLogin: client disconnected.\n";
            return false; 
        }
        char nextOp = nextPkt->op_code;
        if (nextOp == 'L') {
            // Another login attempt
            username = nextPkt->username;
            password = nextPkt->password;
        } else if (nextOp == 'R') {
            // Switch to register
            std::string uname = nextPkt->username;
            std::string pwd   = nextPkt->password;
            if (userRegister(sockFd, uname, pwd, nextOp)) {
                return true;
            } else {
                return false;
            }
        } else {
            std::cerr << "[WARN] userLogin: unexpected op_code=" << nextOp << "\n";
            return false;
        }
    }
}


/**
 * @brief Attempt to register the user in a loop:
 *  1) If username is available, store user in userMap, send Packet(op_code='v', isValidated=true), and return true.
 *  2) Otherwise, send Packet(op_code='v', isValidated=false).
 *     Then expect next packet. Could be a Packet with op_code='R' or 'L', etc.
 */
bool userRegister(int sockFd, const std::string &initialUsername,
                  const std::string &initialPassword, char opCode)
{
    std::string username = initialUsername;
    std::string password = initialPassword;

    while (true) {
        bool success = false;
        {
            std::lock_guard<std::mutex> lock(userMapMutex);
            auto it = userMap.find(username);
            if (it == userMap.end()) {
                // Not found => can register
                UserInfo newUser;
                newUser.password = argon2HashPassword(password); 
                newUser.isOnline = true;
                newUser.socketFd = sockFd;
                userMap[username] = std::move(newUser);
                success = true;
            }
        }

        // Send Packet(op_code='v') for validation
        Packet v;
        v.op_code    = 'v';
        v.isValidated = success;
        sendPacket(sockFd, v);

        if (success) {
            std::cout << "[INFO] User '" << username << "' registered.\n";
            return true;
        }

        // user already taken => expect next packet
        auto nextPkt = receivePacket(sockFd);
        if (!nextPkt) {
            std::cerr << "[WARN] userRegister: client disconnected.\n";
            return false;
        }
        char nextOp = nextPkt->op_code;
        if (nextOp == 'R') {
            username = nextPkt->username;
            password = nextPkt->password;
        } else if (nextOp == 'L') {
            std::string uname = nextPkt->username;
            std::string pwd   = nextPkt->password;
            if (userLogin(sockFd, uname, pwd, nextOp)) {
                return true;
            } else {
                return false;
            }
        } else {
            std::cerr << "[WARN] userRegister: unexpected op_code=" << nextOp << "\n";
            return false;
        }
    }
}


/**
 * @brief This function is called in a thread in main to handle 
 * each client independently. Takes the socket file descriptor 
 * of the connection as an argument. 
 */
void handleClient(int sockFd) {
    bool isAuthenticated = false; // Whether the client is logged in or registered 
    std::string currentUser;      // Current user's username

    while (true) {
        // Receive a Packet using the wire protocol
        auto pkt = receivePacket(sockFd);
        if (!pkt) {
            std::cout << "[INFO] Client disconnected or error.\n";
            break;
        }

        char op = pkt->op_code; // e.g. 'L' for login, 'R' for register

        if (!isAuthenticated) {
            // Not authenticated => we only allow 'L' or 'R'
            if (op == 'L' || op == 'R') {
                std::string uname = pkt->username; 
                std::string pwd   = pkt->password;
                if (!uname.empty() && !pwd.empty()) {
                    bool validated = false;
                    if (op == 'L') {
                        // Attempt login
                        validated = userLogin(sockFd, uname, pwd, op);
                    } else {
                        // Attempt register
                        validated = userRegister(sockFd, uname, pwd, op);
                    }
                    if (validated) {
                        // success => mark isAuthenticated
                        isAuthenticated = true;
                        currentUser = uname;
                        std::cout << "[INFO] " << currentUser << " is now authenticated.\n";
                    } else {
                        // userLogin/userRegister loops until success or client disconnect
                        // so we should break if they fail
                        break;
                    }
                } else {
                    // missing username/pass => send negative validation
                    std::cerr << "[WARN] handleClient: empty username/pass.\n";

                    Packet v;
                    v.op_code     = 'v';   // validation
                    v.isValidated = false;
                    sendPacket(sockFd, v);
                    // continue to next iteration, letting the user try again
                    continue;
                }
            } else {
                // This line should not be reached as client usually sends 'L' or 'R' first
                continue;
            }
        } else {
            // Already authenticated. We expect other operations: 's', 'l', 'd', 'q', ...
            if (op == 's') {
                // "send" => packet has .sender, .recipient, .message
                std::string sender    = pkt->sender;
                std::string recipient = pkt->recipient;
                std::string message   = pkt->message;
                std::cout << "[INFO] Packet(op_code='s') from " << sender
                          << " to " << recipient << ": " << message << "\n";

                // Possibly store or forward this message
                {
                    std::lock_guard<std::mutex> lock1(userMapMutex);
                    std::lock_guard<std::mutex> lock2(messagesMutex);

                    messageCounter++;
                    messages[messageCounter] = {message, sender, recipient};

                    // Check if recipient is online
                    auto it = userMap.find(recipient);
                    if (it == userMap.end()) {
                        // recipient does not exist or was never registered
                        std::cerr << "[WARN] recipient '" << recipient << "' not found.\n";
                        
                        // We can send a Packet back to sender indicating error
                        Packet invalid;
                        invalid.op_code  = 's';       // or 'm' for custom
                        invalid.sender   = "Server";
                        invalid.recipient = sender;
                        invalid.message  = "Invalid recipient";
                        sendPacket(sockFd, invalid);

                    } else {
                        if (it->second.isOnline) {
                            // Forward the message immediately
                            int recSock = it->second.socketFd;

                            Packet forwardPkt;
                            forwardPkt.op_code   = 's';
                            forwardPkt.sender    = sender;
                            forwardPkt.recipient = recipient;
                            forwardPkt.message   = message;
                            sendPacket(recSock, forwardPkt);

                        } else {
                            // Add to offline messages
                            Message offMsg;
                            offMsg.sender    = sender;
                            offMsg.recipient = recipient;
                            offMsg.content   = message;
                            it->second.offlineMessages.push_back(offMsg);
                            std::cout << "[INFO] Stored message for offline user '" 
                                      << recipient << "'.\n";
                        }
                    }
                }

            } else if (op == 'l') {
                // "list users"
                std::string requestor = pkt->sender;
                std::cout << "[INFO] Packet(op_code='l') from " << requestor << "\n";
                // Build a list of all usernames
                std::string allUsers;
                {
                    std::lock_guard<std::mutex> lock(userMapMutex);
                    for (const auto& kv : userMap) {
                        if (!allUsers.empty()) {
                            allUsers += ", ";
                        }
                        allUsers += kv.first;
                    }
                }
                // Respond with a Packet(op_code='s') or 'm' containing the user list
                Packet resp;
                resp.op_code   = 's';     // or 'm', if you prefer
                resp.sender    = "Server";
                resp.recipient = requestor;
                resp.message   = allUsers;
                sendPacket(sockFd, resp);

            } else if (op == 'd') {
                // "delete" => we have .sender and .message_id
                std::string sender = pkt->sender;
                std::string msgId  = pkt->message_id;
                std::cout << "[INFO] Packet(op_code='d') from " << sender
                          << " for message_id=" << msgId << "\n";
                int msgIDnumeric = std::atoi(msgId.c_str());
                {
                    std::lock_guard<std::mutex> lock(messagesMutex);
                    auto it = messages.find(msgIDnumeric);
                    if (it != messages.end() && it->second.sender == sender) {
                        messages.erase(it);
                        std::cout << "[INFO] Deleted message " << msgIDnumeric << "\n";
                    } else {
                        std::cout << "[WARN] Cannot delete message " << msgIDnumeric << "\n";
                    }
                }

            } else if (op == 'q') {
                // "quit"
                std::cout << "[INFO] Received quit from " << currentUser << "\n";
                break;
            } else {
                std::cout << "[WARN] Unknown op_code: " << op << "\n";
                // Optionally send an error packet
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


int main(int argc, char* argv[]) {
    int port = 54000;   // Default port: 54000 

    if (argc == 1) {
        std::string p = std::to_string(port); 
        std::cout << "Using port " << p << "...\n";
    } else if (argc == 2) {
        port = std::atoi(argv[1]); 
        std::cout << "Using port " << argv[1] << "...\n";
    } else {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl; 
        return 1; 
    }

    // Create TCP socket (IPv4)
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        perror("socket failed");
        return EXIT_FAILURE;
    }

    // Set socket as reusable
    int opt = 1;
    if (setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(serverSock);
        return EXIT_FAILURE;
    }

    // Define host address
    sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port        = htons(port);

    // Bind socket
    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind failed");
        close(serverSock);
        return EXIT_FAILURE;
    }

    // Listen
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
        std::cout << "[INFO] New client from " << ipBuf 
                  << ":" << ntohs(clientAddr.sin_port) << "\n";
        
        // Handle this client in a separate thread
        std::thread t(handleClient, clientSock);
        t.detach();
    }

    close(serverSock);
    return 0;
}
