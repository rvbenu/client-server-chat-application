/*
 * chat_server.cpp
 *
 * A simple chat server using POSIX sockets in C++.
 *
 * This server listens on a specified port and accepts client connections.
 * Each client must first register by sending a message of the form:
 *    REGISTER <uuid>
 *
 * Once registered, the client can send messages using the format:
 *    SEND <destination_uuid> <message>
 *
 * The server checks if the destination client is currently connected:
 *   - If so, it immediately forwards the message.
 *   - Otherwise, it stores the message as an “offline message” and sends it
 *     when the recipient later connects.
 *
 * To compile:
 *    g++ chat_server.cpp -o chat_server -pthread
 */

#include <iostream>
#include <sys/socket.h>      // For socket functions
#include <netinet/in.h>      // For sockaddr_in
#include <arpa/inet.h>       // For inet_ntoa and htons
#include <unistd.h>          // For close()
#include <cstring>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <algorithm>

const int PORT = 54000; // Server listening port

// Global data structures to keep track of connected clients and offline messages

// Map from client username to password hash
std::unordered_map<std::string, std::string> userRecord;
std::mutex userMutex;

// Map from client username to its socket descriptor
std::unordered_map<std::string, int> connectedClients;
std::mutex clientsMutex;

// Map from client username to a list of messages that arrived while offline
std::unordered_map<std::string, std::vector<std::string>> offlineMessages;
std::mutex offlineMutex;


/*
user_authenticate

Takes client socket and manages authentication.
If submitted username does not yet exist, create and request password. 
If username does exist, verify password matches.

Return 0 if user creation/auth successful, -1 otherwise.
*/
int user_authenticate(int clientSocket, char* buffer) {
    // Assume buffer is at least 1024 bytes
    const size_t bufSize = 1024;
    
    // --- Step 1: Receive Username ---
    std::cout << "Waiting for username" << std::endl;
    memset(buffer, 0, bufSize);  // Clear buffer
    int bytesReceived = recv(clientSocket, buffer, bufSize - 1, 0);
    if (bytesReceived <= 0) {
        std::cerr << "Username reception error (socket)" << std::endl;
        close(clientSocket);
        return -1;
    }
    buffer[bytesReceived] = '\0';
    std::string username(buffer);
    
    // --- Step 2: Decide if user exists ---
    bool userExists = false;
    {
        std::lock_guard<std::mutex> lock(userMutex);
        userExists = (userRecord.find(username) != userRecord.end());
    }
    
    std::string responseMessage;
    if (userExists) {
        std::cout << "User exists: " << username << std::endl;
        responseMessage = "AUTHENTICATE";
    } else {
        std::cout << "User not found: " << username << std::endl;
        responseMessage = "REGISTER";
    }
    
    // --- Step 3: Send response to client ---
    send(clientSocket, responseMessage.c_str(), responseMessage.size(), 0);
    
    // --- Step 4: Receive Password ---
    std::cout << "Waiting for password" << std::endl;
    memset(buffer, 0, bufSize);  // Clear buffer again
    bytesReceived = recv(clientSocket, buffer, bufSize - 1, 0);
    if (bytesReceived <= 0) {
        std::cerr << "Password reception error (socket)" << std::endl;
        close(clientSocket);
        return -1;
    }
    buffer[bytesReceived] = '\0';
    std::string password(buffer);
    
    // --- Step 5: Process based on previous decision ---
    {
        std::lock_guard<std::mutex> lock(userMutex);
        if (userExists) {
            // Authentication case: verify password matches stored password.
            if (userRecord[username] == password) {
                std::string authSuccessMessage = "AUTH_SUCCESS";
                send(clientSocket, authSuccessMessage.c_str(), authSuccessMessage.size(), 0);
                std::cout << "User authenticated: " << username << std::endl;
            } else {
                std::string authFailureMessage = "AUTH_FAILURE";
                send(clientSocket, authFailureMessage.c_str(), authFailureMessage.size(), 0);
                std::cerr << "User authentication failed: " << username << std::endl;
                close(clientSocket);
                return -1;
            }
        } else {
            // Registration case: add the username and password to the record.
            // (In a real-world scenario, hash the password before storing.)
            userRecord[username] = password;
            std::string regSuccessMessage = "REG_SUCCESS";
            send(clientSocket, regSuccessMessage.c_str(), regSuccessMessage.size(), 0);
            std::cout << "User registered: " << username << std::endl;
        }
    }

    // Add this client to the map of connected clients
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        connectedClients[username] = clientSocket;
    }
    
    return 0;
}

/*
list_users

Takes a client socket as input.

Prompts user for wildcard and sends all matching accounts.

Return -1 if error, 0 otherwise.
*/

int list_users(int clientSocket, const std::string &searchTerm) {
    std::string result;
    {
        std::lock_guard<std::mutex> lock(userMutex);
        for (const auto &pair : userRecord) {
            const std::string &username = pair.first;
            if (username.find(searchTerm) != std::string::npos) {
                result += username + "\n";
            }
        }
    }
    
    if (result.empty()) {
        result = "No matching users found.\n";
    }
    
    if (send(clientSocket, result.c_str(), result.size(), 0) == -1) {
        std::cerr << "Error sending matching users." << std::endl;
        return -1;
    }
    return 0;
}




/* 
send_message

Takes client socket as input.

Prompts user for an account. Delivers or queues depending
on whether the user is connected or not.
*/

int send_message(int clientSocket) {
    // TODO: Implement send_message functionality
    std::string response = "Sending message...\n";
    send(clientSocket, response.c_str(), response.size(), 0);
    return 0;
}

/*
delete_messages

Takes client socket as input.

*/

int delete_messages(int clientSocket) {
    // TODO: Implement delete_messages functionality
    std::string response = "Deleting messages...\n";
    send(clientSocket, response.c_str(), response.size(), 0);
    return 0;
}

/*
handle_client

Takes client socket as input and manages client thread.
Uses user_authenticate and send_message function to deliver functionality.
*/
void handle_client(int clientSocket) {
    char buffer[1024];

    // Step 1: Authenticate the user.
    if (user_authenticate(clientSocket, buffer) < 0) {
        close(clientSocket);
        return;
    }

    // Step 2: Enter a loop to receive new commands.
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            std::cerr << "Error receiving command or client disconnected." << std::endl;
            break; // Exit loop if error or client disconnects.
        }
        buffer[bytesReceived] = '\0';

        // Convert the received command to a string.
        std::string command(buffer);
        // Remove potential trailing newline or whitespace (if needed)
        command.erase(std::remove(command.begin(), command.end(), '\n'), command.end());
        command.erase(std::remove(command.begin(), command.end(), '\r'), command.end());

        // Check which command was received.
        if (command.size() >= 1 && command[0] == 'L') {
            // Expect the command in the format: "L <searchTerm>"
            std::string searchTerm = command.substr(1);
            // Trim any leading spaces:
            searchTerm.erase(0, searchTerm.find_first_not_of(" \t"));
            std::cout << "List users command received with search term: \"" << searchTerm << "\"" << std::endl;
            list_users(clientSocket, searchTerm);
        } else if (command == "S") {
            std::cout << "Send message command received." << std::endl;
            send_message(clientSocket);
        } else if (command == "D") {
            std::cout << "Delete messages command received." << std::endl;
            delete_messages(clientSocket);
        } else if (command == "Q") {
            std::cout << "Quit command received. Closing connection." << std::endl;
            break; // Optional: exit on "Q" for quit.
        } else {
            std::cerr << "Invalid command received: " << command << std::endl;
            std::string errMsg = "INVALID COMMAND\n";
            send(clientSocket, errMsg.c_str(), errMsg.size(), 0);
        }
    }
    
    // Clean up and close the client socket.
    close(clientSocket);
}




/*
 * main
 *
 * Sets up the server socket, binds to the desired port, and listens for
 * incoming client connections. Each new client is handled in a separate thread.
 */
int main() {
    // Create a TCP socket (IPv4, stream socket)
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // Allow the port to be reused immediately after the program terminates
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    // Set up the server address structure
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY; // Listen on all network interfaces
    serverAddress.sin_port = htons(PORT);       // Convert port to network byte order
    
    // Bind the socket to the address and port
    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Start listening for incoming connections
    if (listen(serverSocket, SOMAXCONN) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    std::cout << "Server listening on port " << PORT << "..." << std::endl;
    
    // Continuously accept new client connections
    while (true) {
        sockaddr_in clientAddress;
        socklen_t clientAddressLen = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLen);
        if (clientSocket < 0) {
            perror("accept");
            continue;
        }

        std::cout << "Launching client thread." << std::endl;
        
        // Launch a new thread to handle the connected client
        std::thread clientThread(handle_client, clientSocket);
        clientThread.detach(); // Detach so that the thread cleans up on its own
    }
    
    // Close the server socket (this line is not reached in this example)
    close(serverSocket);
    return 0;
}