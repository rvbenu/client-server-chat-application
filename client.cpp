/*
 * chat_client.cpp
 *
 * A simple chat client using POSIX sockets in C++.
 *
 * Each client has a hard-coded UUID (for example purposes, a sample UUID is used).
 * Upon connecting to the server, the client immediately registers by sending:
 *    REGISTER <uuid>
 *
 * After registration, the client continuously listens for incoming messages from
 * the server (which may include messages sent by other clients) and also allows
 * the user to type and send commands.
 *
 * The supported command format is:
 *    SEND <destination_uuid> <message>
 *
 * If the recipient is online, the server immediately forwards the message. Otherwise,
 * it will be stored for later delivery.
 *
 * To compile:
 *    g++ chat_client.cpp -o chat_client -pthread
 */


#include <iostream>
#include <sys/socket.h>      // For socket functions
#include <netinet/in.h>      // For sockaddr_in
#include <arpa/inet.h>       // For inet_pton
#include <unistd.h>          // For close()
#include <cstring>
#include <thread>
#include <string>

// Server connection details
const char* SERVER_IP = "127.0.0.1";  // Server IP address (localhost for testing)
const int SERVER_PORT = 54000;        // Must match the server port

void receive_messages(int sock) {
    char buffer[1024];
    while (true) {
        int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            // If the connection is closed or an error occurs, notify the user
            std::cout << "Disconnected from server." << std::endl;
            break;
        }
        buffer[bytesReceived] = '\0';
        std::cout << buffer;
    }
}



// client_authenticate handles the authentication process on the client side.
// It returns 0 on successful authentication/registration and -1 on failure.
int client_authenticate(int sock) {
    const size_t bufSize = 1024;
    char buffer[bufSize];

    // --- Step 1: Prompt for Username and Send ---
    std::string username;
    std::cout << "Enter your username: ";
    std::getline(std::cin, username);  // Using getline in case the username has spaces

    // Send the raw username (optionally append a newline if your protocol requires it)
    std::string usernameMessage = username + "\n";
    if (send(sock, usernameMessage.c_str(), usernameMessage.size(), 0) == -1) {
        std::cerr << "Error sending username." << std::endl;
        return -1;
    }

    // --- Step 2: Wait for Server's Response on Username ---
    memset(buffer, 0, bufSize);
    int bytesReceived = recv(sock, buffer, bufSize - 1, 0);
    if (bytesReceived <= 0) {
        std::cerr << "Error receiving server response for username." << std::endl;
        return -1;
    }
    buffer[bytesReceived] = '\0';
    std::string serverResponse(buffer);
    std::cout << "Server response: " << serverResponse << std::endl;
    
    // --- Step 3: Prompt for Password and Send ---
    std::string password;
    std::cout << "Enter your password: ";
    std::getline(std::cin, password);

    std::string passwordMessage = password + "\n";
    if (send(sock, passwordMessage.c_str(), passwordMessage.size(), 0) == -1) {
        std::cerr << "Error sending password." << std::endl;
        return -1;
    }

    // --- Step 4: Wait for Final Authentication/Registration Result ---
    memset(buffer, 0, bufSize);
    bytesReceived = recv(sock, buffer, bufSize - 1, 0);
    if (bytesReceived <= 0) {
        std::cerr << "Error receiving final authentication result." << std::endl;
        return -1;
    }
    buffer[bytesReceived] = '\0';
    std::string finalResponse(buffer);
    std::cout << "Final server response: " << finalResponse << std::endl;

    // --- Step 5: Determine Success or Failure ---
    if (finalResponse.find("SUCCESS") != std::string::npos) {
        std::cout << "Authentication/Registration successful!" << std::endl;
        return 0;
    } else {
        std::cerr << "Authentication/Registration failed." << std::endl;
        return -1;
    }
}


int main() {
    // Create a TCP socket (IPv4, stream socket)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Define the server address structure
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    
    // Convert the server IP address from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &serverAddress.sin_addr) <= 0) {
        perror("inet_pton");
        return 1;
    }
    
    // Connect to the chat server
    if (connect(sock, (sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("connect");
        return 1;
    }
    
    std::cout << "Connected to chat server." << std::endl;


    // Call the authentication function
    if (client_authenticate(sock) != 0) {
        std::cerr << "Authentication failed. Exiting." << std::endl;
        close(sock);
        return -1;
    }

    // Start a thread that listens for incoming messages from the server
    std::thread receiver(receive_messages, sock);
    
    // The main thread now reads user input from the console
    while (true) {
        std::cout << "Command [L: list users, S: send message, D: delete messages, Q: quit]: ";
        std::string command;
        if (!std::getline(std::cin, command)) break;

        // If the command is L (list users), prompt for search term
        if (command == "L") {
            std::cout << "Enter search term: ";
            std::string searchTerm;
            std::getline(std::cin, searchTerm);
            // Build the full command in one line
            command = "L " + searchTerm;
        }

        // Optionally, you could also similarly process other commands

        // Append a newline (or other delimiter) if needed by your protocol
        command += "\n";

        // Send the complete command to the server
        if (send(sock, command.c_str(), command.size(), 0) == -1) {
            std::cerr << "Failed to send command." << std::endl;
        }

        // The client can now wait to display the server response (which is handled
        // either in this loop or in a separate receiving thread).
    }

    
    // Clean up: close the socket and wait for the receiver thread to finish
    close(sock);
    receiver.join();
    return 0;
}
