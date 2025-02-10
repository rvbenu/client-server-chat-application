#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <cstdlib>
#include <arpa/inet.h> 
#include <netdb.h> 
#include <cstdio>
#include "UserAccount.h"







int main(int argc, char** argv) {

    // The client should provide the address and port number to connect to.  
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server IP address> <port number>\n", argv[0]);
        exit(EXIT_FAILURE);   
    }

    const char* server_ip = argv[1]; 
    const char* server_port = argv[2]; 

    // Validate port number
    int port = std::atoi(server_port);
    if (port <= 0 || port > 65535) {
        std::cerr << "Invalid port number: " << server_port << ". Must be between 1 and 65535.\n";
        return 1;
    }

    // Next, we need to determine an address for the client.

    struct addrinfo hints; 
    memset(&hints, 0, sizeof(hints)); 
    hints.ai_family = AF_INET;              // Allow IPv4 only 
    hints.ai_socktype = SOCK_STREAM;        // TCP-like
    hints.ai_protocol = 0;                  // Any protocol 
    hints.ai_flags = AI_PASSIVE;            // For "wildcard address" 
    hints.ai_addr = NULL; 
    hints.ai_canonname = NULL; 
    hints.ai_next = NULL; 
    
    // Define a pointer to the list of potential client addresses that 
    // getaddrinfo will allocate. 
    struct addrinfo* result; 

    /* getaddrinfo() returns a list of address structures.
    Try each address until we successfully bind(2).      
    If socket(2) (or bind(2)) fails, we (close the socket
    and) try the next address. */  
 
    int s = getaddrinfo(NULL, server_port, &hints, &result); 
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    struct addrinfo* client_addrinfo;
    int client_sfd; // Socket file descriptor 

    for (client_addrinfo = result; client_addrinfo != NULL; client_addrinfo = client_addrinfo->ai_next) {
        client_sfd = socket(client_addrinfo->ai_family, client_addrinfo->ai_socktype, client_addrinfo->ai_protocol);    
        if (client_sfd == -1) continue;  
        if (connect(client_sfd, client_addrinfo->ai_addr, client_addrinfo->ai_addrlen) == -1) { 
            break; // Success. 
        }

        close(client_sfd);
        client_sfd = -1; 
    }

    freeaddrinfo(result); 

    if (!client_addrinfo) {           // No address succeeded. 
        fprintf(stderr, "Could not bind\n");
        exit(EXIT_FAILURE);
    }

    // We have a connected socket: client_sfd.
    std::cout << "Connected to " << server_ip 
              << " on port " << server_port << "\n";
    
    // By this points, we have successfully established a 
    // socket for the client. Now, we shall ask the user 
    // to either register or log in. 

    bool logged_in = false;
    while (!logged_in) {

        char choice; 
        std::cout << "Do you want to REGISTER(r) or LOGIN(l)? ";
        std::cin >> choice; 

        if (!choice) {
            std::cout << "EOF on stdin. Type 'e' to exit. Type something else to continue. \n"; 
            std::cin >> choice; 
            if (choice == 'e') {
                close(client_sfd);
                return 0;
            } else {
                continue;   
            }
        }

        // Validate command
        if (choice != 'r' && choice != 'l') {
            std::cout << "Please type 'r' (to register) or 'l' (to log in). \n";
            continue;
        }

        if (choice == 'r') {    // Register

            // Ask for username & password
            std::string username, password;
            std::cout << "Enter username: ";
            if (!std::getline(std::cin, username)) {
                std::cout << "EOF on stdin. Exiting.\n";        // Better error handling needs 
                                                                // to be implemented. 
                break;
            }
            std::cout << "Enter password: ";
            if (!std::getline(std::cin, password)) {
                std::cout << "EOF on stdin. Exiting.\n";        // Same problem here. 
                break;
            }

            // Send username and password to the server. 
            // If username is available, the server creates a new UserAccount object
            // for the new user. If not, the client is asked to enter a different username 
            // and a password again.
             
        } else if (choice == 'l') {
            // Send username and password to the server. 
            // If username and password match, the server updates the socket for
            // this user (if needed). If username and/or password are not valid, 
            // the user is asked to try again. 


        }
    }


    return 0;
}
