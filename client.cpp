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


    struct addrinfo hints; 
    memset(&hints, 0, sizeof(hints)); 
    hints.ai_family = AF_INET;              // Allow IPv4 only 
    hints.ai_socktype = SOCK_STREAM;        // TCP-like
    hints.ai_protocol = 0;                  // Any protocol 
    hints.ai_flags = AI_PASSIVE;            // For "wildcard address" 
    hints.ai_addr = NULL; 
    hints.ai_canonname = NULL; 
    hints.ai_next = NULL; 


    
    // Define a pointer to the list of potential host addresses that 
    // getaddrinfo will allocate. 
    struct addrinfo* result; 
    
    int s = getaddrinfo(NULL, server_port, &hints, &result); 
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

 
    
    /* getaddrinfo() returns a list of address structures.
    Try each address until we successfully bind(2).      
    If socket(2) (or bind(2)) fails, we (close the socket
    and) try the next address. */

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

    // So far, so far a connection has been established. By this point, the client has a
    // socket specified by `client_sfd`. Also, we've captured the client `addrinfo`. 
    // The next step is to allow the clinet to send messages to the server.  
    

    // By this point, we have some information about the user. 
    UserAccount user; 
    user.set_ip_address(server_ip); 
    user.set_socket_fd(client_sfd); 


    // Now, we shall ask the user to create an account if new, and set a password. 
    

    bool logged_in = false;
    while (!logged_in) {
        std::cout << "Do you want to REGISTER(R) or LOGIN(L)? ";
        std::string choice;
        if (!std::getline(std::cin, choice)) {
            std::cout << "EOF on stdin. Exiting.\n";
            close(client_sfd);
            return 0;
        }

        // We want a valid command, e.g. "REGISTER" or "LOGIN"
        if (choice != "R" && choice != "L") {
            std::cout << "Please type 'R' (to register) or 'L' (to log in).\n";
            continue;
        }

        if (choice == "R") {
            // Communicate to the server to get list of used usernames. 


            // Ask for username & password
            std::string username, password;
            std::cout << "Enter username: ";
            if (!std::getline(std::cin, username)) {
                std::cout << "EOF on stdin. Exiting.\n";
                break;
            }
            std::cout << "Enter password: ";
            if (!std::getline(std::cin, password)) {
                std::cout << "EOF on stdin. Exiting.\n";
                break;
            }

            // Set in our local user object (client side)
            user.set_username(username);
            user.set_password(password);
        } else if (choice == "L") {
            // Comunicate to the server to see if password matches the username. 
            



        }
    }


    return 0;
}
