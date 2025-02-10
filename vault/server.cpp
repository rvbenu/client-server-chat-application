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
#include <cstdlib>
#include <thread>
#include "UserAccount.h"
#include <unordered_map> 








// Contains all user accounts.
// Keys are usernames and values are UserAccount objects. 
std::unordered_map<std::string, UserAccount> user_accounts; 




// The following function is intended to be executed concurrently. 
void handle_client(int client_sfd, sockaddr_in client_addr) { 
    

    // The first thing that the server should receive from a client is a password, a username,
    // and whether the client is trying to log in or register. The server then validates this 
    // and sends either a success message to the client and a try-again message. 


}



int main(int argc, char** argv) {


    // User enters the port number. 
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
        exit(EXIT_FAILURE);  
    }

    const char* server_port = argv[1];

    // Next, we need to determine an address for the server.
    
    struct addrinfo hints; 
    memset(&hints, 0, sizeof(hints)); 
    hints.ai_family = AF_INET;              // Allow IPv4 only 
    hints.ai_socktype = SOCK_STREAM;        // TCP-like
    hints.ai_protocol = 0;                  // Any protocol 
    hints.ai_flags = AI_PASSIVE;            // For "wildcard address" 
    hints.ai_addr = NULL; 
    hints.ai_canonname = NULL; 
    hints.ai_next = NULL; 

    // Define a pointer to the list of potential server 
    // addresses that getaddrinfo will allocate. 
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

    
    struct addrinfo* server_addrinfo;
    int sfd; // Socket file descriptor 

    for (server_addrinfo = result; 
            server_addrinfo != NULL; 
            server_addrinfo = server_addrinfo->ai_next) {
        
        sfd = socket(server_addrinfo->ai_family, 
                server_addrinfo->ai_socktype, 
                server_addrinfo->ai_protocol);    
        if (sfd == -1) continue;  
        if (bind(sfd, server_addrinfo->ai_addr, 
                    server_addrinfo->ai_addrlen) == 0) {
            break;      // Successfully binded the the
                        // socket to the server address.  
        }
        close(sfd); 
    }

    freeaddrinfo(result); 

    if (!server_addrinfo) {           // No address succeeded. 
        fprintf(stderr, "Could not bind\n");
        exit(EXIT_FAILURE);
    }
    
    // Mark the server socket as accepting connections. 
    if (listen(sfd, 10) == -1) {    // Limit the amount of connections on queue to 10. 
        fprintf(stderr, "Cound not listen. \n"); 
        exit(EXIT_FAILURE); 
    }

    std::cout << "Listening on port " << server_port << std::endl; 

    // Accepting connections from clients. 
    for (;;) {
        struct sockaddr_in client_addr; 
        socklen_t client_addr_len = sizeof(client_addr); 
        int client_sfd = accept(sfd, (struct sockaddr*)&client_addr, &client_addr_len); 
        if (client_sfd == -1) {
            fprintf(stderr, "Could not accept. \n"); 
            continue;       // Continue iterating to accept new connections. 
        }

        // Create a thread to handle multiple clients. 
        std::thread client_thread(handle_client, client_sfd, client_addr); 
        client_thread.detach();     // So that each client can be managed independently. 
    }

    close(sfd); 

    return 0; 
}
