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



// The following function is intended to be executed concurrently. 
void manage_client_communication(int client_sfd, sockaddr_in client_addr) { 
    
    char client_ip[INET_ADDRSTRLEN];
    // inet_ntop convert IPv4 and IPv6 addresses from binary to text form
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    std::cout << "Connected to client " << client_ip << " on port " << client_port << std::endl; 

    const char* welcome_msg = "Welcome!\n";
    ssize_t bytes_sent = send(client_sfd, welcome_msg, strlen(welcome_msg), 0);
    if (bytes_sent == -1) {
        perror("send");
    } else {
        std::cout << "Sent welcome message to " << client_ip << ":" << client_port << std::endl;
    }


    close(client_sfd);  
    std::cout << "Connection ended. \n"; 

}   



int main(int argc, char** argv) {

    // User is responsible for entering the server port number.  
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
        exit(EXIT_FAILURE); 
    }

    const char* server_port = argv[1];

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

    struct addrinfo* p;
    int sfd; // Socket file descriptor 

    for (p = result; p != NULL; p = p->ai_next) {
        sfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);    
        if (sfd == -1) continue;  
        if (bind(sfd, p->ai_addr, p->ai_addrlen) == 0) {
            break;   // Success.
        }
        close(sfd); 
    }

    freeaddrinfo(result); 

    if (!p) {           // No address succeeded. 
        fprintf(stderr, "Could not bind\n");
        exit(EXIT_FAILURE);
    }
    
    // Now, a socket has been succesfully established and 'sfd' is its file descriptor. 
    // We also have successfully captured the addrinfo of the server in `p`. 
    // The next step is to establish the TCP-like connection with the clients. 
    // We need to listen, accept, wait for connection, and then we can receive and send messages. 
    

    // Mark the server socket as accepting connections. 
    if (listen(sfd, 10) == -1) {    // Limit the amount of connections on queue to 10. 
        fprintf(stderr, "Cound not listen. \n"); 
        exit(EXIT_FAILURE); 
    }

    std::cout << "Listening on port " << server_port << std::endl; 

    // Accept
    for (;;) {
        struct sockaddr_in client_addr; 
        socklen_t client_addr_len = sizeof(client_addr); 
        int client_sfd = accept(sfd, (struct sockaddr*)&client_addr, &client_addr_len); 
        if (client_sfd == -1) {
            fprintf(stderr, "Could not accept. \n"); 
            continue;       // Continue iterating to accept new connections. 
        }

        // Create a thread to handle multiple clients. 
        std::thread client_thread(manage_client_communication, client_sfd, client_addr); 
        client_thread.detach();     // So that each client can be managed independently. 
    }

    close(sfd); 

    return 0; 
}
