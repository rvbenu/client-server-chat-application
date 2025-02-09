#include "UserAccount.h"



// Constructor.  
UserAccount::UserAccount() : socket_fd(-1) {}    // Default value before connection. 



void UserAccount::set_username(const std::string& u) {
    username = u;
}

std::string UserAccount::get_username() const {    // `const`: NO CHANGES 
    return username;
}

void UserAccount::set_password(const std::string& p) {
    password = p;
}

std::string UserAccount::get_password() const {
    return password;
}

void UserAccount::hash_password() {
    hashed_password = hash_function(password);
}

std::string UserAccount::get_hashed_password() const {
    return hashed_password;
}

void UserAccount::set_ip_address(const std::string& ip) {
    ip_address = ip;
}

std::string UserAccount::get_ip_address() const {
    return ip_address;
}

void UserAccount::set_socket_fd(int fd) {
    socket_fd = fd;
}

int UserAccount::get_socket_fd() const {
    return socket_fd;
}

std::string UserAccount::hash_function(const std::string& pass) {
    // To be implemented. 
    return pass; 
}
