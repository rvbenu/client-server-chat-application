#ifndef USERACCOUNT_H
#define USERACCOUNT_H

#include <string>

class UserAccount {
private:
    std::string username;
    std::string password;
    std::string hashed_password;
    int socket_fd;
    std::string hash_function(const std::string& pass);

public:
    UserAccount(); // Constructor

    // Setters and getters
    void set_username(const std::string& u);
    std::string get_username() const;

    void set_password(const std::string& p);
    std::string get_password() const;

    void hash_password();
    std::string get_hashed_password() const;

    void set_socket_fd(int fd);
    int get_socket_fd() const;
};

#endif
