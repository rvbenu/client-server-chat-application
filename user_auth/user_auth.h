#ifndef USER_AUTH
#define ARGON2_AUTH 

#include <string>
#include <unordered_map>
#include <mutex>



// Argon2 parameters
// static const uint32_t T_COST = 2;          // Number of iterations
// static const uint32_t M_COST = (1 << 16);  // Memory usage (64MB)
// static const uint32_t PARALLELISM = 1;
// static const size_t SALT_LEN = 16;
// static const size_t HASH_LEN = 32;
// static const size_t ENCODED_LEN = 128;
// 
// // User structure to store credentials
// struct UserInfo {
//     std::string password; // Argon2-encoded hash
//     bool isOnline;
//     int socketFd;
// };
// 
// // Global user map with a mutex for thread safety
// extern std::unordered_map<std::string, UserInfo> userMap;
// extern std::mutex userMapMutex;
// 
// /**
//  * @brief Generate an Argon2 hash for a plaintext password.
//  * @param password The user's plaintext password.
//  * @return The Argon2-encoded hash string, or an empty string on error.
//  */
std::string argon2HashPassword(const std::string &password);
// 
// /**
//  * @brief Verify a plaintext password against an Argon2-encoded hash.
//  * @param encodedHash The stored Argon2-encoded hash.
//  * @param password The plaintext password.
//  * @return True if the password is correct, false otherwise.
//  */
bool argon2CheckPassword(const std::string &encodedHash, 
        const std::string &password);
// 
// /**
//  * @brief Handles user authentication for login or registration.
//  * @param sockFd The socket file descriptor.
//  * @param username The username.
//  * @param password The password.
//  * @param op The operation: "LOGIN" or "REGISTER".
//  * @return True on successful authentication, false otherwise.
//  */
// bool loginOrRegister(int sockFd, const std::string &username, const std::string &password, const std::string &op);

#endif // AUTHENTICATION_H
