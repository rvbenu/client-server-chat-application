#ifndef JSON_WIRE_PROTOCOL_H
#define JSON_WIRE_PROTOCOL_H

#include <cstdint>
#include <string>
#include <memory>
#include <vector>
#include <stdexcept>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "json.hpp"

// For convenience on POSIX systems
using Socket = int;

// Return codes
constexpr int SUCCESS = 0;
constexpr int FAILURE = -1;

/**
 * @brief Abstract base class for all packet types.
 *
 * Each derived class overrides:
 *  - getOpCode() to return a single char (e.g. 'C', 'L', 'R', 's', 'l', etc.)
 *  - to_json()/from_json() for serialization/deserialization
 *  - the various getters for fields it cares about (others return "")
 *  - if it needs to indicate validation success/fail, override getIsValidated()
 */
class BasePacket {
public:
    virtual ~BasePacket() = default;

    // Returns the single-character op code, e.g. 'L' for LOGIN, etc.
    virtual char getOpCode() const = 0;

    // Convert to JSON for serialization
    virtual nlohmann::json to_json() const = 0;

    // Populate from JSON for deserialization
    virtual void from_json(const nlohmann::json& j) = 0;

    // Common getters for possible fields (return "" if not relevant)
    virtual std::string getUsername()   const { return {}; }
    virtual std::string getPassword()   const { return {}; }
    virtual std::string getSender()     const { return {}; }
    virtual std::string getRecipient()  const { return {}; }
    virtual std::string getMessage()    const { return {}; }
    virtual std::string getMessageId()  const { return {}; }

    /**
     * @brief For a ValidatePacket (or similar). By default, false for all other packets.
     */
    virtual bool getIsValidated() const { return false; }
};

/**
 * @brief For "LOGIN" (op_code = 'L') => needs username, password.
 */
class LoginPacket : public BasePacket {
public:
    std::string username;
    std::string password;

    char getOpCode() const override { return 'L'; }

    nlohmann::json to_json() const override {
        nlohmann::json j;
        j["op_code"]  = "L";
        j["username"] = username;
        j["password"] = password;
        return j;
    }

    void from_json(const nlohmann::json& j) override {
        username = j.at("username").get<std::string>();
        password = j.at("password").get<std::string>();
    }

    // Getters
    std::string getUsername() const override { return username; }
    std::string getPassword() const override { return password; }
};

/**
 * @brief For "REGISTER" (op_code = 'R') => needs username, password.
 */
class RegisterPacket : public BasePacket {
public:
    std::string username;
    std::string password;

    char getOpCode() const override { return 'R'; }

    nlohmann::json to_json() const override {
        nlohmann::json j;
        j["op_code"]  = "R";
        j["username"] = username;
        j["password"] = password;
        return j;
    }

    void from_json(const nlohmann::json& j) override {
        username = j.at("username").get<std::string>();
        password = j.at("password").get<std::string>();
    }

    // Getters
    std::string getUsername() const override { return username; }
    std::string getPassword() const override { return password; }
};

/**
 * @brief For sending a message (op_code = 's'): sender, recipient, message.
 */
class SendPacket : public BasePacket {
public:
    std::string sender;
    std::string recipient;
    std::string message;

    char getOpCode() const override { return 's'; }

    nlohmann::json to_json() const override {
        nlohmann::json j;
        j["op_code"]   = "s";
        j["sender"]    = sender;
        j["recipient"] = recipient;
        j["message"]   = message;
        return j;
    }

    void from_json(const nlohmann::json& j) override {
        sender    = j.at("sender").get<std::string>();
        recipient = j.at("recipient").get<std::string>();
        message   = j.at("message").get<std::string>();
    }

    // Getters
    std::string getSender()    const override { return sender; }
    std::string getRecipient() const override { return recipient; }
    std::string getMessage()   const override { return message; }
};

/**
 * @brief For deleting a message (op_code = 'd'): sender, message_id
 */
class DeletePacket : public BasePacket {
public:
    std::string sender;
    std::string message_id;

    char getOpCode() const override { return 'd'; }

    nlohmann::json to_json() const override {
        nlohmann::json j;
        j["op_code"]    = "d";
        j["sender"]     = sender;
        j["message_id"] = message_id;
        return j;
    }

    void from_json(const nlohmann::json& j) override {
        sender     = j.at("sender").get<std::string>();
        message_id = j.at("message_id").get<std::string>();
    }

    // Getters
    std::string getSender()    const override { return sender; }
    std::string getMessageId() const override { return message_id; }
};

/**
 * @brief For listing users (op_code = 'l'): just needs sender
 */
class ListUsersPacket : public BasePacket {
public:
    std::string sender;

    char getOpCode() const override { return 'l'; }

    nlohmann::json to_json() const override {
        nlohmann::json j;
        j["op_code"] = "l";
        j["sender"]  = sender;
        return j;
    }

    void from_json(const nlohmann::json& j) override {
        sender = j.at("sender").get<std::string>();
    }

    // Getters
    std::string getSender() const override { return sender; }
};

/**
 * @brief For quitting (op_code = 'q'): no fields needed.
 */
class QuitPacket : public BasePacket {
public:
    char getOpCode() const override { return 'q'; }

    nlohmann::json to_json() const override {
        nlohmann::json j;
        j["op_code"] = "q";
        return j;
    }

    void from_json(const nlohmann::json& j) override {
        // nothing else
    }
};

/**
 * @brief A ValidatePacket (op_code = 'v') that indicates success or failure of authentication.
 */
class ValidatePacket : public BasePacket {
public:
    bool isValidated = false;  // true => validated; false => invalid

    char getOpCode() const override { return 'v'; }

    nlohmann::json to_json() const override {
        nlohmann::json j;
        j["op_code"]     = "v";
        j["isValidated"] = isValidated;
        return j;
    }

    void from_json(const nlohmann::json& j) override {
        isValidated = j.at("isValidated").get<bool>();
    }

    // Overriding from BasePacket
    bool getIsValidated() const override { return isValidated; }
};

/**
 * @brief Serialize a BasePacket to binary using nlohmann::json::to_msgpack
 */
std::vector<uint8_t> serializePacket(const BasePacket& pkt);

/**
 * @brief Deserialize binary data into the correct derived packet.
 */
std::unique_ptr<BasePacket> deserializePacket(const std::vector<uint8_t>& data);

/**
 * @brief Send a BasePacket over a socket with a 4-byte size prefix.
 */
int sendPacket(Socket socket, const BasePacket& pkt);

/**
 * @brief Receive a BasePacket from a socket with a 4-byte size prefix.
 */
std::unique_ptr<BasePacket> receivePacket(Socket socket);

#endif // JSON_WIRE_PROTOCOL_H
