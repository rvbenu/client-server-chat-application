#include "json_wire_protocol.h"
#include <iostream>
#include <cstring>       // For memset
#include "json.hpp"

/**
 * @brief Helper function to send all data in a loop until fully transmitted or error.
 */
static ssize_t sendAll(Socket sock, const uint8_t* data, size_t length) {
    size_t totalSent = 0;
    while (totalSent < length) {
        ssize_t sent = send(sock, data + totalSent, length - totalSent, 0);
        if (sent == -1) {
            perror("send failed");
            return -1;
        }
        totalSent += sent;
    }
    return totalSent;
}

/**
 * @brief Helper function to receive all data in a loop until fully read or error.
 */
static ssize_t recvAll(Socket sock, uint8_t* data, size_t length) {
    size_t totalReceived = 0;
    while (totalReceived < length) {
        ssize_t r = recv(sock, data + totalReceived, length - totalReceived, 0);
        if (r <= 0) {
            if (r == 0) {
                std::cerr << "Connection closed by peer.\n";
            } else {
                perror("recv failed");
            }
            return -1;
        }
        totalReceived += r;
    }
    return totalReceived;
}

/**
 * @brief Serialize a Packet to a binary buffer (MessagePack) using nlohmann::json.
 */
std::vector<uint8_t> serializePacket(const Packet& pkt) {
    // 1) Convert Packet fields to nlohmann::json
    nlohmann::json j;
    j["op_code"]     = std::string(1, pkt.op_code);
    j["username"]    = pkt.username;
    j["password"]    = pkt.password;
    j["sender"]      = pkt.sender;
    j["recipient"]   = pkt.recipient;
    j["message"]     = pkt.message;
    j["message_id"]  = pkt.message_id;
    j["isValidated"] = pkt.isValidated;

    // 2) Convert JSON -> MessagePack
    std::vector<uint8_t> msgpackData = nlohmann::json::to_msgpack(j);
    return msgpackData;
}

/**
 * @brief Deserialize a binary buffer (MessagePack) into a Packet object.
 */
std::unique_ptr<Packet> deserializePacket(const std::vector<uint8_t>& data) {
    // 1) Convert MessagePack -> JSON
    nlohmann::json j = nlohmann::json::from_msgpack(data);

    // 2) Construct a Packet and populate
    auto pkt = std::make_unique<Packet>();

    // op_code
    if (j.contains("op_code") && j["op_code"].is_string()) {
        std::string opStr = j["op_code"].get<std::string>();
        if (!opStr.empty()) {
            pkt->op_code = opStr[0];
        }
    }
    // username
    if (j.contains("username")) {
        pkt->username = j["username"].get<std::string>();
    }
    // password
    if (j.contains("password")) {
        pkt->password = j["password"].get<std::string>();
    }
    // sender
    if (j.contains("sender")) {
        pkt->sender = j["sender"].get<std::string>();
    }
    // recipient
    if (j.contains("recipient")) {
        pkt->recipient = j["recipient"].get<std::string>();
    }
    // message
    if (j.contains("message")) {
        pkt->message = j["message"].get<std::string>();
    }
    // message_id
    if (j.contains("message_id")) {
        pkt->message_id = j["message_id"].get<std::string>();
    }
    // isValidated
    if (j.contains("isValidated")) {
        pkt->isValidated = j["isValidated"].get<bool>();
    }

    return pkt;
}

/**
 * @brief Send a Packet over a socket with a 4-byte size prefix.
 */
int sendPacket(Socket socket, const Packet& pkt) {
    try {
        // Serialize the Packet
        std::vector<uint8_t> data = serializePacket(pkt);

        // Send size header (4 bytes in network byte order)
        uint32_t netSize = htonl(static_cast<uint32_t>(data.size()));
        if (sendAll(socket, reinterpret_cast<const uint8_t*>(&netSize), 4) != 4) {
            return FAILURE;
        }

        // Send actual data
        ssize_t sent = sendAll(socket, data.data(), data.size());
        if (sent != static_cast<ssize_t>(data.size())) {
            return FAILURE;
        }
        return SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "[sendPacket] Exception: " << e.what() << "\n";
        return FAILURE;
    }
}

/**
 * @brief Receive a Packet from a socket with a 4-byte size prefix.
 */
std::unique_ptr<Packet> receivePacket(Socket socket) {
    // Read the size header (4 bytes)
    uint32_t netSize = 0;
    if (recvAll(socket, reinterpret_cast<uint8_t*>(&netSize), 4) != 4) {
        return nullptr; // error or disconnect
    }
    uint32_t dataSize = ntohl(netSize);
    if (dataSize == 0) {
        return nullptr; // Possibly empty or error
    }

    // Read the actual data
    std::vector<uint8_t> buffer(dataSize);
    if (recvAll(socket, buffer.data(), dataSize) != static_cast<ssize_t>(dataSize)) {
        return nullptr; // error or disconnect
    }

    // Deserialize into a Packet
    try {
        return deserializePacket(buffer);
    } catch (const std::exception& e) {
        std::cerr << "[receivePacket] Exception: " << e.what() << "\n";
        return nullptr;
    }
}
