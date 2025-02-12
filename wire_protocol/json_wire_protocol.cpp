#include "json_wire_protocol.h"
#include <iostream>
#include <stdexcept>
#include <cstring>       // For memset
#include "json.hpp"

// Helper: send all data
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

// Helper: recv all data
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

std::vector<uint8_t> serializePacket(const BasePacket& pkt) {
    // Convert to JSON
    nlohmann::json j = pkt.to_json();

    // to_msgpack/binary
    std::vector<uint8_t> msgpackData = nlohmann::json::to_msgpack(j);
    return msgpackData;
}

std::unique_ptr<BasePacket> deserializePacket(const std::vector<uint8_t>& data) {
    // from_msgpack -> JSON
    nlohmann::json j = nlohmann::json::from_msgpack(data);

    // Check "op_code"
    if (!j.contains("op_code") || !j["op_code"].is_string()) {
        throw std::runtime_error("Invalid or missing 'op_code'");
    }
    std::string code = j["op_code"].get<std::string>();
    if (code.size() != 1) {
        throw std::runtime_error("op_code must be a single character.");
    }
    char op = code[0];

    std::unique_ptr<BasePacket> packet;
    switch (op) {
    case 'L': {
        auto p = std::make_unique<LoginPacket>();
        p->from_json(j);
        packet = std::move(p);
        break;
    }
    case 'R': {
        auto p = std::make_unique<RegisterPacket>();
        p->from_json(j);
        packet = std::move(p);
        break;
    }
    case 's': {
        auto p = std::make_unique<SendPacket>();
        p->from_json(j);
        packet = std::move(p);
        break;
    }
    case 'd': {
        auto p = std::make_unique<DeletePacket>();
        p->from_json(j);
        packet = std::move(p);
        break;
    }
    case 'l': {
        auto p = std::make_unique<ListUsersPacket>();
        p->from_json(j);
        packet = std::move(p);
        break;
    }
    case 'q': {
        auto p = std::make_unique<QuitPacket>();
        p->from_json(j);
        packet = std::move(p);
        break;
    }
    case 'v': {
        // ValidatePacket
        auto p = std::make_unique<ValidatePacket>();
        p->from_json(j);
        packet = std::move(p);
        break;
    }
    default:
        throw std::runtime_error("Unknown op_code: " + code);
    }
    return packet;
}

int sendPacket(Socket socket, const BasePacket& pkt) {
    try {
        // Serialize
        std::vector<uint8_t> data = serializePacket(pkt);

        // Send size prefix (4 bytes, network order)
        uint32_t netSize = htonl(static_cast<uint32_t>(data.size()));
        if (sendAll(socket, reinterpret_cast<const uint8_t*>(&netSize), 4) != 4) {
            return FAILURE;
        }

        // Send the data
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

std::unique_ptr<BasePacket> receivePacket(Socket socket) {
    // Read 4-byte size
    uint32_t netSize = 0;
    if (recvAll(socket, reinterpret_cast<uint8_t*>(&netSize), 4) != 4) {
        return nullptr;
    }
    uint32_t dataSize = ntohl(netSize);
    if (dataSize == 0) {
        return nullptr;
    }

    // Read data
    std::vector<uint8_t> buffer(dataSize);
    if (recvAll(socket, buffer.data(), dataSize) != static_cast<ssize_t>(dataSize)) {
        return nullptr;
    }

    // Deserialize
    try {
        return deserializePacket(buffer);
    } catch (const std::exception& e) {
        std::cerr << "[receivePacket] Exception: " << e.what() << "\n";
        return nullptr;
    }
}
