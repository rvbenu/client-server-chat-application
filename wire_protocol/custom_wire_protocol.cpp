#include "custom_wire_protocol.h"
#include <iostream>
#include <stdexcept>
#include <cstring>       // For memset
#include <sstream>

// Helper function to send all data in a loop
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

// Helper function to receive all data in a loop
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
 * @brief Serialize a Packet to a binary buffer using a custom delimiter-separated protocol.
 *        Format: key1:value1;key2:value2;...;keyN:valueN;
 * @param pkt A reference to the Packet object.
 * @return A std::vector<uint8_t> containing the serialized data.
 */
std::vector<uint8_t> serializePacket(const Packet& pkt) {
    std::ostringstream oss;

    // Append each field in key:value; format
    oss << "op_code:" << pkt.op_code << ";";
    oss << "username:" << pkt.username << ";";
    oss << "password:" << pkt.password << ";";
    oss << "sender:" << pkt.sender << ";";
    oss << "recipient:" << pkt.recipient << ";";
    oss << "message:" << pkt.message << ";";
    oss << "message_id:" << pkt.message_id << ";";
    oss << "isValidated:" << (pkt.isValidated ? "1" : "0") << ";";

    std::string serializedStr = oss.str();

    // Convert string to bytes
    std::vector<uint8_t> data(serializedStr.begin(), serializedStr.end());
    return data;
}

/**
 * @brief Deserialize a binary buffer into a Packet object using the custom protocol.
 *        Expects format: key1:value1;key2:value2;...;keyN:valueN;
 * @param data A std::vector<uint8_t> containing serialized data.
 * @return A std::unique_ptr<Packet> containing the deserialized Packet.
 */
std::unique_ptr<Packet> deserializePacket(const std::vector<uint8_t>& data) {
    auto pkt = std::make_unique<Packet>();

    // Convert bytes to string
    std::string serializedStr(data.begin(), data.end());

    std::istringstream iss(serializedStr);
    std::string token;

    while (std::getline(iss, token, ';')) {
        if (token.empty()) continue; // Skip empty tokens
        size_t delimiterPos = token.find(':');
        if (delimiterPos == std::string::npos) {
            // Invalid format, skip this token
            continue;
        }
        std::string key = token.substr(0, delimiterPos);
        std::string value = token.substr(delimiterPos + 1);

        // Assign values based on key
        if (key == "op_code") {
            if (!value.empty()) {
                pkt->op_code = value[0];
            }
        }
        else if (key == "username") {
            pkt->username = value;
        }
        else if (key == "password") {
            pkt->password = value;
        }
        else if (key == "sender") {
            pkt->sender = value;
        }
        else if (key == "recipient") {
            pkt->recipient = value;
        }
        else if (key == "message") {
            pkt->message = value;
        }
        else if (key == "message_id") {
            pkt->message_id = value;
        }
        else if (key == "isValidated") {
            pkt->isValidated = (value == "1") ? true : false;
        }
        // Ignore unknown keys
    }

    return pkt;
}

/**
 * @brief Send a Packet over a socket with a 4-byte size prefix using the custom protocol.
 * @param socket The POSIX socket descriptor.
 * @param pkt The Packet to send.
 * @return SUCCESS (0) on success, FAILURE (-1) on error.
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

        // Send the actual data
        ssize_t sent = sendAll(socket, data.data(), data.size());
        if (sent != static_cast<ssize_t>(data.size())) {
            return FAILURE;
        }
        return SUCCESS;
    }
    catch (const std::exception& e) {
        std::cerr << "[sendPacket] Exception: " << e.what() << "\n";
        return FAILURE;
    }
}

/**
 * @brief Receive a Packet from a socket with a 4-byte size prefix using the custom protocol.
 * @param socket The POSIX socket descriptor.
 * @return A std::unique_ptr<Packet> on success, nullptr on error.
 */
std::unique_ptr<Packet> receivePacket(Socket socket) {
    // Read the size header (4 bytes)
    uint32_t netSize = 0;
    if (recvAll(socket, reinterpret_cast<uint8_t*>(&netSize), 4) != 4) {
        return nullptr; // Error or disconnect
    }
    uint32_t dataSize = ntohl(netSize);
    if (dataSize == 0) {
        return nullptr; // Possibly empty or error
    }

    // Read the actual data
    std::vector<uint8_t> buffer(dataSize);
    if (recvAll(socket, buffer.data(), dataSize) != static_cast<ssize_t>(dataSize)) {
        return nullptr; // Error or disconnect
    }

    // Deserialize into a Packet
    try {
        return deserializePacket(buffer);
    }
    catch (const std::exception& e) {
        std::cerr << "[receivePacket] Exception: " << e.what() << "\n";
        return nullptr;
    }
}
