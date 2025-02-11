// custom_wire_protocol.cpp

#include "wire_protocol.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <cstring>

/**
 * Helper to write an unsigned 32-bit length + data to a std::string buffer
 */
static void appendUint32(std::string &buffer, uint32_t val) {
    val = htonl(val);
    buffer.append(reinterpret_cast<const char*>(&val), sizeof(val));
}

/**
 * Helper to write an unsigned 16-bit length + data to a std::string buffer
 */
static void appendUint16(std::string &buffer, uint16_t val) {
    val = htons(val);
    buffer.append(reinterpret_cast<const char*>(&val), sizeof(val));
}

/**
 * Serializes Packet -> custom binary -> send
 */
bool sendPacket(int sockFd, const Packet &pkt) {
    try {
        // We'll build the entire data in a std::string buffer
        std::string payload;
        
        // 1) Number of key-value pairs (uint16_t)
        uint16_t numFields = static_cast<uint16_t>(pkt.fields.size());
        appendUint16(payload, numFields);

        // 2) For each field: key-len(2 bytes) + key bytes + val-len(4 bytes) + val bytes
        for (auto &kv : pkt.fields) {
            const std::string &key = kv.first;
            const std::string &val = kv.second;

            // key length (2 bytes)
            appendUint16(payload, static_cast<uint16_t>(key.size()));
            // key bytes
            payload.append(key.data(), key.size());

            // value length (4 bytes)
            appendUint32(payload, val.size());
            // value bytes
            payload.append(val.data(), val.size());
        }

        // We'll now length-prefix the entire payload with 4 bytes
        uint32_t totalLen = payload.size();
        uint32_t lenNet   = htonl(totalLen);

        // 3) Send the 4-byte length
        if (send(sockFd, &lenNet, sizeof(lenNet), 0) != sizeof(lenNet)) {
            return false;
        }
        // 4) Send the payload
        size_t totalSent = 0;
        while (totalSent < payload.size()) {
            ssize_t chunk = send(sockFd, payload.data() + totalSent,
                                 payload.size() - totalSent, 0);
            if (chunk <= 0) {
                return false;
            }
            totalSent += chunk;
        }
        return true;
    } catch (...) {
        std::cerr << "sendPacket (Custom) exception.\n";
        return false;
    }
}

/**
 * Reads custom binary format -> Packet
 */
Packet receivePacket(int sockFd) {
    Packet pkt;

    // 1) read 4-byte length prefix
    uint32_t lengthNet = 0;
    ssize_t n = recv(sockFd, &lengthNet, sizeof(lengthNet), MSG_WAITALL);
    if (n != sizeof(lengthNet)) {
        // error
        return pkt;
    }
    uint32_t lengthHost = ntohl(lengthNet);
    if (lengthHost == 0) {
        // empty
        return pkt;
    }

    // 2) read exactly lengthHost bytes
    std::string buffer(lengthHost, '\0');
    size_t totalRead = 0;
    while (totalRead < lengthHost) {
        ssize_t chunk = recv(sockFd, &buffer[totalRead], lengthHost - totalRead, MSG_WAITALL);
        if (chunk <= 0) {
            pkt.fields.clear();
            return pkt;
        }
        totalRead += chunk;
    }

    // 3) parse buffer -> Packet
    size_t pos = 0;
    auto readUint16 = [&](uint16_t &val) {
        if (pos + 2 > buffer.size()) return false;
        uint16_t netShort;
        std::memcpy(&netShort, &buffer[pos], 2);
        val = ntohs(netShort);
        pos += 2;
        return true;
    };
    auto readUint32 = [&](uint32_t &val) {
        if (pos + 4 > buffer.size()) return false;
        uint32_t netLong;
        std::memcpy(&netLong, &buffer[pos], 4);
        val = ntohl(netLong);
        pos += 4;
        return true;
    };

    // Number of fields
    uint16_t numFields = 0;
    if (!readUint16(numFields)) {
        pkt.fields.clear();
        return pkt;
    }

    for (int i = 0; i < numFields; i++) {
        // read key length
        uint16_t kLen = 0;
        if (!readUint16(kLen)) {
            pkt.fields.clear();
            return pkt;
        }
        if (pos + kLen > buffer.size()) {
            pkt.fields.clear();
            return pkt;
        }
        std::string key = buffer.substr(pos, kLen);
        pos += kLen;

        // read value length
        uint32_t vLen = 0;
        if (!readUint32(vLen)) {
            pkt.fields.clear();
            return pkt;
        }
        if (pos + vLen > buffer.size()) {
            pkt.fields.clear();
            return pkt;
        }
        std::string val = buffer.substr(pos, vLen);
        pos += vLen;

        pkt.fields[key] = val;
    }
    return pkt;
}
