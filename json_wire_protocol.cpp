// json_wire_protocol.cpp

#include "wire_protocol.h"

// We only include JSON here. The rest of the app is decoupled from JSON.
#include "json.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <iostream>

using nlohmann::json;

/**
 * @brief sendPacket for a JSON-based wire protocol (length prefix + MessagePack).
 */
bool sendPacket(int sockFd, const Packet &pkt) {
    try {
        // 1) Convert Packet => JSON
        json j;
        for (auto &kv : pkt.fields) {
            j[kv.first] = kv.second;
        }
        // 2) Convert JSON => MessagePack bytes
        std::vector<uint8_t> msgpackData = json::to_msgpack(j);

        // 3) Send length prefix
        uint32_t length = msgpackData.size();
        uint32_t lengthNet = htonl(length);
        if (send(sockFd, &lengthNet, sizeof(lengthNet), 0) != sizeof(lengthNet)) {
            return false;
        }

        // 4) Send raw bytes
        size_t totalSent = 0;
        while (totalSent < msgpackData.size()) {
            ssize_t chunk = send(sockFd, msgpackData.data() + totalSent,
                                 msgpackData.size() - totalSent, 0);
            if (chunk <= 0) {
                return false;
            }
            totalSent += chunk;
        }
        return true;
    } catch (std::exception &e) {
        std::cerr << "sendPacket (JSON) exception: " << e.what() << std::endl;
        return false;
    } catch (...) {
        std::cerr << "sendPacket (JSON) unknown exception.\n";
        return false;
    }
}

/**
 * @brief receivePacket for a JSON-based wire protocol (length prefix + MessagePack).
 */
Packet receivePacket(int sockFd) {
    Packet pkt; // initially empty

    // 1) Read 4-byte length prefix
    uint32_t lengthNet = 0;
    ssize_t n = recv(sockFd, &lengthNet, sizeof(lengthNet), MSG_WAITALL);
    if (n != sizeof(lengthNet)) {
        // error or disconnect
        return pkt; // empty fields => indicates error
    }
    uint32_t length = ntohl(lengthNet);
    if (length == 0) {
        return pkt; // no data => empty
    }

    // 2) Read exactly length bytes
    std::vector<uint8_t> buffer(length);
    size_t totalRead = 0;
    while (totalRead < length) {
        ssize_t chunk = recv(sockFd, buffer.data() + totalRead,
                             length - totalRead, MSG_WAITALL);
        if (chunk <= 0) {
            // error or disconnect
            pkt.fields.clear(); // ensure empty
            return pkt;
        }
        totalRead += chunk;
    }

    // 3) Convert MessagePack => JSON => Packet
    try {
        json j = json::from_msgpack(buffer);
        for (auto it = j.begin(); it != j.end(); ++it) {
            if (it.value().is_string()) {
                pkt.fields[it.key()] = it.value().get<std::string>();
            } else {
                // Convert non-string JSON to string if needed
                pkt.fields[it.key()] = it.value().dump();
            }
        }
    } catch (std::exception &e) {
        std::cerr << "receivePacket (JSON) parse error: " << e.what() << std::endl;
        pkt.fields.clear();
    }
    return pkt;
}
