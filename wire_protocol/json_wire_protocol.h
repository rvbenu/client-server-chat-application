#ifndef JSON_WIRE_PROTOCOL_H
#define JSON_WIRE_PROTOCOL_H

#include <vector>
#include <memory>
#include <sys/socket.h>   // POSIX socket
#include <arpa/inet.h>    // htonl, ntohl
#include <unistd.h>       // close()
#include <cstdint>
#include "packet.h"       // Include the Packet class
#include "json.hpp"

/**
 * @brief Typedef for convenience on POSIX systems.
 */
using Socket = int;

// Return codes
constexpr int SUCCESS = 0;
constexpr int FAILURE = -1;

/**
 * @brief Serialize a Packet to a binary buffer (e.g., MessagePack).
 * @param pkt A reference to the Packet object.
 * @return A std::vector<uint8_t> containing the serialized data.
 */
std::vector<uint8_t> serializePacket(const Packet& pkt);

/**
 * @brief Deserialize a binary buffer into a Packet object.
 * @param data A std::vector<uint8_t> containing serialized data.
 * @return A std::unique_ptr<Packet> containing the deserialized Packet.
 */
std::unique_ptr<Packet> deserializePacket(const std::vector<uint8_t>& data);

/**
 * @brief Send a Packet over a socket with a 4-byte size prefix.
 * @param socket The POSIX socket descriptor.
 * @param pkt The Packet to send.
 * @return SUCCESS (0) on success, FAILURE (-1) on error.
 */
int sendPacket(Socket socket, const Packet& pkt);

/**
 * @brief Receive a Packet from a socket with a 4-byte size prefix.
 * @param socket The POSIX socket descriptor.
 * @return A std::unique_ptr<Packet> on success, nullptr on error.
 */
std::unique_ptr<Packet> receivePacket(Socket socket);

#endif // JSON_WIRE_PROTOCOL_H
