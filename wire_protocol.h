#ifndef WIRE_PROTOCOL_H
#define WIRE_PROTOCOL_H

#include <string>
#include <unordered_map>

/**
 * @brief A generic Packet containing key-value pairs.
 * 
 * The server and client logic only uses this struct for sending or
 * receiving key-value data. The actual wire format (JSON, custom binary,
 * etc.) is hidden behind the sendPacket/receivePacket interface.
 */
struct Packet {
    std::unordered_map<std::string, std::string> fields;
};

/**
 * @brief Sends a Packet over the socket.
 * @param sockFd The socket file descriptor.
 * @param pkt The Packet with key-value pairs to send.
 * @return true if successful, false otherwise.
 */
bool sendPacket(int sockFd, const Packet &pkt);

/**
 * @brief Receives a Packet from the socket.
 * @param sockFd The socket file descriptor.
 * @return A Packet with key-value pairs, or an empty Packet if an error occurs.
 */
Packet receivePacket(int sockFd);

#endif // WIRE_PROTOCOL_H
