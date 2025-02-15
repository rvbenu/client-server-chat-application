// client_test.cpp
//
// To compile (example):
//   g++ -std=c++17 -pthread client_test.cpp -lgtest -lgtest_main -lssl -lcrypto -o client_test
//

#include <gtest/gtest.h>
#include <queue>
#include <vector>
#include <string>
#include <sstream>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <unordered_map>
#include <memory>

// -----------------------------------------------------------------------------
// Dummy Definitions and Test Helpers
// -----------------------------------------------------------------------------

#ifndef SUCCESS
#define SUCCESS 0
#endif

// Dummy implementations for SSL and socket-related functions.
namespace {
    // Create a dummy SSL pointer.
    SSL* createDummySSL() {
        return reinterpret_cast<SSL*>(new int(42));
    }
    void freeDummySSL(SSL* ssl) {
        delete reinterpret_cast<int*>(ssl);
    }

    // Dummy SSL functions.
    extern "C" {
        SSL* SSL_new(SSL_CTX* ctx) { return createDummySSL(); }
        void SSL_set_fd(SSL* ssl, int fd) { /* do nothing */ }
        int SSL_connect(SSL* ssl) { return 1; }  // Simulate success.
        int SSL_get_fd(const SSL* ssl) { return 42; }
        int SSL_shutdown(SSL* ssl) { return 0; }
        void SSL_free(SSL* ssl) { freeDummySSL(const_cast<SSL*>(ssl)); }
        int close(int fd) { return 0; }
    }

    // -------------------------------------------------------------------------
    // Dummy Packet Handling for Client Tests
    // -------------------------------------------------------------------------

    // We use the same Packet definition as in the production code.
    // (Assuming Packet is defined in "wire_protocol/json_wire_protocol.h".)
    // If needed, you can include that header here.

    // Global maps to simulate SSL send/receive operations.
    std::unordered_map<SSL*, std::vector<Packet>> client_sentPackets;
    std::unordered_map<SSL*, std::queue<Packet>> client_receiveQueues;

    // Dummy sendPacketSSL: record the packet sent.
    int dummySendPacketSSL(SSL* ssl, const Packet &pkt) {
        if (!ssl) return -1;
        client_sentPackets[ssl].push_back(pkt);
        return SUCCESS;
    }

    // Dummy receivePacketSSL: return the next queued packet (or nullptr if none).
    std::unique_ptr<Packet> dummyReceivePacketSSL(SSL* ssl) {
        if (!ssl) return nullptr;
        auto &queue = client_receiveQueues[ssl];
        if (queue.empty())
            return nullptr;
        Packet pkt = queue.front();
        queue.pop();
        return std::make_unique<Packet>(pkt);
    }

    // Helper: push a packet into the receive queue for a given SSL pointer.
    void pushClientReceivePacket(SSL* ssl, const Packet &pkt) {
        client_receiveQueues[ssl].push(pkt);
    }

    // -------------------------------------------------------------------------
    // Dummy network connection function.
    // -------------------------------------------------------------------------
    int dummyConnectToServer(const std::string& host, int port) {
        // Return a dummy socket descriptor.
        return 42;
    }
} // end anonymous namespace

// -----------------------------------------------------------------------------
// Override functions for client.cpp via macros
// -----------------------------------------------------------------------------

// Override the network and SSL send/receive functions.
#define sendPacketSSL dummySendPacketSSL
#define receivePacketSSL dummyReceivePacketSSL
// Override the raw connection function.
#define connectToServer dummyConnectToServer

// Disable main() from client.cpp by renaming it.
#define main dummy_main
#include "client.cpp"
#undef main

// -----------------------------------------------------------------------------
// GoogleTest Unit Tests for client.cpp
// -----------------------------------------------------------------------------

// Test 1: sendPacketNoResponse should return true if sendPacketSSL returns SUCCESS.
TEST(ClientTest, SendPacketNoResponseSuccess) {
    // Create a dummy SSL pointer.
    SSL* dummySSL = createDummySSL();
    // Clear any previous sent packets.
    client_sentPackets[dummySSL].clear();

    Packet testPkt;
    testPkt.op_code = 's';
    testPkt.sender = "tester";
    testPkt.recipient = "receiver";
    testPkt.message = "Hello";

    bool result = sendPacketNoResponse(dummySSL, testPkt);
    EXPECT_TRUE(result);

    // Verify that the packet was recorded.
    ASSERT_FALSE(client_sentPackets[dummySSL].empty());
    Packet recorded = client_sentPackets[dummySSL].back();
    EXPECT_EQ(recorded.op_code, 's');
    EXPECT_EQ(recorded.sender, "tester");
    EXPECT_EQ(recorded.message, "Hello");

    SSL_free(dummySSL);
}

// Test 2: waitForPacketByOpCode should return a packet with the desired op_code.
TEST(ClientTest, WaitForPacketByOpCode) {
    // Clear the global packet queue.
    {
        std::lock_guard<std::mutex> lock(packetQueueMutex);
        while (!packetQueue.empty()) {
            packetQueue.pop();
        }
    }
    // Create and push a test packet with op_code 'u' (e.g. a user list response).
    Packet testPkt;
    testPkt.op_code = 'u';
    testPkt.message = "user1, user2";
    {
        std::lock_guard<std::mutex> lock(packetQueueMutex);
        // Note: we need to push a unique_ptr to Packet.
        packetQueue.push(std::make_unique<Packet>(testPkt));
        packetQueueCondVar.notify_all();
    }
    // Ensure that keepRunning is true for the wait.
    keepRunning.store(true);
    auto result = waitForPacketByOpCode('u');
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->op_code, 'u');
    EXPECT_EQ(result->message, "user1, user2");
}

// Test 3: connectToServerSSL should return a valid SSL pointer.
TEST(ClientTest, ConnectToServerSSL) {
    // Create a dummy SSL context.
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    ASSERT_NE(ctx, nullptr);

    // Call connectToServerSSL; since connectToServer is overridden,
    // it will return our dummy socket and SSL_connect will succeed.
    SSL* ssl = connectToServerSSL("dummy_host", 12345, ctx);
    EXPECT_NE(ssl, nullptr);

    // Cleanup.
    int sock = SSL_get_fd(ssl);
    (void)sock; // not used in dummy implementation
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

// Test 4: listenerThreadFunc should push non-displayed packets into the packetQueue.
// We simulate a packet with op_code 'u' (user list) that is not handled by immediate printing.
TEST(ClientTest, ListenerThreadPushesPacket) {
    // Create a dummy SSL pointer.
    SSL* dummySSL = createDummySSL();
    // Clear any queued packets.
    while (!client_receiveQueues[dummySSL].empty()) {
        client_receiveQueues[dummySSL].pop();
    }
    // Clear the global packetQueue.
    {
        std::lock_guard<std::mutex> lock(packetQueueMutex);
        while (!packetQueue.empty()) {
            packetQueue.pop();
        }
    }
    // Prepare a packet with op_code 'u'.
    Packet testPkt;
    testPkt.op_code = 'u';
    testPkt.message = "user_list_test";
    pushClientReceivePacket(dummySSL, testPkt);

    // Set keepRunning to true, then start listenerThreadFunc in a separate thread.
    keepRunning.store(true);
    std::thread listener(listenerThreadFunc, dummySSL);

    // Allow a short time for the listener to process the packet.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    // Signal the listener to stop.
    keepRunning.store(false);
    packetQueueCondVar.notify_all();
    listener.join();

    // Check that the packet was pushed into the global packetQueue.
    std::unique_lock<std::mutex> lock(packetQueueMutex);
    bool found = false;
    while (!packetQueue.empty()) {
        auto pkt = std::move(packetQueue.front());
        packetQueue.pop();
        if (pkt->op_code == 'u' && pkt->message == "user_list_test")
            found = true;
    }
    EXPECT_TRUE(found);

    SSL_free(dummySSL);
}

// No main() is defined here because GoogleTest provides its own main.
