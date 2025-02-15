// server_test.cpp
//
// To compile (example):
//   g++ -std=c++17 -pthread server_test.cpp -lgtest -lgtest_main -lssl -lcrypto -o server_test
//

#include <gtest/gtest.h>
#include <string>
#include <queue>
#include <unordered_map>
#include <vector>
#include <memory>

// -----------------------------------------------------------------------------
// Dummy definitions and test helpers
// -----------------------------------------------------------------------------

// Define a SUCCESS return code for our dummy sendPacketSSL.
#ifndef SUCCESS
#define SUCCESS 0
#endif

// --- Dummy implementations for external functions ---
//
// These definitions override (stub out) the functions declared in other modules.
// In a real project these might be provided by a mocking framework.

namespace {
    // Dummy Argon2 functions: for testing we treat the "hashed" password as just the original.
    bool argon2CheckPassword(const std::string &hashed, const std::string &password) {
        return hashed == password;
    }

    std::string argon2HashPassword(const std::string &password) {
        return password;
    }

    // --- Dummy SSL packet handling --- 
    //
    // We use two global maps to simulate sending and receiving packets over an SSL connection.
    // (In production, sendPacketSSL and receivePacketSSL would use the SSL socket.)
    struct Packet;  // Forward declaration (actual definition is in the server code)

    // Global maps for our dummy SSL operations.
    std::unordered_map<SSL*, std::vector<Packet>> g_sentPackets;
    std::unordered_map<SSL*, std::queue<Packet>> g_receiveQueues;

    // Dummy sendPacketSSL: record the packet sent for the given SSL pointer.
    int sendPacketSSL(SSL* ssl, const Packet &pkt) {
        if (!ssl) return -1;
        g_sentPackets[ssl].push_back(pkt);
        return SUCCESS;
    }

    // Dummy receivePacketSSL: return the next queued packet (or nullptr if none).
    std::unique_ptr<Packet> receivePacketSSL(SSL* ssl) {
        if (!ssl) return nullptr;
        auto &queue = g_receiveQueues[ssl];
        if (queue.empty())
            return nullptr;
        Packet pkt = queue.front();
        queue.pop();
        return std::make_unique<Packet>(pkt);
    }

    // Helper: push a packet into the receive queue for a given SSL pointer.
    void pushReceivePacket(SSL* ssl, const Packet &pkt) {
        g_receiveQueues[ssl].push(pkt);
    }

    // --- Dummy implementations for SSL cleanup functions ---
    extern "C" {
        int SSL_get_fd(const SSL* ssl) { return 0; }
        int SSL_shutdown(SSL* ssl) { return 0; }
        void SSL_free(SSL* ssl) { }
    }

    // Dummy close function (overriding the unistd close)
    int close(int fd) { return 0; }

    // --- Dummy SSL object creation ---
    //
    // We create a dummy SSL pointer by allocating an int on the heap and casting its address.
    SSL* createDummySSL() {
        return reinterpret_cast<SSL*>(new int(42));
    }
    void freeDummySSL(SSL* ssl) {
        delete reinterpret_cast<int*>(ssl);
    }
} // end anonymous namespace

// -----------------------------------------------------------------------------
// Include the server source code for testing.
// We disable the server main() by redefining main before including the file.
// (In a production codebase, you’d build the server as a library with a separate main.)
#define main dummy_main
#include "server.cpp"
#undef main

// (Because server.cpp defines static globals, by including it here we have access to them.)
//
// If needed, you can declare (non‑static) externs for userMap, messages, and messageCounter.
// For this example, we assume that they are accessible in our test (since we include the .cpp file).
// For instance:
extern std::unordered_map<std::string, UserInfo> userMap;
extern std::unordered_map<int, Message> messages;
extern int messageCounter;

// -----------------------------------------------------------------------------
// GoogleTest Unit Tests
// -----------------------------------------------------------------------------

// Test 1: Successful registration using userRegister.
TEST(UserRegisterTest, SuccessfulRegistration) {
    SSL* dummySSL = createDummySSL();
    // Clear any queued packets for our dummy SSL.
    while(!g_receiveQueues[dummySSL].empty()) g_receiveQueues[dummySSL].pop();
    g_sentPackets[dummySSL].clear();
    userMap.clear(); // Start with an empty user database.

    bool result = userRegister(dummySSL, "testuser", "password");
    EXPECT_TRUE(result);

    // Check that a validation packet (op_code 'v') with isValidated == true was sent.
    ASSERT_FALSE(g_sentPackets[dummySSL].empty());
    Packet validationPacket = g_sentPackets[dummySSL].back();
    EXPECT_EQ(validationPacket.op_code, 'v');
    EXPECT_TRUE(validationPacket.isValidated);

    // Also check that the user is now in the userMap with the correct hashed password.
    auto it = userMap.find("testuser");
    ASSERT_NE(it, userMap.end());
    EXPECT_EQ(it->second.password, "password");

    freeDummySSL(dummySSL);
}

// Test 2: Successful login using userLogin when the user exists.
TEST(UserLoginTest, SuccessfulLogin) {
    SSL* dummySSL = createDummySSL();
    g_sentPackets[dummySSL].clear();
    while(!g_receiveQueues[dummySSL].empty()) g_receiveQueues[dummySSL].pop();

    // Set up the userMap with a user "testuser" (with password "password").
    userMap.clear();
    UserInfo user;
    user.password = argon2HashPassword("password");
    user.isOnline = false;
    user.ssl = nullptr;
    userMap["testuser"] = user;

    bool result = userLogin(dummySSL, "testuser", "password");
    EXPECT_TRUE(result);

    // The last validation packet sent should have isValidated == true.
    ASSERT_FALSE(g_sentPackets[dummySSL].empty());
    Packet validationPacket = g_sentPackets[dummySSL].back();
    EXPECT_EQ(validationPacket.op_code, 'v');
    EXPECT_TRUE(validationPacket.isValidated);

    // Check that the user is marked online and their SSL pointer is set.
    auto it = userMap.find("testuser");
    ASSERT_NE(it, userMap.end());
    EXPECT_TRUE(it->second.isOnline);
    EXPECT_EQ(it->second.ssl, dummySSL);

    freeDummySSL(dummySSL);
}

// Test 3: First login attempt fails (wrong password) then succeeds after a new packet.
TEST(UserLoginTest, FailedThenSuccessfulLogin) {
    SSL* dummySSL = createDummySSL();
    g_sentPackets[dummySSL].clear();
    while(!g_receiveQueues[dummySSL].empty()) g_receiveQueues[dummySSL].pop();

    // Set up user "testuser" with password "password".
    userMap.clear();
    UserInfo user;
    user.password = argon2HashPassword("password");
    user.isOnline = false;
    user.ssl = nullptr;
    userMap["testuser"] = user;

    // The first attempt (with a wrong password) will fail. Then the code calls receivePacketSSL.
    // Simulate a follow-up login attempt with the correct password.
    Packet secondAttempt;
    secondAttempt.op_code = 'L';
    secondAttempt.username = "testuser";
    secondAttempt.password = "password";
    pushReceivePacket(dummySSL, secondAttempt);

    bool result = userLogin(dummySSL, "testuser", "wrong");
    EXPECT_TRUE(result);

    // The final validation packet should indicate success.
    ASSERT_FALSE(g_sentPackets[dummySSL].empty());
    Packet validationPacket = g_sentPackets[dummySSL].back();
    EXPECT_EQ(validationPacket.op_code, 'v');
    EXPECT_TRUE(validationPacket.isValidated);

    // Confirm that the user is now marked online.
    auto it = userMap.find("testuser");
    ASSERT_NE(it, userMap.end());
    EXPECT_TRUE(it->second.isOnline);
    EXPECT_EQ(it->second.ssl, dummySSL);

    freeDummySSL(dummySSL);
}

// Test 4: Test a full handleClient flow: the client first logs in (via registration),
// then sends a message, then quits. The test verifies that a confirmation packet is sent,
// that the message is stored (as an offline message for a recipient), and that cleanup occurs.
TEST(HandleClientTest, LoginSendMessageQuitFlow) {
    SSL* dummySSL = createDummySSL();
    g_sentPackets[dummySSL].clear();
    while(!g_receiveQueues[dummySSL].empty()) g_receiveQueues[dummySSL].pop();
    userMap.clear();
    messages.clear();
    messageCounter = 0;

    // Set up a recipient user "receiver" (offline).
    UserInfo receiverInfo;
    receiverInfo.password = "dummy";
    receiverInfo.isOnline = false;
    receiverInfo.ssl = nullptr;
    userMap["receiver"] = receiverInfo;

    // Prepare the sequence of packets that handleClient() will process:
    // 1. A login attempt (op 'L') by "sender" with password "password". (This will fail because the user doesn't exist.)
    Packet loginAttempt;
    loginAttempt.op_code = 'L';
    loginAttempt.username = "sender";
    loginAttempt.password = "password";
    pushReceivePacket(dummySSL, loginAttempt);

    // 2. A registration attempt (op 'R') by "sender" with the same credentials.
    Packet registrationAttempt;
    registrationAttempt.op_code = 'R';
    registrationAttempt.username = "sender";
    registrationAttempt.password = "password";
    pushReceivePacket(dummySSL, registrationAttempt);

    // 3. A message sending request (op 's') where "sender" sends "Hello" to "receiver".
    Packet sendMessage;
    sendMessage.op_code = 's';
    sendMessage.sender = "sender";
    sendMessage.recipient = "receiver";
    sendMessage.message = "Hello";
    pushReceivePacket(dummySSL, sendMessage);

    // 4. A quit request (op 'q') to end the session.
    Packet quitPacket;
    quitPacket.op_code = 'q';
    pushReceivePacket(dummySSL, quitPacket);

    // Call handleClient. It will process the queued packets.
    handleClient(dummySSL);

    // Check that among the packets sent (recorded in g_sentPackets),
    // there is a confirmation (op 'c') for the sent message.
    bool foundConfirmation = false;
    for (const auto &pkt : g_sentPackets[dummySSL]) {
        if (pkt.op_code == 'c' && pkt.sender == "sender" &&
            pkt.recipient == "receiver" && pkt.message == "Hello") {
            foundConfirmation = true;
            break;
        }
    }
    EXPECT_TRUE(foundConfirmation);

    // Since "receiver" was offline, the sent message should be queued as an offline message.
    auto it = userMap.find("receiver");
    ASSERT_NE(it, userMap.end());
    const auto &offlineMsgs = it->second.offlineMessages;
    ASSERT_EQ(offlineMsgs.size(), 1);
    EXPECT_EQ(offlineMsgs[0].content, "Hello");

    // Also, after handleClient(), the sender should have been marked offline.
    auto senderIt = userMap.find("sender");
    ASSERT_NE(senderIt, userMap.end());
    EXPECT_FALSE(senderIt->second.isOnline);

    freeDummySSL(dummySSL);
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------

// (No main() is defined here because GoogleTest provides its own main.)
