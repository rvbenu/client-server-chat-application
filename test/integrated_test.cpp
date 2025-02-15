// integrated_test.cpp
//
// This integrated test starts the server in the background, then runs two client scenarios:
// 1. Registration test: A client registers a new user.
// 2. Login and send-message test: A client logs in and sends a message.
// Finally, the test shuts down the server.
//
// To compile:
//   g++ -std=c++17 -pthread integrated_test.cpp -o integrated_test
//
// To run:
//   ./integrated_test

#include <cstdlib>
#include <iostream>
#include <thread>
#include <chrono>
#include <string>

int main() {
    // Choose a port for the test (ensure it's not in use)
    int port = 54000;

    // ---------- Start the Server ----------
    // Launch the server in the background. This command assumes your server binary is named "server".
    std::string serverCommand = "./server " + std::to_string(port) + " &";
    std::cout << "Starting server with command: " << serverCommand << std::endl;
    std::system(serverCommand.c_str());

    // Allow the server a moment to initialize
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // ---------- Test 1: Registration ----------
    // Simulate a client registration command.
    // The command sends:
    //   R<US>testuser<US>password  (R for registration, using ASCII Unit Separator, U+001F)
    // followed by a quit command ("q")
    // (The -e option to echo interprets \x1F correctly.)
    std::string regInput = "R\x1Ftestuser\x1Fpassword\nq\n";
    std::string regClientCmd = "echo -e '" + regInput + "' | ./client 127.0.0.1 " + std::to_string(port);
    std::cout << "Running registration client with command: " << regClientCmd << std::endl;
    int regResult = std::system(regClientCmd.c_str());
    std::cout << "Registration client exited with code: " << regResult << std::endl;

    // Wait a moment before running the next test
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // ---------- Test 2: Login and Send Message ----------
    // This test assumes that "testuser" is already registered.
    // It sends:
    //   L<US>testuser<US>password          (Login)
    //   s<US>testuser<US>otheruser<US>Hello   (Send message from testuser to otheruser)
    //   q                                   (Quit)
    std::string loginMsgInput = "L\x1Ftestuser\x1Fpassword\ns\x1Ftestuser\x1Fotheruser\x1FHello\nq\n";
    std::string loginMsgClientCmd = "echo -e '" + loginMsgInput + "' | ./client 127.0.0.1 " + std::to_string(port);
    std::cout << "Running login & send message client with command: " << loginMsgClientCmd << std::endl;
    int loginMsgResult = std::system(loginMsgClientCmd.c_str());
    std::cout << "Login & send message client exited with code: " << loginMsgResult << std::endl;

    // Allow some time for the server to process the messages
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // ---------- Shut Down the Server ----------
    // Here we use pkill to terminate the server process.
    // (Make sure that no other process named "server" is running.)
    std::cout << "Shutting down server..." << std::endl;
    std::system("pkill server");

    std::cout << "Integrated tests completed." << std::endl;
    return 0;
}
