

For JSON
g++ -std=c++17 -pthread server.cpp json_wire_protocol.cpp -o server
g++ -std=c++17 -pthread client.cpp json_wire_protocol.cpp -o client


For custom wire protocol
g++ -std=c++17 -pthread server.cpp custom_wire_protocol.cpp -o server
g++ -std=c++17 -pthread client.cpp custom_wire_protocol.cpp -o client
