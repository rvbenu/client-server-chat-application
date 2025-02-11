# Chat Application

## server.cpp

Compile: `g++ -std=c++17 -pthread server.cpp custom_wire_protocol.cpp \
    -I/opt/homebrew/opt/argon2/include \
    -I/opt/homebrew/opt/openssl@3/include \
    -L/opt/homebrew/opt/argon2/lib \
    -L/opt/homebrew/opt/openssl@3/lib \
    -largon2 -lssl -lcrypto \
    -o server`

Compile (JSON): `g++ -std=c++17 -pthread server.cpp json_wire_protocol.cpp \
    -I/opt/homebrew/opt/argon2/include \
    -I/opt/homebrew/opt/openssl@3/include \
    -L/opt/homebrew/opt/argon2/lib \
    -L/opt/homebrew/opt/openssl@3/lib \
    -largon2 -lssl -lcrypto \
    -o server`

Usage: ./server 55000

## client.cpp

Compile: `g++ -std=c++17 -pthread client.cpp custom_wire_protocol.cpp \
    -I/opt/homebrew/opt/argon2/include \
    -I/opt/homebrew/opt/openssl@3/include \
    -L/opt/homebrew/opt/argon2/lib \
    -L/opt/homebrew/opt/openssl@3/lib \
    -largon2 -lssl -lcrypto \
    -o client`

Compile (JSON): `g++ -std=c++17 -pthread client.cpp json_wire_protocol.cpp \
    -I/opt/homebrew/opt/argon2/include \
    -I/opt/homebrew/opt/openssl@3/include \
    -L/opt/homebrew/opt/argon2/lib \
    -L/opt/homebrew/opt/openssl@3/lib \
    -largon2 -lssl -lcrypto \
    -o client`


Usage: ./client 127.0.0.1 55000
