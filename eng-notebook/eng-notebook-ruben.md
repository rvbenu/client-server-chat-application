Sat Feb 8 Ruben

Used getaddrinfo() to find a feasible address to establish a connection 
between cleint and server. 

`server.cpp` and `client.cpp` assume the messages sent will be 
short for now. 

TODO: When larger messages are sent, they must be broken down. This is to be implemented. 


Sat Feb 9 Ruben 

In `server.cpp`, connections are continuously being accepted by using an 
infinite loop. When a connection is accepted, a thread is crated. Function 
`manage_client_communication` manages client communication independently.
The thread is detached. 

Created files for the class UserAccount. (This class does no longer exist). 

TODO: The `hash_function` for passwords must be implemented.  

So far, the TCP connection with sockets is pretty much managed by 
the current code. 

Next, the validation of usernames and passwords must be implemented and 
the way the server and client will communicate about this must be implemented as well. 

Check comments in server.cpp and client.cpp for more details. 


Sun Feb 10 Ruben

Decided to create a class `packet.h` that has many fields that won't 
necesarily be used for every communication between server and client. 
These packets are the only (main) ones that will be serialized. 

The custom protocol is simple and uses simple strings and spaces (goes 
from strings to binary) using encode. This is faster than the json 
protocol implemented as defined by the lnohmann library for cpp, which
most of the time add unnecessary detail for the purposes of this 
application. 

Based on testing of the two different protocols, the custom protocol 
takes eighty percent of the time it took for the json protocol to send Packet 
objects (serialized according to the protocol 

Implemented the json protocol. Made use of lnohmann json library and 
MessagePack (a built in json-to/from-binary feature for serialization and 
faster transmission of Packet objects).  


Tue Feb 11 Ruben 

Modularized some components in client.cpp and server.cpp to improve the 
quality of utests. E.g., created connect to server function. Added unit 
tests. 

Sun Feb 16

Created server.h with documentation. 

IDEA: Improve modularity by creating functions to manage the different 
Packet objects (depending on `op_code`) as opposed to having big chunks of 
code to handle these inside `handleClient`. 

IDEA: Create a Docker image to make it easier for users to use the 
application (avoiding adding lots of paths to libraries, e.g., openssl, 
argon2, lnohmann-json). 

TODO: Improve documentation for the wire protocol code (e.g., 
json_wire_procol.cpp, custom_wire_protocol.cpp, packet.cpp). If possible, 
do the same for the client code.

TODO: Implement new fields in the `Packet` class such as `version`.

TODO: Improve test suit. 





Sun Feb 23 

Questions to have in mind: 

Does the use of this tool make the application easier or more difficult? 
What does it do to the size of the data passed? How does it change the 
structure of the client? The server? How does this change the testing of 
the application?




To get started with gRPC: `https://grpc.io/docs/languages/cpp/quickstart/`

Compile chat.proto: `protoc --proto_path=. --cpp_out=. --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` chat.proto`

Resulting files: 
chat.pb.h (Protocol Buffers header)
chat.pb.cc (Protocol Buffers implementation)
chat.grpc.pb.h (gRPC service header)
chat.grpc.pb.cc (gRPC service implementation)




