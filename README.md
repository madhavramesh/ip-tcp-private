# IP

The handout specifies the following three questions:
1. How you abstract your link layer and its interfaces
2. The thread model for your RIP implementation
3. The steps you will need to process IP packets

The first question is answered in the "Link Layer + Interfaces" section.

The second can be found in the "Threading + RIP" section.

The third can be found in the "IP Layer + Routing" section.

# Link Layer + Interfaces

We abstracted away the link layer and its interfaces through a struct called ```Interface``` and functions that wrap around UDP socket calls. 

The ```Interface``` contains an ```id```, a boolean that represents if it is "up" or "down," and a string that represents it's local address. 

The functions that wrap around UDP socket calls are helper functions serialize/deserialize IP headers and construct/deconstruct the necessary UDP packets.

# IP Layer + Routing

A single node has private variables to represent the following notable structures:
- The socket it uses to listen and send messages
- A map that keeps track of its interfaces
- A map representing the ARP table
- A map representing the routing table

To actually process IP packets, the node has a thread that continually listens on the socket for incoming messages. Then the following steps are taken:
- It deserializes the first 20 bytes into an IP struct
- It checks if the the packet has reached it's final destination
  - If the current node is the final destination, it calls the appropriate handler based on the IP protocol number (so either the "Test" or "RIP" handler)
  - If the current node is not the final destination, the node forwards the message via the ARP and routing tables

# Threading + RIP

For each node there were 3 main threads. 

One thread was for listening for commands from the CLI. It listens for user commands and calls the respective handlers. 

One thread was for sending RIP messages every 5 seconds. This thread sends out the node's routing table after applying split horizon and poisoned reverse to it. 

One thread for for listening for incoming messages. If those messages were test packets, it would either forward or handle them depending on the packet's final destination. If those messages were RIP packets, it would handle the packet by updating the node's routing table and sending triggered updates (after applying split horizon and poisoned reverse) if needed.

# Project Structure

Inside the ```src``` directory there are three main folders: 

1. IP
2. repl
3. TCP

The ```IP``` folder contains a file ```IPCommands.cpp``` that contains implementations of CLI commands. The file ```Node.cpp``` contains implementations of internet protocol logic for a single node e.g. rip packets, forwarding, split horizon and poisoned reverse, creating IP headers, etc.

The ```repl``` folder contains a generic REPL implementation.

The ```TCP``` currently does not contain anything.

# CMAKE and Make Information

To set up and build the project we need to create a ```build``` directory and run ```make```. To do this, run the following commands from the root directory
```
mkdir build 
cd build
cmake ..
make
```
A file called ```node``` should now exist in the ```build``` directory.

# Bugs

None know so far.
