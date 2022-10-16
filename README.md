# IP

## Todos

**Set up**

1. Set up CMAKE
2. Set up boost
3. Set up helper functions
4. Figure out what clean should do
5. Talk to Madhav about what to put in .gitignore (tools?)
6. Talk about branches and how we want to do workflow
7. CMAKE library for boost

**Part One: IP-in-UDP Encapsulation**

1. "IP-in-UDP encapsulation"
2. Forwarding

**Part Two: Routing**

1. Routing

**Random (for jack)**

- (DONE) Run the references to make sure you understand what is going on
- Talk to someone about header files etc. cpp design
- Need destructors for which functions?
- **Structure for main/libraries etc.**
- fprintf vs stderr
- interface vs public include directories/libraries

## Questions for design check

- What should clean up do
- Thread structure
- What is being used when one node has multiple IPs -- NAT or ARP?

## Design

Three main folders:

1. Link
2. IP
3. TCP

Link should contain files that emulate the link layer using UDP.

IP should contain files that emulate nodes that follow the IP protocol.

TCP is for later.

The include folder is for headers.

## CMAKE and Make Information

_Insert directions on using cmake and make_

## Implementation Details

Node constructor:

- Create send socket
- Bind socket to specific port
- Store port
  Node addInterface:

- Given (port, IP)
- Update ARP table
- Update routing table if port = this node's port
- Update vector/unordered map of all interfaces storing up and down?

Node send:

- Given (port, protocol, IP)
- Look up to destination
- Construct IPv4 header
- Call sendPacket in Link
