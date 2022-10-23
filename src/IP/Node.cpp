#include "include/IP/Node.h"
#include <vector>
#include <chrono>
#include <thread>



// std::vector<RIPentry> entries; 

/**
 * Constructor
*/
Node::Node(unsigned int port) : 
    port(port), 
    socket(my_io_context, {ip::udp::v4(), port})
{
    using namespace std::placeholders;

    auto testFunc = std::bind(&Node::testHandler, this, _1, _2);
    registerHandler(0, testFunc);

    auto ripFunc = std::bind(&Node::ripHandler, this, _1, _2);
    registerHandler(200, ripFunc);
}

/**
 * Adds interface 
*/
void Node::addInterface(
    int id,
    std::string srcAddr,
    std::string destAddr,
    unsigned int destPort,
    int cost) 
{
    Interface interface;
    interface.id = id;
    interface.up = true;
    interface.srcAddr = srcAddr;
    interface.destAddr = destAddr;
    interface.destPort = destPort;

    // 1) Set up ARP table
    ARPTable.insert(std::make_pair(id, interface));

    // 2) Set up routing table
    if (destAddr != srcAddr) {
        std::tuple<int, int> nextHop = std::make_tuple(id, cost);
        routingTable.insert(std::make_pair(destAddr, nextHop));
    }
}

bool Node::enableInterface(int id) {
    if (!ARPTable.count(id)) {
        std::cerr << "interface " << id << " does not exist" << std::endl;
        return false;
    } else if (ARPTable[id].up) {
        std::cerr << "interface " << id << " is already up" << std::endl;
        return false;
    }

    ARPTable[id].up = true;
    return true;
}

bool Node::disableInterface(int id) {
    if (!ARPTable.count(id)) {
        std::cerr << "interface " << id << " does not exist" << std::endl;
        return false;
    } else if (!ARPTable[id].up) {
        std::cerr << "interface " << id << " is already down" << std::endl;
        return false;
    }

    ARPTable[id].up = false;
    return true;
}

std::vector<Interface> Node::getInterfaces() {
    std::vector<Interface> interfaces;
    for (auto& [_, interface] : ARPTable) {
        if (interface.id >= 0) {
            interfaces.push_back(interface);
        }
    }
    return interfaces;
}

std::vector<std::tuple<std::string, std::string, int>> Node::getRoutes() {
    std::vector<std::tuple<std::string, std::string, int>> routes;
    for (auto& [destAddr, interfaceInfo] : routingTable) {
        auto [id, cost] = interfaceInfo;

        Interface& interface = ARPTable[id];
        if (interface.up) {
            auto route = std::make_tuple(destAddr, interface.destAddr, cost);
            routes.push_back(route);
        }
    }
    return routes;
}

// Note: copy/pasted from lecture example
// Compute the IP checksum
// This is a modified version of the example in RFC 1071
// https://datatracker.ietf.org/doc/html/rfc1071#section-4.1
uint16_t Node::ip_sum(void *buffer, int len) {
  uint8_t *p = (uint8_t *)buffer;
  uint16_t answer;
  long sum = 0;
  uint16_t odd_byte = 0;

  while (len > 1) {
    uint16_t c = 0;
    c = (p[1] << 8) | p[0];
    
    sum += c;
    p += 2;
    len -= 2;
  }

  if (len == 1) {
    *(uint8_t*)&odd_byte = *p;
    sum += odd_byte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;

}

// int Node::calculateChecksum(std::shared_ptr<struct ip> ipHeader) {
//     int prevChecksum = ipHeader->ip_sum;
//     ipHeader->ip_sum = 0;

//     char *data = (char *)ipHeader.get();

//     // Initialize accumulator
//     uint32_t acc = 0xffff;
//     for (size_t i = 0; i + 1 < sizeof(ipHeader); i += 2) {
//         uint16_t word;
//         memcpy(&word, data + i, 2);
//         acc += ntohs(word);
//         if (acc > 0xffff) {
//             acc -= 0xffff;
//         }
//     }

//     // Handle any partial blocks at end 
//     if (sizeof(ipHeader) % 2 == 1) {
//         uint16_t word = 0;
//         memcpy(&word, data + sizeof(ipHeader) - 1, 1);
//         acc += ntohs(word);
//         if (acc > 0xffff) {
//             acc -= 0xffff;
//         }
//     }

//     ipHeader->ip_sum = prevChecksum;
//     // Return checksum in network byte order
//     return htons(~acc);
// }


/**
 * Sends message (from CLI)
*/
void Node::send(
    std::string address, 
    int protocol, 
    const std::string& payload) 
{   
    std::cout << "calling send in node" << std::endl;

    // #todo handle cases where address or next hop not in arp table
    // specifically, routing table case
    auto [nextHop, cost] = routingTable[address];

    // Check if interface has been disabled
    if (!ARPTable[nextHop].up) {
        std::cerr << "Cannot send to " << address << ", it is an unreachable address." << std::endl;
        return;
    }

    unsigned int destPort = ARPTable[nextHop].destPort;
    std::string srcAddr = ARPTable[nextHop].srcAddr;
    
    // Build IPv4 header
    std::shared_ptr<struct ip> ip_header = std::make_shared<struct ip>();

    ip_header->ip_hl     = 5;   // always 20 if no IP options // why is there an error in compiler for this
    ip_header->ip_v      = 4;    // version is IPv4
    ip_header->ip_tos    = 0;    // n/a
    ip_header->ip_len    = htons(20 + payload.length());
    ip_header->ip_id     = 0;    // n/a
    ip_header->ip_off    = 0;    // n/a
    ip_header->ip_ttl    = 16;   // initial time to live
    ip_header->ip_p      = protocol;    // ipv6/default
    ip_header->ip_sum    = 0;    // checksum should be zeroed out b4 calc
    ip_header->ip_src    = {inet_addr(srcAddr.c_str())};
    ip_header->ip_dst    = {inet_addr(address.c_str())};

    ip_header->ip_sum = ip_sum(ip_header.get(), ip_header->ip_hl * 4);

    // Declare boost array that will store the new payload
    // #todo maybe fix size later
    unsigned int new_size = sizeof(struct ip) + payload.size();
    std::vector<char> new_payload(new_size);

    // Copy contents of old ip header and payload into new payload
    memcpy(&new_payload[0], ip_header.get(), sizeof(struct ip));
    // memcpy(&new_payload[0] + sizeof(struct ip), &payload, payload.size());
    memcpy(&new_payload[0] + sizeof(struct ip), payload.data(), payload.size());

    
    // // Convert ip_header to a string
    // char b[sizeof(struct ip)];
    // std::cpy(b, ip_header, sizeof(struct ip));
    // b[sizeof(struct ip)] = '\0'; 

    // std::string iph_str(b);
    // std::string new_string = iph_str + payload;

    // #TODO send it via udp and check if this works
    socket.send_to(buffer(new_payload), {ip::udp::v4(), destPort});
}

void Node::forward(std::shared_ptr<struct ip> ipHeader, 
        const std::string& payload, 
        unsigned int forwardPort) {

    ipHeader->ip_ttl--;
    ipHeader->ip_sum = ip_sum(ipHeader.get(), ipHeader->ip_len * 4);

    unsigned int newSize = sizeof(struct ip) + payload.size();
    std::vector<char> newPayload(newSize);

    memcpy(&newPayload[0], ipHeader.get(), sizeof(struct ip));
    memcpy(&newPayload[sizeof(struct ip)], &payload[0], payload.size());

    socket.send_to(buffer(newPayload), {ip::udp::v4(), forwardPort});
}


/**
 * @brief sends rip packet RIP RIP
 * 
 */
void Node::sendRIPpacket(std::string dest, u_int type, std::vector<RIPentry> entries) {
    // create struct (the payload)
    struct RIPpacket packet;
    packet.command = htons(type);    
    packet.num_entries = htons(entries.size()); 

    // // ip::address_v4::from_string("255.255.255.255").to_ulong;
    // #todo make safe pointer
    int total_size = 4 + (packet.num_entries * sizeof(RIPentry));
    std::string payload;
    payload.resize(total_size);

    // copy front
    memcpy((char *)payload.data(), &packet, 4); 

    // copy rest
    int offset = packet.num_entries * sizeof(RIPentry);
    memcpy((char *)payload.data() + offset, &entries, total_size - 4);

    // send w/ 200 as protocol
    send(dest, 200, payload);
}


/**
 * @brief Implements split horizon with poison reverse.
 * Uses routing table to see if next hop matches with destination.
 * If yes, then cost should be set to infinity/16. 
 * 
 * @param dest 
 * @param updates 
 * @return std::vector<RIPentry> 
 */
std::vector<RIPentry> Node::SHPR(std::string packetDest, std::vector<RIPentry> updates) {
    std::vector<RIPentry> results;

    // Loop through updates and check if next hop for each RIP entry destination
    // is the dest of this RIP message. If yes, set cost to infinity/16.
    for (RIPentry entry : updates) {
        // #TODO think about error handling when entry doesn't exist?
        // Convert u_int_32_t to std::string
        std::string entryDest = ip::make_address_v4(entry.address).to_string();
        int entryDestID = std::get<0>(routingTable[entryDest]);

        // Find next hop *if* it exists and is not down
        Interface nextHop = ARPTable[entryDestID];

    }
}


/**
 * @brief Creates vector of RIP entries from corresponding routing table entries.
 * 
 * @param routes 
 * @return std::vector<RIPentry> 
 */
std::vector<RIPentry> Node::createRIPentries(std::unordered_map<std::string, std::tuple<int, int>> routes) {
    std::vector<RIPentry> ripEntries;

    u_int32_t mask = ip::address_v4::from_string("255.255.255.255").to_ulong;

    for (auto [dest, tup] : routes) {
        u_int32_t destInt = ip::address_v4::from_string(dest).to_ulong
        RIPentry entry = {std::get<1>(tup), destInt, mask};
        ripEntries.push_back(entry);
    }

    return ripEntries;
}


/**
 * @brief On start it sends a request to all interfaces. Then periodically sends
 * updates ("responses") of the full routing table every 5 seconds while implementing
 * split horizon + poison reverse
 * 
 */
void Node::RIP() {
    std::cout << "thread for RIP started" << std::endl;

    // Send request to each interface
    for (auto& [id, interface] : ARPTable) {
        if (id >= 0) {
            std::cout << "sending request to " << interface.destAddr << std::endl;

            std::vector<RIPentry> entries = std::vector<RIPentry>();
            sendRIPpacket(interface.destAddr, 1, entries); // type 1 for request
        }
    }

    // every 5 seconds, send out a response/update 
    // implements split horizon + poison reverse
    while (true) {

        std::vector<RIPentry> updates;
        
        // std::cout << "I would send" << std::endl;

        std::chrono::seconds dura(5);
        std::this_thread::sleep_for(dura);
    }
}

void Node::receive() {
    while (true) {
        try {
            boost::array<char, MAX_IP_PACKET_SIZE> receiveBuffer;
            ip::udp::endpoint receiverEndpoint;

            size_t len = socket.receive_from(buffer(receiveBuffer), receiverEndpoint);
            genericHandler(receiveBuffer, len, receiverEndpoint);
        } catch (std::exception& e) {
            std::cerr << "Error: receiving packet: " << e.what() << std::endl;
        }
    }
}

void Node::registerHandler(int protocol, ProtocolHandler func) {
    handlers[protocol] = func;
}

void Node::genericHandler(boost::array<char, MAX_IP_PACKET_SIZE> receiveBuffer, 
        size_t receivedBytes, ip::udp::endpoint receiverEndpoint) {
    // Need to check whether the port message was sent from appears in ARP Table
    // if (receiver_endpoint.port() != port) {
        // return;
    // }

    struct ip *ipHeaderRaw = (struct ip *)(&receiveBuffer[0]);

    // Reconstruct IPv4 header
    std::shared_ptr<struct ip> ipHeader = std::make_shared<struct ip>();
    memcpy(ipHeader.get(), ipHeaderRaw, sizeof(ipHeaderRaw));

    // Get payload/data from IP packet
    std::string payload(receiveBuffer.begin() + sizeof(ipHeader), receiveBuffer.begin() + receivedBytes);

    // Compute checksum
    if (ip_sum(ipHeader.get(), ipHeader->ip_len) != (ipHeader->ip_sum * 4)) {
        return;
    }

    // check 
    // branch here

    // Is the destination address in the routing table?
    if (!routingTable.count(ip::make_address_v4(ntohl(ipHeader->ip_dst.s_addr)).to_string())) {
        return;
    }

    // Calculate whether packet has reached destination
    auto [nextHop, cost] = routingTable[ip::make_address_v4(ntohl(ipHeader->ip_dst.s_addr)).to_string()];

    // Check if interface has been disabled
    if (!ARPTable[nextHop].up) {
        return;
    }

    unsigned int destPort = ARPTable[nextHop].destPort;
    if (destPort == port) {
        if (handlers.count(ipHeader->ip_p)) {
            handlers.find(ipHeader->ip_p)->second(ipHeader, payload);
        }
        throw std::runtime_error("Error: handler for protocol " + 
                std::to_string(ipHeader->ip_p) + " not found");
    }

    // Packet has not reached destination so forward packet
    forward(ipHeader, payload, destPort);
}

void Node::testHandler(std::shared_ptr<struct ip> ipHeader, std::string& data) {
    auto src_ip = ip::make_address_v4(ipHeader->ip_src.s_addr);
    auto dest_ip = ip::make_address_v4(ipHeader->ip_dst.s_addr);

    std::cout << "---Node received packet!---" << std::endl;
    std::cout << "\t\tsource IP      : " << src_ip << std::endl;
    std::cout << "\t\tdestination IP : " << dest_ip << std::endl;
    std::cout << "\t\tprotocol       : " << ipHeader->ip_p << std::endl;
    std::cout << "\t\tpayload length : " << data.size() << std::endl;
    std::cout << "\t\tpayload        : " << data << std::endl;
    std::cout << "---------------------------" << std::endl;
    return;
}

void Node::ripHandler(std::shared_ptr<struct ip> ipHeader, std::string& data) {
    std::cout << "You have entered the RIP handler!" << std::endl;
    return;
}
