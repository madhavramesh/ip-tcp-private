#include <vector>
#include <chrono>
#include <thread>
#include <unordered_set>
#include <mutex>

#include "include/IP/Node.h"
#include "include/repl/colors.h"

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
    unsigned int destPort) 
{
    if (!interfaces.count(id)) {
        Interface interface;
        interface.id = id;
        interface.up = true;
        interface.srcAddr = srcAddr;

        // Add interface to interfaces table
        interfaces[id] = interface;
    }

    // Set up ARP table
    auto ARPVal = std::make_tuple(destPort, id);
    ARPTable.insert(std::make_pair(destAddr, ARPVal));

    ARPVal = std::make_tuple(port, id);
    ARPTable.insert(std::make_pair(srcAddr, ARPVal));

    // Initially, routing table only contains routes from node to itself
    auto t = chrono::steady_clock::now();
    auto routingVal = std::make_tuple(srcAddr, 0, t);
    { 
        std::scoped_lock lock(routingTableMtx);
        routingTable.insert(std::make_pair(srcAddr, routingVal));
    }
}

bool Node::enableInterface(int id) {
    if (!interfaces.count(id)) {
        std::cerr << red << "interface " << id << " does not exist" << reset << std::endl;
        return false;
    } else if (interfaces[id].up) {
        std::cerr << red << "interface " << id << " is already up" << reset << std::endl;
        return false;
    }

    interfaces[id].up = true;
    return true;
}

bool Node::disableInterface(int id) {
    if (!interfaces.count(id)) {
        std::cerr << red << "interface " << id << " does not exist" << reset << std::endl;
        return false;
    } else if (!interfaces[id].up) {
        std::cerr << red << "interface " << id << " is already down" << reset << std::endl;
        return false;
    }

    interfaces[id].up = false;
    return true;
}

std::vector<std::tuple<Interface, std::string, int>> Node::getInterfaces() {
    std::vector<std::tuple<Interface, std::string, int>> interfacesToDisplay;

    std::unordered_set<int> addedInterfaceIds;
    for (auto& [nextHopAddr, nextHopInfo] : ARPTable) {
        auto [nextHopPort, interfaceId] = nextHopInfo;
        if (!interfaces.count(interfaceId)) {
            continue;
        }
        if (addedInterfaceIds.count(interfaceId)) {
            continue;
        }

        Interface interface = interfaces[interfaceId];
        if (nextHopAddr == interface.srcAddr) {
            continue;
        }

        addedInterfaceIds.insert(interfaceId);
        interfacesToDisplay.push_back(std::make_tuple(interface, nextHopAddr, nextHopPort));
    }
    return interfacesToDisplay;
}

std::vector<std::tuple<std::string, std::string, int>> Node::getRoutes() {
    // 1) Check last time updated
    cleanUpRoutingTable(routingTable);
    
    std::vector<std::tuple<std::string, std::string, int>> routes;

    {
        std::scoped_lock lock(routingTableMtx);

        for (auto& [destAddr, nextHop] : routingTable) {
            auto [nextHopAddr, cost, time] = nextHop;

            int interfaceId = get<1>(ARPTable[nextHopAddr]);
            Interface& interface = interfaces[interfaceId];
            if (interface.up) {
                auto route = std::make_tuple(destAddr, nextHopAddr, cost);
                routes.push_back(route);
            }
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


/**
 * @brief This send should be called from the CLI
 * 
 */
void Node::sendCLI(std::string address, const std::string& payload) {
    // 2) Check last time updated
    cleanUpRoutingTable(routingTable);
    
    // Check if it exists in the routing table.
    // Useful for perhaps when routing table entry expires
    std::string nextHopAddr;
    int cost;
    std::chrono::time_point<std::chrono::steady_clock> time;
    {
        std::scoped_lock lock(routingTableMtx);
        if (routingTable.find(address) == routingTable.end()) {
            std::cerr << red << "Cannot send to " << address 
                << ", it is an unreachable address." << reset << std::endl;
            return;
        }
        std::tie(nextHopAddr, cost, time) = routingTable[address];
    }
    // auto [nextHopAddr, cost, time] = routingTable[address];
    int interfaceId = std::get<1>(ARPTable[nextHopAddr]);

    // Check if interface has been disabled
    // Useful if a user takes down a route
    if (!interfaces[interfaceId].up) {
        std::cerr << red << "Cannot send to " << address 
            << ", it is an unreachable address." << reset << std::endl;
        return;
    }

    send(address, nextHopAddr, payload, 0);
}

/**
 * @brief Creates vector of RIP entries from corresponding routing table entries.
 * 
 * @param routes 
 * @return std::vector<RIPentry> 
 */
RIPpacket Node::createRIPpacket(uint16_t type, 
        std::unordered_map<std::string, std::tuple<std::string, int, std::chrono::time_point<std::chrono::steady_clock>>> routes) {
    struct RIPpacket packet;
    packet.command = type;

    uint32_t mask = ip::address_v4::from_string("255.255.255.255").to_ulong();
    for (auto [destAddr, nextHopTup] : routes) {
        auto [nextHop, cost, t] = nextHopTup;
        int interfaceID = std::get<1>(ARPTable[nextHop]);
        // Only send if interface is up
        if (interfaces[interfaceID].up) {
            uint32_t destInt = ip::address_v4::from_string(destAddr).to_ulong();
            RIPentry entry = { cost, destInt, mask };
            packet.entries.push_back(entry);
        }
    }
    packet.num_entries = packet.entries.size();
    return packet;
}

void Node::sendRIPpacket(std::string address, struct RIPpacket packet) {
    // 1) Check last time updated
    cleanUpRoutingTable(routingTable);
    
    int interfaceId = std::get<1>(ARPTable[address]);
    // Check if interface has been disabled
    if (!interfaces[interfaceId].up) {
        return;
    }

    packet = SHPR(address, packet);

    packet.command = htons(packet.command);
    packet.num_entries = htons(packet.num_entries);
    for (auto &entry : packet.entries) {
        entry.cost = htonl(entry.cost);
        entry.address = htonl(entry.address);
        entry.mask = htonl(entry.mask);
    }

    // // ip::address_v4::from_string("255.255.255.255").to_ulong;
    // #todo make safe pointer
    int front_size = sizeof(packet.command) + sizeof(packet.num_entries);
    int total_size = front_size + (packet.entries.size() * sizeof(RIPentry));

    std::string payload;
    payload.resize(total_size);

    // copy front
    memcpy((char *)payload.data(), &packet.command, sizeof(packet.command)); 
    memcpy((char *)payload.data() + sizeof(packet.command), 
        &packet.num_entries, sizeof(packet.num_entries)); 

    // copy rest
    memcpy((char *)payload.data() + front_size, &packet.entries[0], total_size - front_size);

    send(address, address, payload, 200);
}

/**
 * @brief Implements split horizon with poison reverse.
 * Uses routing table to see if next hop matches with destination.
 * If yes, then cost should be set to infinity/16. 
 *
 * Assumes that routingTable is locked upon entry
 * 
 * @param dest 
 * @param updates 
 * @return std::vector<RIPentry> 
 */
struct RIPpacket Node::SHPR(std::string packetDestAddr, struct RIPpacket packet) {
    struct RIPpacket modifiedPacket;
    modifiedPacket.command = packet.command;

    // Loop through updates and check if next hop for each RIP entry destination
    // is the dest of this RIP message. If yes, set cost to infinity/16.
    for (RIPentry& entry : packet.entries) {
        // #TODO think about error handling when entry doesn't exist?
        // Convert u_int_32_t to std::string
        std::string entryDest = ip::make_address_v4(entry.address).to_string();
        std::string nextHopAddr = std::get<0>(routingTable[entryDest]);

        // Find next hop *if* it exists and is not down
        int interfaceId = std::get<1>(ARPTable[nextHopAddr]);
        if (!interfaces[interfaceId].up) {
            continue;
        }

        if (nextHopAddr == packetDestAddr) {
            entry.cost = 16;
        }
        modifiedPacket.entries.push_back(entry);
    }

    modifiedPacket.num_entries = modifiedPacket.entries.size();
    return packet;
}

/**
 * Sends message (from CLI)
*/
void Node::send(
    std::string address, 
    std::string nextHopAddr,
    const std::string& payload,
    int protocol) 
{   
    auto [destPort, interfaceId] = ARPTable[nextHopAddr];
    std::string srcAddr = interfaces[interfaceId].srcAddr;
    
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
    memcpy(&new_payload[0] + sizeof(struct ip), &payload[0], payload.size());

    // #TODO send it via udp and check if this works
    socket.send_to(buffer(new_payload), {ip::udp::v4(), destPort});
}

void Node::forward(std::string address, 
    const std::string& payload,
    std::shared_ptr<struct ip> ipHeader) {
    // 3) Check last time updated
    std::cout << "forwarding" << std::endl;
    cleanUpRoutingTable(routingTable);


    std::string nextHopAddr;
    {
        std::scoped_lock lock(routingTableMtx);
        nextHopAddr = std::get<0>(routingTable[address]);
    }
    unsigned int destPort = std::get<0>(ARPTable[nextHopAddr]);

    ipHeader->ip_ttl--;
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = ip_sum(ipHeader.get(), ipHeader->ip_hl * 4);

    unsigned int newSize = sizeof(struct ip) + payload.size();
    std::vector<char> newPayload(newSize);

    memcpy(&newPayload[0], ipHeader.get(), sizeof(struct ip));
    memcpy(&newPayload[sizeof(struct ip)], &payload[0], payload.size());

    socket.send_to(buffer(newPayload), {ip::udp::v4(), destPort});
}

void Node::receive() {
    while (true) {
        try {
            boost::array<char, MAX_IP_PACKET_SIZE> receiveBuffer;
            ip::udp::endpoint receiverEndpoint;

            size_t len = socket.receive_from(buffer(receiveBuffer), receiverEndpoint);
            genericHandler(receiveBuffer, len, receiverEndpoint);
        } catch (std::exception& e) {
            std::cerr << red << "Error: receiving packet: " << e.what() << reset << std::endl;
        }
    }
}


/**
 * @brief On start it sends a request to all interfaces. Then periodically sends
 * updates ("responses") of the full routing table every 5 seconds while implementing
 * split horizon + poison reverse
 *
 */
void Node::RIP() {
    // Send request to each interface
    for (auto& [nextHopAddr, nextHopInfo] : ARPTable) {
        int interfaceId = std::get<1>(nextHopInfo);
        // Don't send RIP packets to node's own IP addresses
        if (nextHopAddr == interfaces[interfaceId].srcAddr) {
            continue;
        }

        struct RIPpacket packet;
        packet.command = 1;
        packet.num_entries = 0;
        packet.entries = {};

        sendRIPpacket(nextHopAddr, packet); // type 1 for request
    }

    // every 5 seconds, send out a response/update 
    // implements split horizon + poison reverse
    while (true) {
        RIPpacket packet;
        {
            std::scoped_lock lock(routingTableMtx);
            packet = createRIPpacket(2, routingTable);
        }

        for (auto& [nextHopAddr, nextHopInfo] : ARPTable) {
            int interfaceId = std::get<1>(nextHopInfo);
            // Don't send RIP packets to node's own IP addresses
            if (nextHopAddr != interfaces[interfaceId].srcAddr) {
                sendRIPpacket(nextHopAddr, packet);
            }
        }

        std::chrono::seconds dura(5);
        std::this_thread::sleep_for(dura);
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
    memcpy(ipHeader.get(), ipHeaderRaw, sizeof(struct ip));

    // Get payload/data from IP packet
    std::string payload(receiveBuffer.begin() + sizeof(struct ip), receiveBuffer.begin() + receivedBytes);

    // Compute checksum
    int prevCheckSum = ipHeader->ip_sum;
    ipHeader->ip_sum = 0;
    if (ip_sum(ipHeader.get(), ipHeader->ip_hl * 4) != prevCheckSum) {
        return;
    }
    ipHeader->ip_sum = prevCheckSum;

    // check 
    // branch here

    // Is the destination address in the routing table?
    std::string destAddr = ip::make_address_v4(ntohl(ipHeader->ip_dst.s_addr)).to_string();
    std::string nextHopAddr;
    int cost;
    std::chrono::time_point<std::chrono::steady_clock> time;
    {
        std::scoped_lock lock(routingTableMtx);
        if (!routingTable.count(destAddr)) {
            return;
        }
        std::tie(nextHopAddr, cost, time) = routingTable[destAddr];
    }

    // Calculate whether packet has reached destination
    // auto [nextHopAddr, cost, time] = routingTable[destAddr];
    auto [destPort, interfaceId] = ARPTable[destAddr];

    // Check if interface has been disabled
    if (!interfaces[interfaceId].up) {
        return;
    }

    if (destPort == port) {
        if (handlers.count(ipHeader->ip_p)) {
            handlers.find(ipHeader->ip_p)->second(ipHeader, payload);
            return;
        }
        throw std::runtime_error("Error: handler for protocol " + 
                std::to_string(ipHeader->ip_p) + " not found");
    }

    // Packet has not reached destination so forward packet
    if (ipHeader->ip_ttl > 0) {
        forward(destAddr, payload, ipHeader);
    }
}

void Node::testHandler(std::shared_ptr<struct ip> ipHeader, std::string& payload) {
    auto src_ip = ip::make_address_v4(ntohl(ipHeader->ip_src.s_addr));
    auto dest_ip = ip::make_address_v4(ntohl(ipHeader->ip_dst.s_addr));

    std::cout << "\r" << std::flush;
    std::cout << "---Node received packet!---" << std::endl;
    std::cout << "\tsource IP      : " << src_ip << std::endl;
    std::cout << "\tdestination IP : " << dest_ip << std::endl;
    std::cout << "\tprotocol       : " << ipHeader->ip_p << std::endl;
    std::cout << "\tpayload length : " << payload.size() << std::endl;
    std::cout << "\tpayload        : " << payload << std::endl;
    std::cout << "---------------------------" << std::endl;
    std::cout << "> " << std::flush;
}

void Node::ripHandler(std::shared_ptr<struct ip> ipHeader, std::string& payload) {
    struct RIPpacket receivedPacket;
    
    memcpy(&receivedPacket.command, (char *)payload.data(), sizeof(receivedPacket.command));
    memcpy(&receivedPacket.num_entries, (char *)payload.data() + sizeof(receivedPacket.command),
        sizeof(receivedPacket.num_entries));
        
    int front_size = sizeof(receivedPacket.command) + sizeof(receivedPacket.num_entries);
    receivedPacket.command = ntohs(receivedPacket.command);
    receivedPacket.num_entries = ntohs(receivedPacket.num_entries);

    int entries_size = (receivedPacket.num_entries * sizeof(RIPentry));
    int total_size = front_size + entries_size;

    receivedPacket.entries.resize(receivedPacket.num_entries);
    memcpy(&receivedPacket.entries[0], (char *)payload.data() + front_size, total_size - front_size);

    for (auto& entry : receivedPacket.entries) {
        entry.cost = ntohl(entry.cost);
        entry.address = ntohl(entry.address);
        entry.mask = ntohl(entry.mask);
    }

    struct RIPpacket sendPacket;
    std::string RIPSrcAddr = ip::make_address_v4(ntohl(ipHeader->ip_src.s_addr)).to_string();

    auto t = chrono::steady_clock::now();
    
    {
        std::scoped_lock lock(routingTableMtx);
        // 4) Check last time updated
        std::cout << "rip handler" << std::endl;
        cleanUpRoutingTable(routingTable);
        if (receivedPacket.command == 1) {
            // Deal with RIP request
            // add to routing table
            if (routingTable.find(RIPSrcAddr) == routingTable.end()) {
                // If no entry exists, create an entry
                // works under the assumption that rip packets set between neighbors
                std::cout << "new entry being added" << std::endl;
                routingTable[RIPSrcAddr] = {RIPSrcAddr, 1, t};
            } 
            // RIP packet when responding to RIP request contains all routing table entries
            sendPacket = createRIPpacket(2, routingTable);
            sendRIPpacket(RIPSrcAddr, sendPacket);
        } else if (receivedPacket.command == 2) {

            // Deal with RIP response
            std::unordered_map<std::string, std::tuple<std::string, int, std::chrono::time_point<std::chrono::steady_clock>>> updatedRoutes;

            for (auto& entry : receivedPacket.entries) {
                // #todo check if need to convert
                std::string destAddr = ip::make_address_v4(entry.address).to_string(); 

                // Check if entry exists for dest addr
                if (routingTable.find(destAddr) == routingTable.end()) {

                    // If no entry exists, create an entry
                    // works under the assumption that rip packets set between neighbors
                    // routingTable[destAddr] = {RIPSrcAddr, entry.cost + 1, t};
                    routingTable.insert({destAddr, {RIPSrcAddr, entry.cost + 1, t}});
                } else {
                    // Else, grab corresponding next hop and cost

                    // This grabs the old hop address and cost: the data associated
                    // with destination address
                    auto [oldHopAddr, oldCost, time] = routingTable[destAddr];

                    int newCost;
                
                    if (newCost < oldCost) {
                        // If the new cost is less then old cost, update with 
                        // the newHopdId
                         newCost = entry.cost + 1;
                    } 
                    else if (newCost > oldCost && oldHopAddr == RIPSrcAddr) {
                        // Else, we only update the routing table 
                        // if new cost > old cost *and* the new cost and old cost
                        // come from the same source
                        newCost = entry.cost + 1;
                    } else {
                        newCost = oldCost;
                    }
                    
                    routingTable[destAddr] = std::make_tuple(RIPSrcAddr, newCost, t);

                    if (newCost != oldCost) {
                        updatedRoutes[destAddr] = routingTable[destAddr];
                    }
                }
            }
            // RIP packet for triggered update contains only updated routing table entries
            sendPacket = createRIPpacket(2, updatedRoutes);

            // Only send triggered update if there are updates
            if (sendPacket.entries.size() != 0) {
                for (auto [addr, addrInfo] : ARPTable) {
                    int interfaceId = std::get<1>(addrInfo);
                    if (addr != interfaces[interfaceId].srcAddr) {
                        sendRIPpacket(addr, sendPacket);
                    }
                }
            }
        }
    }
}


/**
 * @brief This function should traverse all entries in the routing table. 
 * If the time between the last time the entry was updated and the current time is 
 * greater than 12, it should "expire" and be removed from the routing table.
 * 
 * @param routingTable 
 */
void Node::cleanUpRoutingTable(std::unordered_map<std::string, std::tuple<std::string, int, std::chrono::time_point<std::chrono::steady_clock>>> &routingTable) {
    
    for (auto it = routingTable.begin(); it != routingTable.end();) {
        auto val = it->second;
        // get last time updated
        auto lastUpdate = std::get<2>(val);
        auto end        = chrono::steady_clock::now();
        auto delta      = chrono::duration_cast<chrono::seconds>(end - lastUpdate).count();

        // std::cout << std::c_time(chrono::steady_clock::to_time_t(end)) << std::endl;
        // std::cout << delta << std::endl;
        std::string dest = it->first;
        std::string src  = std::get<0>(val);
        if(delta >= 12 && (dest != src)) {
            std::cout << dest << " " << src << " entry has expired!" << std::endl;
            it = routingTable.erase(it);
        }
        else {
            it++;
        }
    }
}
