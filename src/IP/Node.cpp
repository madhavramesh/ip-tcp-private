#include "include/IP/Node.h"

/**
 * Constructor
*/
Node::Node(unsigned int port) : 
    port(port), 
    // my_endpoint(ip::udp::v4(), port),
    socket(my_io_context, {ip::udp::v4(), port}),
    // socket(my_io_context, my_endpoint)
    handler()
{
    std::cout << "Constructing node at port " << port << std::endl;
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
    unsigned int destPort, 
    std::string srcAddr,
    std::string destAddr) 
{
    std::cout << "Adding interface from " << srcAddr << ":" << port << " to " << 
    destAddr << ":" << destPort << std::endl;

    // 1) Set up ARP table
    ARPTable.insert(std::make_pair(destAddr, destPort));

    // 2) Set up routing table
    // #warning? hard coding 0 and 1 as hops
    // do NOT use this to add interfaces anywhere besides initialization

    std::tuple<std::string, unsigned int> valDiff = std::make_tuple(destAddr, 1);
    // From dest -> (src, 1)
    routingTable.insert(std::make_pair(destAddr, valDiff));

    std::tuple<std::string, unsigned int> valSame = std::make_tuple(srcAddr, 1);
    // From src -> (src, 0)
    routingTable.insert(std::make_pair(srcAddr, valSame));

    // 3) Set up dst -> src table
    dst-to-src.insert(std::make_pair(dstAddr, srcAddr));

}

int calculateChecksum(std::shared_ptr<ip> ipHeader) {
    int prevChecksum = ipHeader->ip_sum;
    ipHeader->ip_sum = 0;

    char *data = (char *)ipHeader;

    // Initialize accumulator
    uint32_t acc = 0xffff;
    for (size_t i = 0; i + 1 < sizeof(ipHeader); i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    // Handle any partial blocks at end 
    if (sizeof(ipHeader) % 2 == 1) {
        uint16_t word = 0;
        memcpy(&word, data + sizeof(ipHeader) - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    ipHeader->ip_sum = prevChecksum;
    // Return checksum in network byte order
    return htons(~acc);
}


/**
 * Sends message (from CLI)
*/
void Node::send(
    std::string address, 
    int protocol, 
    const std::string& payload) 
{
    // #todo handle cases where address or next hop not in arp table
    // specifically, routing table case
    std::string nextHop = std::get<0>(routingTable[address]);
    unsigned int destPort = ARPTable[nextHop];
    
    // Build IPv4 header
    struct ip ip_header;

    ip_header.ip_hl     = 20;   // always 20 if no IP options
    ip_header.ip_v      = 4;    // version is IPv4
    ip_header.ip_tos    = 0;    // n/a
    ip_header.ip_len    = htons(ip_header.ip_hl + payload.length());
    ip_header.ip_id     = 0;    // n/a
    ip_header.ip_off    = 0;    // n/a
    ip_header.ip_ttl    = 16;   // initial time to live
    ip_header.ip_p      = 17;   // UDP = 17
    ip_header.ip_sum    = 0;    // checksum should be zeroed out b4 calc
    ip_header.ip_src = inet_addr(dst-to-src[nextHop]);
    ip_header.ip_dst = inet_addr(address);

    // Convert ip_header to a string
    char b[sizeof(ip)];
    std::cpy(b, ip_header, sizeof(ip));
    b[sizeof(ip)] = '\0'; 

    std::string iph_str(b);
    std::string new_string = iph_str + payload;

    // #TODO check if this works
    unsigned int new_size = sizeof(ip) + sizeof(payload);
    boost::array<char, new_size> new_payload = new_string;

    // #TODO 
    // calculate checksum
    int checksum = 0;
    ip_header.ip_sum = checksum;

    // #TODO send it via udp and check if this works
    socket.send_to(buffer(payload), {ip::udp::v4(), destPort});

    
}

void receive() {
    while (true) {
        try {
            boost::array<char, MAX_IP_PACKET_SIZE> receiveBuffer;
            udp::endpoint receiverEndpoint;
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
        size_t receivedBytes, udp::endpoint receiverEndpoint) {
    // Need to check whether the port message was sent from appears in ARP Table
    // if (receiver_endpoint.port() != port) {
        // return;
    // }

    ip *ipHeaderRaw = (ip *)(&receiveBuffer[0]);

    // Reconstruct IPv4 header
    std::shared_ptr<ip> ipHeader = std::make_shared<ip>();
    memcpy(ipHeader, ipHeaderRaw, sizeof(ipHeaderRaw));

    // Get payload/data from IP packet
    std::string payload(buf.begin() + sizeof(ipHeader), buf.begin() + receivedBytes);

    // Compute checksum
    if (calculateChecksum(ipHeader) != ipHeader->ip_sum) {
        return;
    }

    // Is the destination address in the routing table?
    if (!routingTable.count(ipHeader->ip_dst.s_addr)) {
        return;
    }

    // Calculate whether packet has reached destination
    std::string nextHop = std::get<1>(routingTable[ipHeader->ip_dst.s_addr]);
    unsigned int destPort = ARPTable[nextHop];
    if (destPort == port) {
        if (handlers.count(ipHeader->ip_p)) {
            handlers.find(ipHeader->ip_p)->second(std::move(ipHeader), payload);
        }
        throw std::runtime_error("Error: handler for protocol " + 
                std::to_string(ipHeader->ip_p) + " not found");
    }

    // Packet has not reached destination so forward packet
}

void Node::testHandler(std::shared_ptr<ip> ipHeader, std::string& data) {
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

void Node::ripHandler(std::shared_ptr<ip> ipHeader, std::string& data) {
    std::cout << "You have entered the RIP handler!" << std::endl;
    return;
}
