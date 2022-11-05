#pragma once

#include <iostream>
#include <string>
#include <unordered_map>
#include <tuple>
#include <chrono> 
#include <mutex>

#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <netinet/ip.h>

const int MAX_IP_PACKET_SIZE = 1400;

using namespace boost::asio;

typedef std::function<void(std::shared_ptr<struct ip>, std::string&)> ProtocolHandler;

struct Interface {
    int id;
    bool up;
    std::string srcAddr;
};

struct RIPentry{
    uint32_t cost;
    uint32_t address;
    uint32_t mask;
} __attribute__((__packed__));

struct RIPpacket {
    uint16_t command;
    uint16_t num_entries;
    std::vector<RIPentry> entries;
};

class IPNode {

    public:
        IPNode (unsigned int port);

        // Populates relevant data structures for each interface
        void addInterface(
            int id,
            std::string srcAddr,
            std::string destAddr,
            unsigned int destPort);

        // Enable an interface; Returns false if interface not found
        bool enableInterface(int id);
        // Disable an interface; Returns false if interface not found
        bool disableInterface(int id);

        void sendCLI(std::string address, const std::string& payload);

        // Returns all non-negative interfaces 
        // (interfaces that don't have smae source and destination address)
        std::vector<std::tuple<Interface, std::string, int>> getInterfaces();
        // Returns all possible routes in the form (source address, destination address, cost)
        std::vector<std::tuple<std::string, std::string, int>> getRoutes();

        // Loops infinitely while receiving packets
        void receive();

        // Loops infinitely sending RIP updates every 5 seconds
        void RIP();

        // Registers a handler for a new protocol (can be user provided)
        void registerHandler(int protocol, ProtocolHandler func);

    private:
        // Port that the socket will bind to
        unsigned int port;
        boost::asio::io_context my_io_context;
        boost::asio::ip::udp::socket socket;

        std::unordered_map<int, ProtocolHandler> handlers;

        // interface id -> interface
        std::unordered_map<int, Interface> interfaces;
        // ARP Table: next hop address -> (port, interface id)
        std::unordered_map<std::string, std::tuple<unsigned int, int>> ARPTable;
        // Routing Table: destination address -> (next hop address, cost)
        std::unordered_map<std::string, std::tuple<std::string, int, std::chrono::time_point<std::chrono::steady_clock>>> routingTable;
        std::mutex routingTableMtx;

        uint16_t ip_sum(void *buffer, int len);

        // Given a subset of the routing table, generates a RIP entry for element.
        RIPpacket createRIPpacket(
            uint16_t type, 
            std::unordered_map<std::string, std::tuple<std::string, int, std::chrono::time_point<std::chrono::steady_clock>>>& routes);

        void sendRIPpacket(std::string address, struct RIPpacket packet);

        // Implements split horizon with poison reverse
        // Takes in destination and vector of RIP entries
        // Returns a vector of RIP entries that should be sent
        struct RIPpacket SHPR(std::string packetDestAddr, struct RIPpacket packet);

        // Constructs IPv4 header and sends packet
        void send(
            std::string address, 
            std::string nextHopAddr,
            const std::string& payload,
            int protocol);

        // Forwards a packet to destination
        // NOTE: Modifies shared pointer
        void forward(
            std::string address,
            const std::string& payload,
            std::shared_ptr<struct ip> ipHeader);

        // Handlers for printing to stdout/files and implementing RIP 
        void genericHandler(
            boost::array<char, MAX_IP_PACKET_SIZE> receiveBuffer, 
            size_t receivedBytes, boost::asio::ip::udp::endpoint receiverEndpoint);
        void testHandler(std::shared_ptr<struct ip> ipHeader, std::string& payload);
        void ripHandler(std::shared_ptr<struct ip> ipHeader, std::string& payload);

        void cleanUpRoutingTable(std::unordered_map<std::string, std::tuple<std::string, int, std::chrono::time_point<std::chrono::steady_clock>>> &routingTable);
};
