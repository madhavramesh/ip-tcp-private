#pragma once

#include <iostream>
#include <string>
#include <unordered_map>
#include <tuple>

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
    std::string destAddr;
    unsigned int destPort;
};

class Node {

    public:
        Node (unsigned int port);

        // Populates relevant data structures for each interface
        void addInterface(
            int id,
            std::string srcAddr,
            std::string destAddr,
            unsigned int destPort,
            int cost);

        // Enable an interface; Returns false if interface not found
        bool enableInterface(int id);
        // Disable an interface; Returns false if interface not found
        bool disableInterface(int id);

        // Returns all non-negative interfaces 
        // (interfaces that don't have smae source and destination address)
        std::vector<Interface> getInterfaces();
        // Returns all possible routes in the form (source address, destination address, cost)
        std::vector<std::tuple<std::string, std::string, int>> getRoutes();

        // Constructs IPv4 header and sends packet
        void send(
            std::string address, 
            int protocol, 
            const std::string& payload);

        // Loops infinitely while receiving packets
        void receive();

        // Registers a handler for a new protocol (can be user provided)
        void registerHandler(int protocol, ProtocolHandler func);

    private:
        // Port that the socket will bind to
        unsigned int port;
        boost::asio::io_context my_io_context;
        boost::asio::ip::udp::socket socket;

        std::unordered_map<int, ProtocolHandler> handlers;

        // ARP Table: interface id -> interface
        std::unordered_map<int, Interface> ARPTable;
        // Routing Table: destination address -> (next hop interface, cost)
        std::unordered_map<std::string, std::tuple<int, int>> routingTable;

        uint16_t ip_sum(void *buffer, int len);

        // Calculates checksum of an IP Header
        int calculateChecksum(std::shared_ptr<struct ip> ipHeader);

        // Forwards a packet to destination
        // NOTE: Modifies shared pointer
        void forward(std::shared_ptr<struct ip> ipHeader, 
            const std::string& payload,
            unsigned int forwardPort);

        // Handlers for printing to stdout/files and implementing RIP 
        void genericHandler(boost::array<char, MAX_IP_PACKET_SIZE> receiveBuffer, 
                size_t receivedBytes, boost::asio::ip::udp::endpoint receiverEndpoint);
        void testHandler(std::shared_ptr<struct ip> ipHeader, std::string& data);
        void ripHandler(std::shared_ptr<struct ip> ipHeader, std::string& data);
};
