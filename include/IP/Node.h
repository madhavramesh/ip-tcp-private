#pragma once

#include "include/repl/handler.h"

#include <iostream>
#include <string>
#include <unordered_map>

#include <boost/asio.hpp>
#include <netinet/ip.h>

const int MAX_IP_PACKET_SIZE = 1400;

typedef std::function<void(std::shared_ptr<ip>, std::string&)> ProtocolHandler;

using namespace boost::asio;

class Node {
    public:
        Node (unsigned int port);

        /**
         * Populates the relevant data structures for each interface
        */
        void addInterface(
            unsigned int destPort, 
            std::string srcAddr,
            std::string destAddr);

        /**
         * Given an ip address, protocol, and payload, sends the message.
         * First looks up necessary information and then constructs IPv4 header
         * and then sends information.
        */
        void send(
            std::string address, 
            int protocol, 
            const std::string& payload);

        void registerHandler(int protocol, ProtocolHandler func);

    private:
        // Port that the socket will bind to
        unsigned int port;
        io_context my_io_context;
        ip::udp::socket socket;

        std::unordered_map<int, ProtocolHandler> handlers;

        std::unordered_map<std::string, unsigned int> ARPTable;
        std::unordered_map<std::string, std::tuple<std::string, unsigned int>> routingTable;

        int calculateChecksum(std::shared_ptr<ip> ipHeader);

        void genericHandler(boost::array<char, MAX_IP_PACKET_SIZE> receiveBuffer, 
                size_t receivedBytes, udp::endpoint receiverEndpoint);
        void testHandler(std::shared_ptr<ip> ipHeader, std::string& data);
        void ripHandler(std::shared_ptr<ip> ipHeader, std::string& data);
};
