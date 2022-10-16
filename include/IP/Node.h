#pragma once

#include <string>
#include <boost/asio.hpp>
#include <unordered_map>
#include <iostream>

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
        

    private:
        // Port that the socket will bind to
        unsigned int port;
        io_context my_io_context;
        ip::udp::socket socket;

        std::unordered_map<std::string, unsigned int> ARPTable;
        std::unordered_map<std::string, std::tuple<std::string, unsigned int>> routingTable;

        /**
         * Given port number and payload, sends via UDP.
        */
        void udp_send(
            unsigned int port,
            const std::string& payload);
};
