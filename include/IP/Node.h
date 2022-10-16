#pragma once

#include "include/"
#include <boost/asio.hpp>

using namespace boost::asio

class Node {
    public:
        Node (unsigned int port);

        void addInterface(unsigned int port, ip::udp::endpoint destAddr);
        // void send(ip::udp::endpoint, const string& payload);

    private:
        unsigned int port;
        UDPLink link;

        unordered_map<ip::udp::endpoint, unsigned int> ARPTable;
        unordered_map<ip::udp::endpoint, tuple<ip::udp::endpoint, unsigned int>> routingTable;
};
