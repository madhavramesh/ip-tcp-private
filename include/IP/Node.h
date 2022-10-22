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


class Node {

    public:
        Node (unsigned int port);

        /**
         * Populates the relevant data structures for each interface
        */
        void addInterface(
            uint16_t destPort, 
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
        /**
         * #TODO this should forward a packet
        */
        void forward();

        void receive();
        

    private:
        // Port that the socket will bind to
        unsigned int port;
        boost::asio::io_context my_io_context;
        boost::asio::ip::udp::socket socket;

        std::unordered_map<int, ProtocolHandler> handlers;

        std::unordered_map<std::string, unsigned int> ARPTable;
        std::unordered_map<std::string, std::tuple<std::string, unsigned int>> routingTable;

        // DS to store both sides of a single interface (dest -> src)
        // #todo make it contain ports as well
        std::unordered_map<std::string, std::string> dstToSrc;

        int calculateChecksum(std::shared_ptr<struct ip> ipHeader);

        void genericHandler(boost::array<char, MAX_IP_PACKET_SIZE> receiveBuffer, 
                size_t receivedBytes, boost::asio::ip::udp::endpoint receiverEndpoint);
        void testHandler(std::shared_ptr<struct ip> ipHeader, std::string& data);
        void ripHandler(std::shared_ptr<struct ip> ipHeader, std::string& data);
       

};
