#pragma once

#include <boost/asio.hpp>

using namespace boost::asio;

/**
 * This is a class representing a UDP link layer.
*/
class UDPLink {
    private:
        boost::asio::io_context*    my_io_context;
        ip::udp::endpoint           my_endpoint;
        ip::udp::socket             my_socket;
   
        // unsigned int bindPort;

    public:
        // Functions
        UDPLink(const unsigned int port);
        void sendPacket(
            const std::string& payload, 
            const unsigned int sendPort);
        std::string recvPacket(); 

};
