#include "include/Link/UDPLink.h"
#include <iostream>

UDPLink::UDPLink(unsigned int port) : 
    my_io_context(new io_context),
    my_endpoint(ip::udp::endpoint(ip::udp::v4(), port)),
    my_socket(ip::udp::socket(*my_io_context, my_endpoint))
{

    /* ~~ Onto creating a socket... ~~ */

    // create and bind dat sock
}

void UDPLink::sendPacket(const std::string& payload, const unsigned int sendPort) {

}

std::string UDPLink::recvPacket() {

    return std::string("hi");
}


