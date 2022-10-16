#include "include/IP/Node.h"
#include <netinet/ip.h>

/**
 * Constructor
*/
Node::Node(unsigned int port) : 
    port(port), 
    // my_endpoint(ip::udp::v4(), port),
    socket(my_io_context, {ip::udp::v4(), port}) 
    // socket(my_io_context, my_endpoint)
{
    std::cout << "Constructing node at port " << port << std::endl;

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

    // Set up ARP table
    ARPTable.insert(std::make_pair(destAddr, destPort));

    // Set up routing table
    // #warning? hard coding 0 and 1 as hops
    // do NOT use this to add interfaces anywhere besides initialization

    std::tuple<std::string, unsigned int> valDiff = std::make_tuple(destAddr, 1);
    // From dest -> (src, 1)
    routingTable.insert(std::make_pair(destAddr, valDiff));

    std::tuple<std::string, unsigned int> valSame = std::make_tuple(srcAddr, 1);
    // From src -> (src, 0)
    routingTable.insert(std::make_pair(srcAddr, valSame));

}

/**
 * Sends message
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

    

}

/**
 * Sends via UDP
*/
void udp_send(
    unsigned int port,
    const std::string& payload) 
{

}