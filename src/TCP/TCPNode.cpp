#include "include/TCP/TCPNode.h"


/**
 * @brief Construct a new TCPNode::TCPNode object
 * 
 * @param port 
 */
 TCPNode::TCPNode(unsigned int port) : 
    nextSockId(0),
    ipNode(std::make_shared<IPNode>(port)) {
 }





/**
 * @brief Creates a new ListenSocket. 
 * Returns the id of the newly created socket on success.
 * Returns -1 on failure.
 * 
 * @param address 
 * @param port 
 * @return int 
 */
int TCPNode::listen(std::string& address, unsigned int port) {
    // Create new ListenSocket
    ListenSocket listenerSock;
    listenerSock.id = nextSockId++; // #todo put mutex
    listenerSock.state = SocketState::LISTEN;
    listenerSock.srcAddr = "";
    listenerSock.srcPort = port;

    // Adds socket to map of listener sockets
    if (listen_sd_table.find(port) == listen_sd_table.end()) {
        listen_sd_table.insert(std::pair<int, ListenSocket>(port, listenerSock));
        return listenerSock.id;
    } else {
        std::cerr << "error: cannot bind to port " << port << std::endl;
        return -1;
    }
}

/**
 * @brief Blocks until new socket is accepted. Returns socket's id.
 * 
 * @param socket A listener socket
 * @param address An address to be filled in 
 * @return int Id of the newly gotten client socket
 */
int TCPNode::accept(int socket, std::string& address) {
    // Grab listener socket, if it exists
    auto listenSockIt = listen_sd_table.find(socket);
    if (listenSockIt == listen_sd_table.end()) {
        std::cerr << "error: socket does not exist" << std::endl;
        return -1;
    }

    ListenSocket listenSock = listenSockIt->second;

    // Accept blocks until a connection is found
    while (listenSock.completedConns.empty());

    // Remove the socket from completed connections
    ClientSocket newClientSock = listenSock.completedConns.front();
    listenSock.completedConns.pop_front();

    // Add socket to client_sd table
    int destPort = newClientSock.destPort;
    if (client_port_table.find(destPort) == client_port_table.end()) {
        // Create new entry
        // #todo remove this at end
        std::cerr << "this should never be reached!" << std::endl;
        client_port_table[destPort].push_front(newClientSock);
    } else {
        // Update old entry
        client_port_table.find(destPort)->second.push_back(newClientSock);
    }

    // Set address
    address = newClientSock.destAddr; // #todo, double check if dst or src, figure out why this is needed

    return newClientSock.id;
}   