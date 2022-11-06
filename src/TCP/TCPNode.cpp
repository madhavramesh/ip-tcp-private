#include <string>
#include <random>

#include <netinet/tcp.h>

#include <include/TCP/TCPNode.h>

TCPNode::TCPNode(unsigned int port) : nextSockId(0), ipNode(std::make_shared<IPNode>(port)) {}

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
    while (listenSock.completeConns.empty());

    // Remove the socket from completed connections
    ClientSocket newClientSock = listenSock.completeConns.front();
    listenSock.completeConns.pop_front();

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

int TCPNode::connect(std::string& address, unsigned int port) {
    ClientSocket clientSock;
    clientSock.id = nextSockId++;
    clientSock.state = SocketState::SYN_SENT;
    clientSock.destAddr = address;
    clientSock.destPort = port;
    
    // Randomly select an interface to use as srcAddr
    auto interfaces = ipNode->getInterfaces();
    if (interfaces.empty()) {
        return -1;
    }
    std::random_device rd;
    std::mt19937 rd_gen(rd());
    std::uniform_int_distribution<> dis(0, interfaces.size() - 1);
    int randomInterface = dis() % interfaces.size();

    Interface interface = std::get<0>(interfaces[randomInterface]);
    clientSock.srcAddr = interface.srcAddr;

    // Randomly select a port to use as srcPort
    // NOTE: Inefficient when large number of ports are being used
    int ephemeralPort = MIN_PORT;
    while (client_port_table.count(port) || listen_port_table.count(port)) {
        ephemeralPort = MIN_PORT + (rand() % (MAX_PORT - MIN_PORT));
    }
    clientSock.srcPort = ephemeralPort;

    // Generate ISN 
    unsigned int isn = generateISN(clientSock.srcAddr, clientSock.srcPort, clientSock.destAddr, 
                                    clientSock.destPort);
    clientSock.seqNum = isn;
    clientSock.ackNum = 0;

    client_sd_table.insert(std::make_pair(clientSock.id, clientSock));
    client_port_table[clientSock.destPort].push_front(clientSock.id);

    // Create TCP Header and send SYN
    send(clientSock, TH_SYN);
}

void TCP::send(ClientSocket& clientSock, unsigned char sendFlags) {
    std::shared_ptr<struct tcphdr> tcpHeader = std::make_shared<struct tcphdr>();
    tcpHeader->th_sport = htonl(clientSock.srcPort);
    tcpHeader->th_dport = htonl(clientSock.destPort);
    tcpHeader->th_seq = htonl(clientSock.seqNum);
    tcpHeader->th_ack = htonl(clientSock.ackNum);
    tcpHeader->th_flags = sendFlags;
    tcpHeader->th_flags = htons(tpcHeader->th_flags);
    tcpHeader->th_win = 0;
    tcpHeader->th_sum = 0; 
    tcpHeader->th_urp = 0;

    // Compute checksum
    uint32_t srcIp = inet_addr(clientSock.srcAddr.c_str());
    uint32_t destIp = inet_addr(clientSock.destAddr.c_str());
    std::string payload = "";
    tcpHeader->th_sum = computeTCPChecksum(srcIp, destIp, tcpHeader, payload);

    payload.resize(sizeof(struct tcphdr));
    memcpy(&payload[0], tcpHeader.get(), sizeof(struct tcphdr));

    ipNode->sendCLI(clientSock.destAddr, payload); 
}

void TCP::receive(
    std::shared_ptr<struct ip> ipHeader, 
    std::shared_ptr<struct tcphdr> tcpHeader,
    std::string& payload) {

    // Check if a corresponding listen socket exists on dest port 
    int destPort = ntohs(tcpHeader->th_dport);
    auto listenSocketsIt = listen_port_table.find(destPort);
    if (listenSocketsIt == listen_port_table.end()) {
        return;
    }

    int listenSocketDescriptor = getListenSocket(destPort, listenSocketsIt->second);
    if (listenSocketDescriptor == -1) {
        return;
    }
    ListenSocket& listenSock = listen_sd_table[listenSockDescriptor];

    // Get 4-tuple (srcAddr, srcPort, destAddr, destPort)
    std::string& srcAddr = ip::make_address_v4(ntohl(ipHeader->ip_src.s_addr));
    unsigned int srcPort = ntohs(tcpHeader->th_sport);
    std::string& destAddr = ip::make_address_v4(ntohl(ipHeader->ip_dst.s_addr));
    unsigned int destPort = ntohs(tcpHeader->th_dport);

    // SYN + ACK received
    if ((tcpHeader->th_flags & TH_SYN) && (tcpHeader->th_flags & TH_ACK)) {
        if (!client_port_table.count(destPort)) {
            return;
        }

        int socketDescriptor = getClientSocket(srcAddr, srcPort, destAddr, destPort, 
                                                     client_port_table[destPort]->second);

        // Send ACK
        if (clientSocketDescriptor != -1) {
            ClientSocket& clientSock = client_sd_table[socketDescriptor];
            clientSock.state = SocketState::ESTABLISHED;
            clientSock.seqNum = ntohl(tcpHeader->th_ack);
            clientSock.ackNum = ntohl(tcpHeader->th_seq) + 1;

            send(clientSock, ACK);
        }
    } 
    // SYN
    else if (tcpHeader->th_flags & TH_SYN) {
        // Create new socket
        ClientSocket clientSock;
        clientSock.id = nextSockId++;
        clientSock.state = SocketState::SYN_RECV;
        clientSock.destAddr = srcAddr;
        clientSock.destPort = srcPort;
        clientSock.srcAddr = destAddr;
        clientSock.srcPort = destPort;
        clientSock.seqNum = generateISN(clientSock.srcAddr, clientSock.srcPort, clientSock.destAddr, 
                                         clientSock.destPort);
        clientSock.ackNum = ntohl(tcpHeader->th_seq) + 1;

        client_sd_table.insert(std::make_pair(clientSock.id, clientSock));
        client_port_table[clientSock.destPort].push_front(clientSock);

        // Add socket to corresponding listening socket's incomplete connections
        listenSock.incompleteConns.push_front(clientSock.id);

        // Send SYN + ACK
        send(clientSock, TH_SYN | TH_ACK);
    } 
    // ACK received
    else if (tcpHeader->th_flags & TH_ACK) {
        // Change state to ESTABLISHED
        int socketDescriptor = getClientSocket(srcAddr, srcPort, destAddr, destPort, 
                                               listenSock.incompleteConns);

        if (socketDescriptor != -1) {
            ClientSocket& clientSock = client_sd_table[socketDescriptor]
            clientSock.state = SocketState::ESTABLISHED;
            clientSock.seqNum = ntohl(tcpHeader->th_ack);
            clientSock.ackNum = ntohl(tcpHeader->th_seq) + 1;
        }
    }
}

// The TCP checksum is computed based on a "pesudo-header" that
// combines the (virtual) IP source and destination address, protocol value,
// as well as the TCP header and payload

// For more details, see the "Checksum" component of RFC793 Section 3.1,
// https://www.ietf.org/rfc/rfc793.txt (pages 14-15)
uint16_t TCPNode::computeTCPChecksum(
    uint32_t virtual_ip_src, 
    uint32_t virtual_ip_dst,
    std::shared_ptr<struct tcphdr> tcp_header, 
    std::string& payload) {

    struct pseudo_header {
        uint32_t ip_src;
        uint32_t ip_dst;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    };

    struct pseudo_header ph;

    size_t ph_len = sizeof(struct pseudo_header);
    size_t hdr_len = sizeof(struct tcphdr);
    assert(ph_len == 12);
    assert(hdr_len == 20);

    // Now fill in the pesudo header
    memset(&ph, 0, sizeof(struct pseudo_header));
    ph.ip_src = virtual_ip_src;
    ph.ip_dst = virtual_ip_dst;
    ph.protocol = 6;  // TCP's assigned IP protocol number is 6

    // From RFC: "The TCP Length is the TCP header length plus the
    // data length in octets (this is not an explicitly transmitted
    // quantity, but is computed), and it does not count the 12 octets
    // of the pseudo header."
    ph.tcp_length = htons(hdr_len + payload.size());

    size_t total_len = ph_len + hdr_len + payload.size();
    char buffer[total_len];
    memset(buffer, 0, total_len);
    memcpy(buffer, &ph, ph_len);
    memcpy(buffer + ph_len, tcp_header.get(), hdr_len);
    memcpy(buffer + ph_len + hdr_len, &payload[0], payload.size());

    uint16_t checksum = ipNode->ip_sum(buffer, total_len);
    return checksum;
}

// ISN = M + F(localip, localport, remoteip, remoteport, secretkey) where
// M is an ~4 microsecond timer and F() is the SipHash pseudorandom function
// of the connection's identifying parameters and a secret key
//
// For more details, see the "Initial Sequence Number Selection" component
// of RFC9293 Section 3.4.1, https://www.rfc-editor.org/rfc/rfc9293
unsigned int TCPNode::generateISN(
    std::string& srcAddr, 
    unsigned int srcPort, 
    std::string& destAddr, 
    unsigned int destPort) {

    std::random_device rd;
    std::mt19937 isn_gen(rd());
    std::uniform_int_distribution<unsigned int> isn_dis(0, UINT_MAX);
    return isn_dis();
}
