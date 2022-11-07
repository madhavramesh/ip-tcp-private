#include <string>
#include <random>
#include <chrono>

#include <netinet/tcp.h>

#include <include/TCP/TCPNode.h>
#include <include/repl/siphash.h>

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

    // #todo should try and check if address exists or if its nil/0

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

    ListenSocket& listenSock = listenSockIt->second;

    // Accept blocks until a connection is found
    while (listenSock.completeConns.empty());

    // Remove the socket from completed connections
    int clientSocketDescriptor = listenSock.completeConns.front();
    listenSock.completeConns.pop_front();

    ClientSocket& newClientSock = client_sd_table[clientSocketDescriptor];

    // Add socket to client_sd table
    int destPort = newClientSock.destPort;
    if (client_port_table.find(destPort) == client_port_table.end()) {
        // Create new entry
        // #todo remove this at end
        std::cerr << "this should never be reached!" << std::endl;
        client_port_table[destPort].push_front(clientSocketDescriptor);
    } else {
        // Update old entry
        client_port_table.find(destPort)->second.push_back(clientSocketDescriptor);
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
    std::uniform_int_distribution<int> dis(0, interfaces.size() - 1);
    int randomInterface = dis(rd_gen) % interfaces.size();

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
    return nextSockId - 1;
}

void TCPNode::send(ClientSocket& clientSock, unsigned char sendFlags) {
    std::shared_ptr<struct tcphdr> tcpHeader = std::make_shared<struct tcphdr>();
    tcpHeader->th_sport = htonl(clientSock.srcPort);
    tcpHeader->th_dport = htonl(clientSock.destPort);
    tcpHeader->th_seq = htonl(clientSock.seqNum);
    tcpHeader->th_ack = htonl(clientSock.ackNum);
    tcpHeader->th_flags = sendFlags;
    tcpHeader->th_flags = htons(tcpHeader->th_flags);
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

TCPNode::AddrAndPort TCPNode::extractAddrPort(std::shared_ptr<struct ip> ipHeader, 
        std::shared_ptr<struct tcphdr> tcpHeader) {

    std::string srcAddr = ip::make_address_v4(ntohl(ipHeader->ip_src.s_addr)).to_string();
    unsigned int srcPort = ntohs(tcpHeader->th_sport);
    std::string destAddr = ip::make_address_v4(ntohl(ipHeader->ip_dst.s_addr)).to_string();
    int destPort = ntohs(tcpHeader->th_dport);

    return std::make_tuple(srcAddr, srcPort, destAddr, destPort);
}

void TCPNode::receive(
    std::shared_ptr<struct ip> ipHeader, 
    std::shared_ptr<struct tcphdr> tcpHeader,
    std::string& payload) {

    if ((tcpHeader->th_flags & TH_SYN) && (tcpHeader->th_flags & TH_ACK)) {
        // SYN + ACK received
        receiveSYNACK(ipHeader, tcpHeader);
    } else if (tcpHeader->th_flags & TH_SYN) {
        // SYN received
        receiveSYN(ipHeader, tcpHeader);
    } else if (tcpHeader->th_flags & TH_ACK) {
        // ACK received
        receiveACK(ipHeader, tcpHeader);
    }
}

void TCPNode::receiveSYN(std::shared_ptr<struct ip> ipHeader,
        std::shared_ptr<struct tcphdr> tcpHeader) {

    // Get 4-tuple (srcAddr, srcPort, destAddr, destPort)
    auto [srcAddr, srcPort, destAddr, destPort] = extractAddrPort(ipHeader, tcpHeader);

    // Check if listen socket exists
    auto listenSocketsIt = listen_port_table.find(srcPort);
    if (listenSocketsIt != listen_port_table.end()) {
        return;
    }

    auto listenSocketIt = getListenSocket(srcPort, listenSocketsIt->second);
    if (listenSocketIt == listenSocketsIt->second.end()) {
        return;
    }
    ListenSocket& listenSock = listen_sd_table[*listenSocketIt];

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

    // Add new socket to socket table
    client_sd_table.insert(std::make_pair(clientSock.id, clientSock));
    client_port_table[clientSock.destPort].push_front(clientSock.id);

    // Add socket to corresponding listening socket's incomplete connections
    listenSock.incompleteConns.push_front(clientSock.id);

    // Send SYN + ACK
    send(clientSock, TH_SYN | TH_ACK);
}

void TCPNode::receiveSYNACK(std::shared_ptr<struct ip> ipHeader, 
        std::shared_ptr<struct tcphdr> tcpHeader) {

    // Get 4-tuple (srcAddr, srcPort, destAddr, destPort)
    auto [srcAddr, srcPort, destAddr, destPort] = extractAddrPort(ipHeader, tcpHeader);

    if (!client_port_table.count(srcPort)) {
        return;
    }

    auto clientSocketIt = getClientSocket(srcAddr, srcPort, destAddr, destPort, 
                                          client_port_table[srcPort]);
    if (clientSocketIt == client_port_table[srcPort].end()) {
        return;
    }

    // Send ACK
    int clientSockDescriptor = *clientSocketIt;
    if (clientSockDescriptor != -1) {
        ClientSocket& clientSock = client_sd_table[clientSockDescriptor];
        if (clientSock.state == SocketState::SYN_SENT) {
            clientSock.state = SocketState::ESTABLISHED;
            clientSock.seqNum = ntohl(tcpHeader->th_ack);
            clientSock.ackNum = ntohl(tcpHeader->th_seq) + 1;

            send(clientSock, TH_ACK);
        }
    }
}

void TCPNode::receiveACK(std::shared_ptr<struct ip> ipHeader,
        std::shared_ptr<struct tcphdr> tcpHeader) {

    // Get 4-tuple (srcAddr, srcPort, destAddr, destPort)
    auto [srcAddr, srcPort, destAddr, destPort] = extractAddrPort(ipHeader, tcpHeader);

    // Check if listen socket exists
    auto listenSocketsIt = listen_port_table.find(srcPort);
    if (listenSocketsIt != listen_port_table.end()) {
        return;
    }

    auto listenSocketIt = getListenSocket(srcPort, listenSocketsIt->second);
    if (listenSocketIt == listenSocketsIt->second.end()) {
        return;
    }
    ListenSocket& listenSock = listen_sd_table[*listenSocketIt];

    // Change state to ESTABLISHED
    auto clientSocketIt = getClientSocket(srcAddr, srcPort, destAddr, destPort, 
                                           listenSock.incompleteConns);

    if (clientSocketIt != listenSock.incompleteConns.end()) {
        ClientSocket& clientSock = client_sd_table[*clientSocketIt];
        if (clientSock.state == SocketState::SYN_RECV) {
            clientSock.state = SocketState::ESTABLISHED;
            clientSock.seqNum = ntohl(tcpHeader->th_ack);
            clientSock.ackNum = ntohl(tcpHeader->th_seq) + 1;
    
            // Add to completed connections
            listenSock.incompleteConns.erase(clientSocketIt);
            listenSock.completeConns.push_front(clientSock.id);
        }
    }
}

std::vector<std::tuple<int, ClientSocket>> TCPNode::getClientSockets() {
    std::vector<std::tuple<int, ClientSocket>> clientSockets;
    for (auto& clientSock : client_sd_table) {
        clientSockets.push_back(std::make_tuple(clientSock.first, clientSock.second));
    }
    return clientSockets;
}

std::vector<std::tuple<int, ListenSocket>> TCPNode::getListenSockets() {
    std::vector<std::tuple<int, ListenSocket>> listenSockets;
    for (auto& listenSock : listen_sd_table) {
        listenSockets.push_back(std::make_tuple(listenSock.first, listenSock.second));
    }
    return listenSockets;
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

    uint32_t first = ip::address_v4::from_string(srcAddr).to_ulong();
    uint32_t second = ip::address_v4::from_string(destAddr).to_ulong();
    uint32_t third = (uint32_t)(srcPort) << 16 | (uint32_t)(destPort);
    struct siphash_key key = generateSecretKey();
    uint64_t hashVal = siphash_3u32(first, second, third, key);

    auto curTime = std::chrono::system_clock::now().time_since_epoch();
    auto timeNano = std::chrono::duration_cast<std::chrono::nanoseconds>(curTime).count();
    return hashVal + (timeNano >> 6);
}

struct siphash_key TCPNode::generateSecretKey() {
    static siphash_key key;
    static std::once_flag flag;
    std::call_once(flag, [](){
        std::random_device rd;
        std::mt19937 rd_gen(rd());
        std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
        key.key[0] = dis(rd_gen);
        key.key[1] = dis(rd_gen);
    });
    return key;
}
