#include <string>
#include <random>
#include <chrono>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <netinet/tcp.h>

#include <include/TCP/CircularBuffer.h>
#include <include/TCP/TCPNode.h>
#include <include/repl/siphash.h>

TCPNode::TCPNode(unsigned int port) : nextSockId(0), nextEphemeral(minPort), ipNode(std::make_shared<IPNode>(port)) {

    using namespace std::placeholders;

    auto tcpFunc = std::bind(&TCPNode::tcpHandler, this, _1, _2);
    ipNode->registerHandler(6, tcpFunc);
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

    // #todo should try and check if address exists or if its nil/0
    if (port < MIN_PORT) {
        return -1;
    }

    // Adds socket to map of listener sockets
    if (listen_port_table.find(port) != listen_port_table.end()) {
        return -1;
    } 

    listen_sd_table.insert(std::pair<int, ListenSocket>(listenerSock.id, listenerSock));
    listen_port_table[port].push_front(listenerSock.id);
    return listenerSock.id;
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
        std::cerr << "error: socket " << socket << " could not be found" << std::endl;
        return -1;
    }

    ListenSocket& listenSock = listenSockIt->second;

    // Accept blocks until connection is found (with condition variable)
    std::unique_lock<std::mutex> lk(accept_mutex);
    while (listenSock.completeConns.empty()) {
        accept_cond.wait(lk);
    }

    // Remove the socket from completed connections
    int clientSocketDescriptor = listenSock.completeConns.front();
    listenSock.completeConns.pop_front();

    lk.unlock();

    ClientSocket& newClientSock = client_sd_table[clientSocketDescriptor];

    // // Add socket to client_sd table
    // int srcPort = newClientSock.srcPort;
    // if (client_port_table.find(srcPort) == client_port_table.end()) {
    //     // Create new entry
    //     // #todo remove this at end
    //     std::cerr << "this should never be reached!" << std::endl;
    //     client_port_table[srcPort].push_front(clientSocketDescriptor);
    // } else {
    //     // Update old entry
    //     client_port_table.find(srcPort)->second.push_back(clientSocketDescriptor);
    // }

    // Set address
    address = newClientSock.destAddr; // #todo, double check if dst or src, figure out why this is needed

    return newClientSock.id;
}   

int TCPNode::connect(std::string& address, unsigned int port) {
    ClientSocket clientSock;
    clientSock.id = nextSockId++;
    clientSock.activeOpen = true;
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

    int count = MAX_PORT - MIN_PORT + 1;
    while (count > 0) {
        if (!client_port_table.count(nextEphemeral) && !listen_port_table.count(nextEphemeral)) {
            break;
        }
        nextEphemeral = ((nextEphemeral + 1) % (MAX_PORT - MIN_PORT)) + MIN_PORT;
        count--;
    }

    if (count == 0) {
        return -1;
    }
    clientSock.srcPort = ephemeralPort;

    // Set appropriate windows 
    clientSock.sendWnd = RECV_WINDOW_SIZE;
    clientSock.sendWl1 = 0;
    clientSock.sendWl2 = 0;

    // Generate ISN 
    clientSock.iss = generateISN(clientSock.srcAddr, clientSock.srcPort, clientSock.destAddr, 
                                 clientSock.destPort);
    clientSock.irs = 0;
    clientSock.maxRetransmits = MAX_RETRANSMITS;
    clientSock.unAck = clientSock.iss;
    clientSock.sendNext = clientSock.iss + 1;
    
    // Set up send and receive buffers
    clientSock.recvBuffer = TCPCircularBuffer(RECV_WINDOW_SIZE);

    client_sd_table.insert(std::make_pair(clientSock.id, clientSock));
    client_port_table[clientSock.srcPort].push_front(clientSock.id);

    // Create TCP Header and send SYN
    send(clientSock, TH_SYN, clientSock.iss, 0, "");
    return nextSockId - 1;
}

void TCPNode::send(ClientSocket& clientSock, 
        unsigned char sendFlags, int seqNum, int ackNum, std::string payload) {
    // #todo handle splitting packets i.e. less than max tcp packet size

    std::shared_ptr<struct tcphdr> tcpHeader = std::make_shared<struct tcphdr>();
    tcpHeader->th_sport = htons(clientSock.srcPort);
    tcpHeader->th_dport = htons(clientSock.destPort);
    tcpHeader->th_seq = htonl(seqNum);
    tcpHeader->th_ack = htonl(ackNum);
    tcpHeader->th_flags = sendFlags;

    int windowSize = clientSock.recvBuffer.getWindowSize();
    tcpHeader->th_win = htons(windowSize);
    tcpHeader->th_off = 5;
    tcpHeader->th_sum = 0; 
    tcpHeader->th_urp = 0;

    // Compute checksum
    uint32_t srcIp = inet_addr(clientSock.srcAddr.c_str());
    uint32_t destIp = inet_addr(clientSock.destAddr.c_str());
    tcpHeader->th_sum = computeTCPChecksum(srcIp, destIp, tcpHeader, payload);

    std::string newPayload = "";
    newPayload.resize(sizeof(struct tcphdr));
    memcpy(&newPayload[0], tcpHeader.get(), sizeof(struct tcphdr));
    memcpy(&newPayload[sizeof(struct tcphdr)], &payload[0], payload.size());

    // Call IP's send method to send packet
    ipNode->sendMsg(clientSock.destAddr, clientSock.srcAddr, newPayload, TCP_PROTOCOL_NUMBER); 
    if (tcpHeader->th_flags & (TH_SYN | TH_FIN)) {
        clientSock.sendNext++;
    }
    clientSock.sendNext += payload.size();

    // Add to retranmission queue
    struct RetransmitPacket retransmitPacket;
    retransmitPacket.tcpHeader = tcpHeader;
    retransmitPacket.payload = payload;
    retransmitPacket.time = std::chrono::steady_clock::now();

    clientSock.retransmissionQueue.push_back(retransmitPacket);
}

void TCPNode::retransmitPackets() {
    while (true) {
        auto curTime = std::chrono::steady_clock::now();
        for (auto& [id, clientSock] : client_sd_table) {
            for (auto it = clientSock.retranmissionQueue.begin(); 
                    it != clientSock.retransmissionQueue.end(); it++) {

                auto timeDiff = std::chrono::duration_cast<std::seconds>(curTime - it->retransmitTime).count();
                if (timeDiff > it->retransmitInterval) {
                    // Exponential backoff for retranmission
                    it->reTransmitInterval *= 2;
                    it->numRetransmits++;

                    if (it->numRetransmits > clientSock.maxRetransmits) {
                        // Close socket
                        clientSock.retransmissionQueue.erase(it);
                        client_port_table[clientSock.destPort].erase(id);
                        client_sd_table.erase(id);
                        return;
                    }
                    it->retransmitTime = std::chrono::steady_clock::now();

                    // Retransmit packet if receiver window allows
                    unsigned int segEnd = (it->tcpHeader->th_seq + it->payload.size()) - 1;
                    if (segEnd < clientSock.unAck + clientSock.sendWnd) {
                        std::string newPayload = "";
                        newPayload.resize(sizeof(struct tcphdr));
                        memcpy(&newPayload[0], tcpHeader.get(), sizeof(struct tcphdr));
                        memcpy(&newPayload[sizeof(struct tcphdr)], &payload[0], payload.size());

                        ipNode->sendMsg(clientSock.destAddr, clientSock.srcAddr, newPayload, 
                                        TCP_PROTOCOL_NUMBER); 
                    }
                }
            }
        }
    }
}

TCPNode::AddrAndPort TCPNode::extractAddrPort(std::shared_ptr<struct ip> ipHeader, 
        std::shared_ptr<struct tcphdr> tcpHeader) {

    std::string srcAddr = ip::make_address_v4(ipHeader->ip_src.s_addr).to_string();
    unsigned int srcPort = tcpHeader->th_sport;
    std::string destAddr = ip::make_address_v4(ipHeader->ip_dst.s_addr).to_string();
    int destPort = tcpHeader->th_dport;

    return std::make_tuple(srcAddr, srcPort, destAddr, destPort);
}

void TCPNode::handleClient(
    std::shared_ptr<struct ip> ipHeader, 
    std::shared_ptr<struct tcphdr> tcpHeader, 
    std::string payload,
    int socketId) {
        
        auto [srcAddr, srcPort, destAddr, destPort] = extractAddrPort(ipHeader, tcpHeader);
        ClientSocket socket = client_sd_table[socketId]; // hopefully it exists

        // 1) Check validity
        
        bool acceptable = true;
        int segSeq   = tcpHeader->th_seq;
        int recvNext = socket.irs + socket.recvBuffer.getNext();
        int recvLast = recvNext + socket.recvBuffer.getWindowSize();

        if ((payload.size() == 0) && (tcpHeader->th_win == 0)) {         // case #1
            if (!(segSeq == recvNext)) {
                acceptable = false;
            }
        } else if ((payload.size() == 0) && (tcpHeader->th_win > 0)) {   // case #2
            if (!(recvNext <= segSeq && segSeq < recvLast)) {
                acceptable = false;
            }
        } else if ((tcpHeader->th_win == 0) && (tcpHeader->th_win == 0)) {  // case #3
                acceptable = false;
        } else {                                                            // case #4
            if (!((recvNext <= segSeq && segSeq < recvLast) ||
                (recvNext <= segSeq + payload.size() - 1 && segSeq + payload.size() - 1 < recvLast))) {
                acceptable = false;
            }
        }

        if (!acceptable) {
            if (tcpHeader->th_flags & TH_RST) {
                return;
            }
            // Send ACK
            send(socket,TH_ACK, socket.sendBuffer.getNext(), socket.recvBuffer.getNext(), "");
            return;
        }

        // trim 
        if (segSeq < recvNext) {
            payload = payload.substr(recvNext - segSeq + 1);
        }
        if (recvLast <= segSeq + payload.size() - 1) {
            payload = payload.substr(0, recvLast - segSeq);
        }
        
        // 2) Check the reset bit
        bool resetBitSet = tcpHeader->th_flags & TH_RST;

        if (resetBitSet && (socket.state == SocketState::SYN_RECV)) {
            // If initiated with passive open, return back to listen state
            client_port_table[destPort].erase(socketId);
            client_sd_table.erase(socketId);

            // # potentially consider active vs passive open

            // # flush
            flushSendBuffer(socket);

            return;
        }

        else if (resetBitSet && (socket.state == SocketState::TIME_WAIT)) {
            // If initiated with passive open, return back to listen state
            client_port_table[destPort].erase(socketId);
            client_sd_table.erase(socketId);

            // # potentially consider active vs passive open

            return;
        }

        else if (resetBitSet && (socket.state == SocketState::CLOSE_WAIT)) {
            // # send reset responses to outstanding reads/sends

            // # flush
            flushSendBuffer(socket);

            return;
        }

        // 3) Don't need to check security

        // 4) Check SYN bit
        bool synBitSet = tcpHeader->th_flags & TH_SYN;

        if (synBitSet && (socket.state == SocketState::SYN_RECV)) {
            // Check if passive OPEN 
            if (!socket.activeOpen) {
                // Return back to listen state
                client_port_table[destPort].erase(socketId);
                client_sd_table.erase(socketId);
                
                return;
            }
        }

        else if (synBitSet && (socket.state == SocketState::TIME_WAIT)) {
            // Flush
            flushSendBuffer(socket);

            // If syn in window, it is an error
            // send reset
            send(socket, TH_RST);

            // Send reset response to user by making read/send return 0

            return;
        }

        // 5) Check ACK bit
        bool ackBitSet = tcpHeader->th_flags & TH_ACK;
        if (!ackBitSet) {
            return;
        }
        
        else if (socket.state == SocketState::SYN_RECV) {
            tcp_seq ack = tcpHeader->th_ack;
            if (socket.sendBuffer.start < ack && ack <= socket.sendBuffer.next) {
                socket.state = SocketState::ESTABLISHED;
                socket.sndWnd = tcpHeader->th_win;

                socket.seqNum = tcpHeader->th_ack;
                socket.ackNum = tcpHeader->th_seq;
                // continue processing in ESTABLISHED state
            } else {
                // send reset
                socket.seqNum = tcpHeader->th_ack;
                send(socket, TH_RST, "");
                return;
            }
        }

        // 6) If ESTABLISHED state
        if (socket.state == SocketState::ESTABLISHED || socket.state == SocketState::FIN_WAIT1 ||
            socket.state == SocketState::FIN_WAIT2 || socket.state == SocketState::CLOSE_WAIT) {
            if (socket.sendBuffer.start < ack && ack <= socket.sendBuffer.next) {
                // update send buffer
                socket.sendBuffer.start = ack;

                // #todo handle retransmission
                // #todo handle out of order packets
            } else if (ack > socket.sendBuffer.next) {
                // Send an ack
                send(socket, TH_ACK, "");
                return;
            }

            if (socket.sendBuffer.start <= ack && ack <= socket.sendBuffer.next) {
                if ()
                socket.sendWnd = tcpHeader->th_win;
                
                if ()
            }
        }

        if (socket.state == SocketState::FIN_WAIT1) {
            // FIN segment has been acknowledged
        }

        if (socket.state == SocketState::FIN_WAIT2) {
            // User CLOSE can be acknowledged

        }

    
}

void TCPNode::receive(
    std::shared_ptr<struct ip> ipHeader, 
    std::shared_ptr<struct tcphdr> tcpHeader,
    std::string& payload) {
        
        // Convert back to host byte order
        ipHeader->ip_src.s_addr = ntohl(ipHeader->ip_src.s_addr);
        ipHeader->ip_dst.s_addr = ntohl(ipHeader->ip_dst.s_addr);
        ipHeader->ip_len = ntohs(ipHeader->ip_len);

        tcpHeader->th_sport = ntohs(tcpHeader->th_sport);
        tcpHeader->th_dport = ntohs(tcpHeader->th_dport);
        tcpHeader->th_seq = ntohl(tcpHeader->th_seq);
        tcpHeader->th_ack = ntohl(tcpHeader->th_ack);
        tcpHeader->th_win = ntohs(tcpHeader->th_win);

        // Find socket
        auto [srcAddr, srcPort, destAddr, destPort] = extractAddrPort(ipHeader, tcpHeader);
        
        bool inClientTable = true;
        // Check if in client socket table
        if (!client_port_table.count(destPort)) {
            inClientTable = false;
        }
        auto clientSocketIt = getClientSocket(srcAddr, srcPort, destAddr, destPort, 
                                            client_port_table[destPort]);
        if (clientSocketIt == client_port_table[destPort].end()) {
            inClientTable = false;
        }

        if (inClientTable) {
            // Handle client
        }

        if (foundInClientTable()) {
            handleClient()
        } else if (foundInListenerTable()) {
            handleListenerCase()
        } else {
            // Handle CLOSED state
            // printError
        }
        
    

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
    auto listenSocketsIt = listen_port_table.find(destPort);
    if (listenSocketsIt == listen_port_table.end()) {
        return;
    }

    auto listenSocketIt = getListenSocket(destPort, listenSocketsIt->second);
    if (listenSocketIt == listenSocketsIt->second.end()) {
        return;
    }
    ListenSocket& listenSock = listen_sd_table[*listenSocketIt];

    // Create new socket
    ClientSocket clientSock;
    clientSock.id = nextSockId++;
    clientSock.activeOpen = false;
    clientSock.state = SocketState::SYN_RECV;
    clientSock.destAddr = srcAddr;
    clientSock.destPort = srcPort;
    clientSock.srcAddr = destAddr;
    clientSock.srcPort = destPort;
    clientSock.iss = generateISN(clientSock.srcAddr, clientSock.srcPort, clientSock.destAddr,
                                     clientSock.destPort);
    clientSock.ackNum = ntohl(tcpHeader->th_seq) + 1;
    clientSock.sendBuffer = TCPCircularBuffer(SEND_WINDOW_SIZE);
    clientSock.recvBuffer = TCPCircularBuffer(RECV_WINDOW_SIZE);

    // Add new socket to socket table
    client_sd_table.insert(std::make_pair(clientSock.id, clientSock));
    client_port_table[clientSock.srcPort].push_front(clientSock.id);

    // Add socket to corresponding listening socket's incomplete connections
    listenSock.incompleteConns.push_front(clientSock.id);

    // Send SYN + ACK
    send(clientSock, TH_SYN | TH_ACK, "");
}

void TCPNode::receiveSYNACK(std::shared_ptr<struct ip> ipHeader, 
        std::shared_ptr<struct tcphdr> tcpHeader) {

    // Get 4-tuple (srcAddr, srcPort, destAddr, destPort)
    auto [srcAddr, srcPort, destAddr, destPort] = extractAddrPort(ipHeader, tcpHeader);

    if (!client_port_table.count(destPort)) {
        return;
    }

    auto clientSocketIt = getClientSocket(srcAddr, srcPort, destAddr, destPort, 
                                          client_port_table[destPort]);
    if (clientSocketIt == client_port_table[destPort].end()) {
        return;
    }

    // Send ACK
    int clientSockDescriptor = *clientSocketIt;
    if (clientSockDescriptor != -1) {
        ClientSocket& clientSock = client_sd_table[clientSockDescriptor];
        if (clientSock.state == SocketState::SYN_SENT) {
            clientSock.state = SocketState::ESTABLISHED;
            clientSock.seqNum = tcpHeader->th_ack;
            clientSock.ackNum = tcpHeader->th_seq + 1;

            send(clientSock, TH_ACK, "");
        }
    }
}

void TCPNode::receiveACK(std::shared_ptr<struct ip> ipHeader,
        std::shared_ptr<struct tcphdr> tcpHeader) {

    // Get 4-tuple (srcAddr, srcPort, destAddr, destPort)
    auto [srcAddr, srcPort, destAddr, destPort] = extractAddrPort(ipHeader, tcpHeader);

    // Check if listen socket exists
    auto listenSocketsIt = listen_port_table.find(destPort);
    if (listenSocketsIt == listen_port_table.end()) {
        return;
    }

    auto listenSocketIt = getListenSocket(destPort, listenSocketsIt->second);
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
            clientSock.seqNum = tcpHeader->th_ack;
            clientSock.ackNum = tcpHeader->th_seq + 1;
    
            // Remove from incomplete connections
            listenSock.incompleteConns.erase(clientSocketIt);

            // Add to completed connections
            std::unique_lock<std::mutex> lock(accept_mutex);
            listenSock.completeConns.push_front(clientSock.id);
            accept_cond.notify_one();
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

void flushSendBuffer(ClientSocket& clientSock) {
    int cap = clientSock.sendBuffer.getCapacity();
    int sendWindowSize = cap - clientSock.sendBuffer.getWindowSize();

    std::vector<char> buf(sendWindowSize);
    int numCopied = clientSock.sendBuffer.getNumBytes(sendWindowSize, buf);

    std::string payload(buf.begin(), buf.end());
    send(clientSock, 0, payload);
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
    ph.zero = 0;
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

void TCPNode::tcpHandler(std::shared_ptr<struct ip> ipHeader, std::string& payload) {
    std::shared_ptr<struct tcphdr> tcpHeader = std::make_shared<struct tcphdr>();
    memcpy(tcpHeader.get(), &payload[0], sizeof(tcphdr));

    std::string remainingPayload = payload.substr(sizeof(tcphdr));
    receive(ipHeader, tcpHeader, remainingPayload);
}
