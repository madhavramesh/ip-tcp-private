#include <string>
#include <sys/socket.h>
#include <unordered_map>
#include <random>
#include <chrono>
#include <thread>
#include <condition_variable>
#include <mutex>

#include <netinet/tcp.h>

#include <include/TCP/TCPNode.h>
#include <include/TCP/TCPSocket.h>
#include <include/repl/siphash.h>

TCPNode::TCPNode(uint16_t port) : nextSockId(0), nextEphemeral(minPort), ipNode(std::make_shared<IPNode>(port)) {

    using namespace std::placeholders;

    auto tcpFunc = std::bind(&TCPNode::tcpHandler, this, _1, _2);
    ipNode->registerHandler(6, tcpFunc);
}

std::shared_ptr<TCPSocket> TCPNode::getSocket(const TCPTuple& socketTuple) {
    std::scoped_lock lk(sd_table_mutex);

    if (socket_tuple_table.count(socketTuple)) {
        return socket_tuple_table[socketTuple];
    }

    // Try to find a listen socket
    TCPTuple listenSocketTuple = SocketTuple(NULL_IPADDR, socketTuple.getSrcPort(), NULL_IPADDR, 0);
    if (socket_tuple_table.count(listenSocket)) {
        return socket_tuple_table[listenSocketTuple];
    }

    return nullptr;
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
int TCPNode::listen(std::string& address, uint16_t port) {
    // User ports must be above MIN_PORT
    if (port < MIN_PORT) {
        return -1;
    }

    // Check that port is not already bound
    TCPTuple socketTuple = TCPTuple(NULL_IPADDR, port, NULL_IPADDR, 0);
    if (getSocket(socketTuple)) {
        return -1;
    }

    // Create new listener socket
    std::shared_ptr<TCPSocket> sock = std::make_shared<TCPSocket>(socketTuple);
    sock->socket_listen();

    std::scoped_lock lk(sd_table_mutex);
    int socketId = nextSockId++;

    // Add socket to socket descriptor table
    sd_table.insert(std::make_pair(socketId, sock));
    socket_tuple_table.insert(std::make_pair(sock.toTuple(), socketId));

    return socketId;
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
    auto sockIt = sd_table.find(socket);
    if (sockIt == sd_table.end()) {
        std::cerr << "error: socket " << socket << " could not be found" << std::endl;
        return -1;
    }

    // NOTE: Newly accepted TCPSocket should already exist in socket descriptor table
    std::shared_ptr<TCPSocket> sock = sockIt->second;
    std::shared_ptr<TCPSocket> newSock = sock->socket_accept();

    // TODO: SHOULD I BE LOCKING sd_table HERE?
    auto newSocketTuple = newSock.toTuple();
    if (socket_tuple_table.count(newSocketTuple)) {
        address = newSocketTuple.getDestAddr();
        return socket_tuple_table[newSocketTuple];
    }

    address = "";
    return -1;
}   

int TCPNode::connect(std::string& address, uint16_t port) {
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
    std::string srcAddr = interface.srcAddr;

    uint16_t srcPort = allocatePort();
    if (srcPort < 0) {
        return -1;
    }

    std::shared_ptr<TCPSocket> sock = std::make_shared<TCPSocket>(srcAddr, srcPort, address, port);

    // Add to socket descriptor table
    int socketId = nextSockId++;
    sd_table.insert(std::make_pair(socketId, sock));
    socket_tuple_table.insert(std::make_pair(sock.toTuple(), socketId));

    // TODO: SHOULD I BE LOCKING sd_table HERE?
    sock->socket_connect();
    return socketId;
}

int TCPNode::write(int socket, std::vector<char>& buf) {
    // TODO: handle splitting packets i.e. less than max tcp packet size

    // Check if socket descriptor exists
    auto sockIt = sd_table.find(socket);
    if (sockIt == sd_table.end()) {
        std::cerr << red << "error: connection does not exist" << color_reset << std::endl;
        return -1
    }

    std::shared_ptr<TCPSocket> sock = sockIt->second;
    switch (sock->getState()) {
        case TCPSocket::SocketState::LISTEN:
            std::cerr << red << "error: remote socket unspecified" << color_reset << std::endl;
            return -1;
        case TCPSocket::SocketState::SYN_SENT: 
        case TCPSocket::SocketState::SYN_RECV:
            sock->addToWaitQueue(TH_ACK, payload);
            return buf.size();
        case TCPSocket::SocketState::ESTABLISHED:
        case TCPSocket::SocketState::CLOSE_WAIT:
            std::string payload(buf.begin(), buf.end());
            sock->sendTCPPacket(TH_ACK, payload);
            return buf.size();
        case TCPSocket::SocketState::FIN_WAIT1:
        case TCPSocket::SocketState::FIN_WAIT2:
        case TCPSocket::SocketState::CLOSING:
        case TCPSocket::SocketState::LAST_ACK:
        case TCPSocket::SocketState::TIME_WAIT:
            std::cerr << red << "error: connection closing" << color_reset << std::endl;
            return -1;
        default:
            std::cerr << red << "error: unknown state reached" << color_reset << std::endl;
            return -1;
    }
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
    std::string payload) {

        auto [srcAddr, srcPort, destAddr, destPort] = extractAddrPort(ipHeader, tcpHeader);

        ClientSocket tempSock;
        tempSock.id = -1;
        tempSock.activeOpen = false;
        tempSock.state = SocketState::CLOSED;
        tempSock.srcAddr = destAddr;
        tempSock.srcPort = destPort;
        tempSock.destAddr = srcAddr;
        tempSock.destPort = srcPort;

        // =============================================================================================================
        // CLOSED

        if (!(listen_port_table.count(destPort) || client_port_table.count(destPort))) { // is closed

            if (!(tcpHeader->th_flags & TH_RST) && (tcpHeader->th_flags & TH_ACK)) {
                // Send RST
                send(tempSock, TH_RST, tcpHeader->th_ack, 0, "");
            } else {
                // Send RST
                send(tempSock, TH_RST, tcpHeader->th_seq + payload.size(), 0, "");
            }
            return;
        }
        
        // =============================================================================================================
        // LISTEN

        auto listenSocketsIt = listen_port_table.find(destPort);
           // Check if listen socket exists
        if (listenSocketsIt != listen_port_table.end()) {

            if (tcpHeader->th_flags & TH_RST) {
                return;
            }

            if (tcpHeader->th_flags & TH_ACK) {
                send(tempSocket, TH_RST, tcpHeader->th_ack, 0, "");
                return;
            }

            if (tcpHeader->th_flags & TH_SYN) {
                // Retrieve the listener socket
                auto listenSocketIt = getListenSocket(destPort, listenSocketsIt->second);
                if (listenSocketIt != listenSocketsIt->second.end()) {
                    ListenSocket& listenSock = listen_sd_table[*listenSocketIt];

                    // Set up new client socket
                    ClientSocket clientSock;
                    clientSock.id               = nextSockId++;
                    clientSock.activeOpen       = false;
                    clientSock.state            = SocketState::SYN_RECV;
                    clientSock.destAddr         = srcAddr;
                    clientSock.destPort         = srcPort;
                    clientSock.srcAddr          = destAddr;
                    clientSock.srcPort          = destPort;
                    clientSock.sendWnd          = tcpHeader->th_win;
                    clientSock.sendWl1          = tcpHeader->th_seq;
                    clientSock.sendWl2          = 0;
                    clientSock.iss              = generateISN(
                                                    clientSock.srcAddr,  clientSock.srcPort, 
                                                    clientSock.destAddr, clientSock.destPort);
                    clientSock.irs              = tcpHeader->th_seq;
                    clientSock.recvBuffer       = TCP::CircularBuffer(RECV_WINDOW_SIZE);
                    clientSock.maxRetransmits   = MAX_RETRANSMITS;
                    clientSock.unAck            = clientSock.iss;
                    clientSock.sendNext         = clientSock.iss;

                    // Add new socket to socket table
                    client_sd_table.insert(std::make_pair(clientSock.id, clientSock));
                    client_port_table[clientSock.srcPort].push_front(clientSock.id);

                    // Add socket to corresponding listening socket's incomplete connections
                    listenSock.incompleteConns.push_front(clientSock.id);

                    // Fill receive buffer with data
                    clientSock.recvBuffer.put(payload.size(), payload);

                    // Send SYN + ACK
                    send(clientSock, TH_SYN | TH_ACK, clientSock.iss, clientSock.recvBuffer.getNext(), "");
                } else {
                    // Drop segment
                    return;
                }
            }

        } 

        // Else in client port table, continue




        // =============================================================================================================

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

// std::vector<std::tuple<int, ClientSocket>> TCPNode::getClientSockets() {
    // std::vector<std::tuple<int, ClientSocket>> clientSockets;
    // for (auto& clientSock : client_sd_table) {
        // clientSockets.push_back(std::make_tuple(clientSock.first, clientSock.second));
    // }
    // return clientSockets;
// }
//
// std::vector<std::tuple<int, ListenSocket>> TCPNode::getListenSockets() {
    // std::vector<std::tuple<int, ListenSocket>> listenSockets;
    // for (auto& listenSock : listen_sd_table) {
        // listenSockets.push_back(std::make_tuple(listenSock.first, listenSock.second));
    // }
    // return listenSockets;
// }
//
void flushSendBuffer(ClientSocket& clientSock) {
    int cap = clientSock.sendBuffer.getCapacity();
    int sendWindowSize = cap - clientSock.sendBuffer.getWindowSize();

    std::vector<char> buf(sendWindowSize);
    int numCopied = clientSock.sendBuffer.getNumBytes(sendWindowSize, buf);

    std::string payload(buf.begin(), buf.end());
    send(clientSock, 0, payload);
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

// Returns a port number > 0 or -1 if a port cannot be allocated
int TCPNode::allocatePort() {
    // Randomly select a port to use as srcPort
    // NOTE: Inefficient when large number of ports are being used
    int count = MAX_PORT - MIN_PORT + 1;
    while (count > 0) {
        if (!client_port_table.count(nextEphemeral) && !listen_port_table.count(nextEphemeral)) {
            break;
        }

        if (nextEphemeral == MAX_PORT) {
            nextEphemeral = MIN_PORT;
        } else {
            nextEphemeral++;
        }
        count--;
    }

    if (count == 0) {
        return -1;
    }
}

void TCPNode::tcpHandler(std::shared_ptr<struct ip> ipHeader, std::string& payload) {
    std::shared_ptr<struct tcphdr> tcpHeader = std::make_shared<struct tcphdr>();
    memcpy(tcpHeader.get(), &payload[0], sizeof(tcphdr));

    std::string remainingPayload = payload.substr(sizeof(tcphdr));
    receive(ipHeader, tcpHeader, remainingPayload);
}
