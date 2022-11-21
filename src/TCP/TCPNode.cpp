#include <string>
#include <sys/socket.h>
#include <unordered_map>
#include <random>
#include <chrono>
#include <thread>
#include <condition_variable>
#include <mutex>

#include <netinet/tcp.h>
#include "include/tools/colors.h"
#include <include/TCP/TCPNode.h>
#include <include/TCP/TCPSocket.h>
#include <include/tools/siphash.h>

// #todo fix
int MAX_READ_SIZE = 65535;

TCPNode::TCPNode(uint16_t port) : nextSockId(0), nextEphemeral(MIN_PORT), ipNode(std::make_shared<IPNode>(port)) {

    using namespace std::placeholders;

    auto tcpFunc = std::bind(&TCPNode::tcpHandler, this, _1, _2);
    ipNode->registerHandler(6, tcpFunc);
}

std::shared_ptr<TCPSocket> TCPNode::getSocket(const TCPTuple& socketTuple) {
    std::scoped_lock lk(sd_table_mutex);

    if (socket_tuple_table.count(socketTuple)) {
        int socketId = socket_tuple_table[socketTuple];
        return sd_table[socketId];
    }

    // Try to find a listen socket
    TCPTuple listenSocketTuple = TCPTuple(NULL_IPADDR, socketTuple.getSrcPort(), NULL_IPADDR, 0);
    if (socket_tuple_table.count(listenSocketTuple)) {
        int socketId = socket_tuple_table[socketTuple];
        return sd_table[socketId];
    }

    return nullptr;
}

std::unordered_map<int, TCPSocket> TCPNode::getSockets() {
    // Clean up any sockets in TIME_WAIT state
    removeTimedWaitSockets();

    std::unordered_map<int, TCPSocket> sd_table_copy;
    for (auto& [id, sock] : sd_table) {
       sd_table_copy.insert(std::make_pair(id, *sock)); 
    }
    return sd_table_copy;
}

void TCPNode::deleteSocket(TCPTuple socketTuple) {
    int socketId = socket_tuple_table[socketTuple];
    std::shared_ptr<TCPSocket> sock = sd_table[socketId];

    sock->setState(TCPSocket::SocketState::CLOSED);

    sd_table.erase(socketId);
    socket_tuple_table.erase(socketTuple);
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
    std::shared_ptr<TCPSocket> sock = std::make_shared<TCPSocket>(socketTuple, ipNode);
    sock->socket_listen();

    std::scoped_lock lk(sd_table_mutex);
    int socketId = nextSockId++;

    // Add socket to socket descriptor table
    sd_table.insert(std::make_pair(socketId, sock));
    socket_tuple_table.insert(std::make_pair(sock->toTuple(), socketId));

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
        std::cerr << red << "error: socket " << socket << " could not be found" color_reset << std::endl;
        return -1;
    }

    // NOTE: Newly accepted TCPSocket should already exist in socket descriptor table
    std::shared_ptr<TCPSocket> sock = sockIt->second;
    std::shared_ptr<TCPSocket> newSock = sock->socket_accept();

    // TODO: SHOULD I BE LOCKING sd_table HERE?
    auto newSocketTuple = newSock->toTuple();
    if (socket_tuple_table.count(newSocketTuple)) {
        address = newSocketTuple.getDestAddr();
        return socket_tuple_table[newSocketTuple];
    }

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

    uint16_t srcPort = allocatePort(srcAddr, address, port);
    if (srcPort < 0) {
        return -1;
    }

    std::shared_ptr<TCPSocket> sock = std::make_shared<TCPSocket>(srcAddr, srcPort, address, port, 
                                                                  ipNode);

    // Add to socket descriptor table
    int socketId = nextSockId++;
    sd_table.insert(std::make_pair(socketId, sock));
    socket_tuple_table.insert(std::make_pair(sock->toTuple(), socketId));

    // TODO: SHOULD I BE LOCKING sd_table HERE?
    sock->socket_connect();
    return socketId;
}

int TCPNode::write(int socket, std::string& buf) {
    // TODO: handle splitting packets i.e. less than max tcp packet size

    // Check if socket descriptor exists
    auto sockIt = sd_table.find(socket);
    if (sockIt == sd_table.end()) {
        std::cerr << red << "error: connection does not exist" << color_reset << std::endl;
        return -1;
    }

    std::shared_ptr<TCPSocket> sock = sockIt->second;

    switch (sock->getState()) {
        case TCPSocket::SocketState::LISTEN:
            std::cerr << red << "error: remote socket unspecified" << color_reset << std::endl;
            return -1;
        case TCPSocket::SocketState::SYN_SENT: 
        case TCPSocket::SocketState::SYN_RECV:
            // sock->addToWaitQueue(tcpPacket); // #todo 
            std::cerr << red << "error: connection in progress" << color_reset << std::endl;
            return -1;
        case TCPSocket::SocketState::ESTABLISHED:
        case TCPSocket::SocketState::CLOSE_WAIT:
            for (int i = 0; i < buf.size(); i += MAX_TRANSMIT_UNIT) {
                std::string payload = buf.substr(i, MAX_TRANSMIT_UNIT)
                auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSendNext(), 
                                                       sock->getRecvNext(), payload);
                sock->sendTCPPacket(tcpPacket);
            }

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


/**
 * @brief Returns number of bytes read. If the call is blocking, it should loop until all bytes read
 * #todo IMPORTANT, caller should check for -1 to see if connection is closed
 * 
 * @param socket 
 * @param buf 
 * @return int 
 */
int TCPNode::read(int socket, std::string& buf, bool blocking) {
    // Find socket
    auto sockIt = sd_table.find(socket);
    if (sockIt == sd_table.end()) {
        std::cerr << red << "error: connection does not exist" << color_reset << std::endl;
        return -1;
    }
    std::shared_ptr<TCPSocket> sock = sockIt->second;

    switch (sock->getState()) {
        case TCPSocket::SocketState::CLOSED:
            std::cerr << red << "error: connection does not exist" << color_reset << std::endl;
            return -1;
        case TCPSocket::SocketState::LISTEN:
        case TCPSocket::SocketState::SYN_SENT: 
        case TCPSocket::SocketState::SYN_RECV:
            std::cerr << red << "error: connection in progress" << color_reset << std::endl;
            return -1;
        case TCPSocket::SocketState::ESTABLISHED:
        case TCPSocket::SocketState::FIN_WAIT1:
        case TCPSocket::SocketState::FIN_WAIT2:
            // TODO: If blocking call, queue for processing (some kind of cond variable?)
            return sock->readRecvBuf(buf.size(), buf, blocking);
        case TCPSocket::SocketState::CLOSE_WAIT:
            int numRead = sock->readRecvBuf(buf.size(), buf); 
            if (numRead == 0) {
                std::cerr << red << "error: connection closing" << color_reset << std::endl;
                return -1;
            }
            return numRead;
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


void TCPNode::shutdown(int socket, int type) {
    // Find socket
    auto sockIt = sd_table.find(socket);
    if (sockIt == sd_table.end()) {
        std::cerr << red << "error: connection does not exist" << color_reset << std::endl;
        // return -1;
        return;
    }
    std::shared_ptr<TCPSocket> sock = sockIt->second;

    switch (type) {
        case 1: // Close writing part, send FIN
            return;

        case 2: // Close reading part
            return;

        case 3: // Close both
            return;

        default:
            return;
        
    }
}


void TCPNode::close(int socket) {
    return;
}

void TCPNode::retransmitPackets() {
    while (true) {
        for (auto& [_, sock] : sd_table) {
            sock->retransmitPackets();
        }
    }
}

TCPTuple TCPNode::extractTCPTuple(std::shared_ptr<struct ip> ipHeader, 
        std::shared_ptr<struct tcphdr> tcpHeader) {

    std::string remoteAddr = ip::make_address_v4(ipHeader->ip_src.s_addr).to_string();
    unsigned int remotePort = tcpHeader->th_sport;
    std::string localAddr = ip::make_address_v4(ipHeader->ip_dst.s_addr).to_string();
    int localPort = tcpHeader->th_dport;

    return TCPTuple(localAddr, localPort, remoteAddr, remotePort);
}

uint32_t TCPNode::calculateSegmentEnd(std::shared_ptr<struct tcphdr> tcpHeader, std::string& payload) {
    int additionalByte = tcpHeader->th_flags & (TH_SYN | TH_FIN);
    return tcpHeader->th_seq + payload.size() + additionalByte;
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
    handleClient(ipHeader, tcpHeader, payload);
}


// #todo, handle removing from incomplete to complete 
void TCPNode::handleClient(
    std::shared_ptr<struct ip> ipHeader, 
    std::shared_ptr<struct tcphdr> tcpHeader, 
    std::string payload) {

    TCPTuple socketTuple = extractTCPTuple(ipHeader, tcpHeader);

    // ===================================================================================
    // CLOSED
    // ===================================================================================

    if (!socket_tuple_table.count(socketTuple)) {
        transitionFromClosed(tcpHeader, payload, socketTuple);
        return;
    }

    // ===================================================================================
    // LISTEN
    // ===================================================================================

    // Check if listen socket exists
    std::shared_ptr<TCPSocket> sock = getSocket(socketTuple);
    SocketState sockState = sock->getState();
    if (sock && sockState == TCPSocket::SocketState::LISTEN) {
        transitionFromListen(tcpHeader, payload, sock, socketTuple);
        // Only continue processing if SYN present
        if (!(tcpHeader->th_flags & TH_SYN)) {
            return;
        }
    } 

    // ===================================================================================
    // SYN_SENT 
    // ===================================================================================
    
    if (sockState == TCPSocket::SocketState::SYN_SENT) {
        transitionFromSynSent(tcpHeader, ipHeader, payload, sock);
        return;
    }

    // ===================================================================================
    // OTHER STATES
    // ===================================================================================

    // 1) Check validity
    if (!segmentIsAcceptable(tcpHeader, payload, sock)) {
        if (tcpHeader->th_flags & TH_RST) {
            return;
        }

        // Send ACK
        auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSendNext(), sock->getRecvNext(), "");
        sock->sendTCPPacket(tcpPacket) ;
        return;
    }
    
    // Trim payload
    trimPayload(sock, tcpHeader, payload);
    
    // 2) Check the reset bit
    if (tcpHeader->th_flags & TH_RST) {
        transitionFromOtherRSTBit(tcpHeader, payload, sock);
        return;
    }

    // 3) Don't need to check security

    // 4) Check SYN bit
    if (tcpHeader->th_flags & TH_SYN) {
        transitionFromOtherSYNBit(tcpHeader, payload, sock);
    }

     // 5) Check ACK bit
    if (tcpHeader->th_flags & TH_ACK) {
        transitionFromACKBit(tcpHeader, payload, sock);

        tcp_seq ack = tcpHeader->th_ack;
        if (ack <= sock->getUnAck() || ack > sock->getSendNext()) {
            return;
        }
        if (sockState == TCPSocket::SocketState::CLOSED || 
            sockState == TCPSocket::SocketState::TIME_WAIT) {
            return;
        }
    } else {
        return;
    }

    // 6) Check URG bit
    // Not doing for now

    // 7) Process segment text
    processSegmentText(tcpHeader, payload, sock);
        
    // 8) Check FIN bit
    if (tcpHeader->th_flags & TH_FIN) {
        transitionFromOtherFIN(tcpHeader, payload, sock);
    }
}
    
// Handles messages received when socket does not exist
void TCPNode::transitionFromClosed(std::shared_ptr<struct tcphdr> tcpHeader, 
        std::string& payload, TCPTuple& socketTuple) {

    std::shared_ptr<TCPSocket> tempSock = std::make_shared<TCPSocket>(socketTuple, ipNode);

    if (!(tcpHeader->th_flags & TH_RST)) {
        if (tcpHeader->th_flags & TH_ACK) {
            // Ack bit on
            auto tcpPacket = tempSock->createTCPPacket(TH_RST, tcpHeader->th_ack, 0, "");
            tempSock->sendTCPPacket(tcpPacket);
        } else {
            // Ack bit off
            uint32_t segEnd = calculateSegmentEnd(tcpHeader, payload);
            auto tcpPacket = tempSock->createTCPPacket(TH_RST, 0, segEnd, "");
            tempSock->sendTCPPacket(tcpPacket);
        }
    } 
}

// Handles creation of new socket in SYN RECEIVED state
void TCPNode::transitionFromListen(std::shared_ptr<struct tcphdr> tcpHeader, std::string& payload, 
        std::shared_ptr<TCPSocket> listenSock, TCPTuple& socketTuple) {
    // Check for RST
    if (tcpHeader->th_flags & TH_RST) {
        return;
    }

    std::shared_ptr<TCPSocket> tempSock = std::make_shared<TCPSocket>(socketTuple, ipNode);

    // Check for ACK
    if (tcpHeader->th_flags & TH_ACK) {
        auto tcpPacket = tempSock->createTCPPacket(TH_RST, tcpHeader->th_ack, 0, "");
        tempSock->sendTCPPacket(tcpPacket);
        return;
    }

    // Check for SYN
    if (tcpHeader->th_flags & TH_SYN) {
        // Add new socket to listen socket's map of SYN RECV connections
        std::shared_ptr<TCPSocket> newSock = listenSock->addIncompleteConnection(newSock);

        // Add to socket descriptor table
        int socketId = nextSockId++;
        sd_table.insert(std::make_pair(socketId, newSock));
        socket_tuple_table.insert(std::make_pair(newSock->toTuple(), socketId));

        // Send SYN + ACK
        auto tcpPacket = newSock->createTCPPacket(TH_SYN | TH_ACK, newSock->getSendNext(), 
                                                  newSock->getRecvNext(), "");
        newSock->sendTCPPacket(tcpPacket);
    } 
}

// Handles transition from SYN SENT to ESTABLISHED and simultaneous open
void TCPNode::transitionFromSynSent(std::shared_ptr<struct tcphdr> tcpHeader, 
        std::shared_ptr<struct ip> ipHeader, std::string& payload, std::shared_ptr<TCPSocket> sock) {
    // 1) Check ACK bit
    bool ackBitSet = tcpHeader->th_flags & TH_ACK;
    if (ackBitSet) {
        // If SEG.ACK =< ISS or SEG.ACK > SND.NXT, 
        // send a reset (unless the RST bit is set, if so drop the segment and return)
        // <SEQ=SEG.ACK><CTL=RST>
        // and discard the segment. Return.
        if (tcpHeader->th_ack <= sock->getIss() || tcpHeader->th_ack > sock->getSendNext()) {
            if (!(tcpHeader->th_flags & TH_RST)) {
                auto tcpPacket = sock->createTCPPacket(TH_RST, tcpHeader->th_ack, 0, "");
                sock->sendTCPPacket(tcpPacket);
            }
            return;
        }
        // Otherwise, SND.UNA < SEG.ACK =< SND.NXT, and the ACK is acceptable. 
    }

    // 2) Check RST bit
    bool rstBitSet = tcpHeader->th_flags & TH_RST;
    if (rstBitSet) {
        // Optional: deal with blind reset attack

        // If ACK was also acceptable then signal to the user "error: connection reset", 
        // drop the segment, 
        // enter CLOSED state, delete TCB, and return. 
        // Otherwise (no ACK), drop the segment and return.
        if (ackBitSet) {
            std::cerr << red << "error: connection reset" << color_reset << std::endl;
            deleteSocket(sock->toTuple());
        } 
        return;
    }

    // 3) Check security
    // N/A

    // 4) Check SYN bit
    bool synBitSet = tcpHeader->th_flags & TH_SYN;
    if (synBitSet) {
        // "If the SYN bit is on and the security/compartment is acceptable, 
        // then RCV.NXT is set to SEG.SEQ+1, IRS is set to SEG.SEQ. 
        // SND.UNA should be advanced to equal SEG.ACK (if there is an ACK), 
        // and any segments on the retransmission queue that are thereby 
        // acknowledged should be removed."

        sock->initializeRecvBuffer(tcpHeader->th_seq);
        sock->setIrs(tcpHeader->th_seq);
        if (ackBitSet) {
            sock->setUnack(tcpHeader->th_ack);
            sock->receiveTCPPacket(ipHeader, tcpHeader, payload);
        }

        // "If SND.UNA > ISS (our SYN has been ACKed), change the connection state to ESTABLISHED, 
        // form an ACK segment
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        // and send it"
        if (sock->getUnack() > sock->getIss()) {
            sock->setState(TCPSocket::SocketState::ESTABLISHED);
            auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSendNext(), sock->getRecvNext(), "");
            sock->sendTCPPacket(tcpPacket);
            // #todo make sure you're not supposed to return here
        } else {
            // Otherwise, enter SYN-RECEIVED (simultaneous open) and form a SYN+ACK segment
            // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
            // and send it
            auto tcpPacket = sock->createTCPPacket(TH_SYN | TH_ACK, sock->getIss(), 
                                                   sock->getRecvNext(), "");   
            sock->sendTCPPacket(tcpPacket);

            // Set variables
            sock->setSendWnd(tcpHeader->th_win);
            sock->setSendWl1(tcpHeader->th_seq);
            sock->setSendWl2(tcpHeader->th_ack);
        }
    }

    // 5) If neither SYN or RST bits are set, return and drop segment
}

bool TCPNode::segmentIsAcceptable(std::shared_ptr<struct tcphdr> tcpHeader, 
        std::string& payload, std::shared_ptr<TCPSocket> sock) {

    uint32_t segSeq   = tcpHeader->th_seq;
    uint32_t segEnd   = calculateSegmentEnd(tcpHeader, payload);
    uint32_t recvNext = sock->getRecvNext();
    uint32_t recvLast = recvNext + sock->getRecvWnd();

    // Segment length = 0, receive window = 0, SEG.SEQ = RCV.NXT
    if ((payload.size() == 0) && (tcpHeader->th_win == 0)) {
        if (!(segSeq == recvNext)) {
            return false;
        }
    }
    // Segment length = 0, receive window > 0, RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND
    else if ((payload.size() == 0) && (tcpHeader->th_win > 0)) {
        if (!(recvNext <= segSeq && segSeq < recvLast)) {
            return false;
        }
    } 
    // Segment length > 0, receive window = 0, not acceptable
    else if ((tcpHeader->th_win == 0) && (tcpHeader->th_win == 0)) {
        return false;
    } 
    // Segment length > 0, receive window = 0, RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND or 
    // RCV.NXT <= SEG.SEQ + SEG.LEN - 1 < RCV.NXT + RCV.WND
    else {
        if (!((recvNext <= segSeq && segSeq < recvLast) ||
            (recvNext <= segEnd - 1 && segEnd - 1 < recvLast))) {
            return false;
        }
    }
    return true;
}

void TCPNode::trimPayload(std::shared_ptr<TCPSocket> sock, std::shared_ptr<struct tcphdr> tcpHeader, std::string& payload) {
    uint32_t segSeq   = tcpHeader->th_seq;
    uint32_t segEnd   = calculateSegmentEnd(tcpHeader, payload);
    uint32_t recvNext = sock->getRecvNext();
    uint32_t recvLast = recvNext + sock->getRecvWnd();

    if (segSeq < recvNext) {
        payload = payload.substr(recvNext - segSeq);
        tcpHeader->th_seq = recvNext;
    }
    if (segEnd >= recvLast) {
        payload = payload.substr(0, sock->getRecvWnd());
    }
}

void TCPNode::transitionFromOtherRSTBit(std::shared_ptr<struct tcphdr> tcpHeader, 
        std::string& payload, std::shared_ptr<TCPSocket> sock) {

    SocketState sockState = sock->getState();
    if (sockState == TCPSocket::SocketState::SYN_RECV) {
        // Delete TCB
        int socketId = socket_tuple_table[sock->toTuple()];
        deleteSocket(sock->toTuple());

        // Flush retransmissionQueue
        sock->flushRetransmission();

        // If initiated with passive open, convert to listener socket if one doesn't exist
        if (!sock->isActiveOpen()) {
            sock->socket_listen();
            if (!socket_tuple_table.count(sock->toTuple())) {
                sd_table.insert(std::make_pair(socketId, sock));
                socket_tuple_table.insert(std::make_pair(sock->toTuple(), socketId));
            }
        }
    } else if (sockState == TCPSocket::SocketState::ESTABLISHED ||
        sockState == TCPSocket::SocketState::FIN_WAIT1 ||
        sockState == TCPSocket::SocketState::FIN_WAIT2 ||
        sockState == TCPSocket::SocketState::CLOSE_WAIT) {
        // If the RST bit is set, then any outstanding RECEIVEs and SEND should receive "reset" responses. 
        // All segment queues should be flushed. Users should also receive an unsolicited general "connection reset" signal. 

        // TODO: Send outstanding receives and sends "reset" responses

        // Flush retransmissionQueue and delete TCB
        std::cerr << red << "connection reset" << color_reset << std::endl;
        sock->flushRetransmission();
        deleteSocket(sock->toTuple());
    } else if (sockState == TCPSocket::SocketState::CLOSING ||
        sockState == TCPSocket::SocketState::LAST_ACK ||
        sockState == TCPSocket::SocketState::TIME_WAIT) {

        // delete TCB
        deleteSocket(sock->toTuple());
    }
}

void TCPNode::transitionFromOtherSYNBit(std::shared_ptr<struct tcphdr> tcpHeader, 
        std::string& payload, std::shared_ptr<TCPSocket> sock) {

    SocketState sockState = sock->getState();
    if (sockState == TCPSocket::SocketState::SYN_RECV) {
        // Delete TCB
        int socketId = socket_tuple_table[sock->toTuple()];
        deleteSocket(sock->toTuple());

        // If initiated with passive open, convert to listener socket if one doesn't exist
        if (!sock->isActiveOpen()) {
            sock->socket_listen();
            if (!socket_tuple_table.count(sock->toTuple())) {
                sd_table.insert(std::make_pair(socketId, sock));
                socket_tuple_table.insert(std::make_pair(sock->toTuple(), socketId));
            }
        }
    } else if (sockState == TCPSocket::SocketState::ESTABLISHED ||
        sockState == TCPSocket::SocketState::FIN_WAIT1 ||
        sockState == TCPSocket::SocketState::FIN_WAIT2 ||
        sockState == TCPSocket::SocketState::CLOSE_WAIT ||
        sockState == TCPSocket::SocketState::CLOSING ||
        sockState == TCPSocket::SocketState::LAST_ACK ||
        sockState == TCPSocket::SocketState::TIME_WAIT) {
            // RFC 793: send reset response
            auto tcpPacket = sock->createTCPPacket(TH_RST, sock->getSeqNext(), sock->getRecvNext(), "");
            sock->sendTCPPacket(tcpPacket);

            // #TODO: send reset responses to outstanding receives and sends

            std::cerr << red << "connection reset" << color_reset << std::endl;
            // Flush segment queues and delete TCB
            sock->flushRetransmission();
            deleteSocket(sock->toTuple());
    }
}

void TCPNode::transitionFromOtherACKBit(std::shared_ptr<struct tcphdr> tcpHeader, 
        std::string& payload, std::shared_ptr<TCPSocket> sock) {

    SocketState sockState = sock->getState();
    tcp_seq ack = tcpHeader->th_ack;
    if (sockState == TCPSocket::SocketState::SYN_RECV) {
        if (sock->getUnack() < ack && ack <= sock->getSendNext()) {
            sock->setState(TCPSocket::SocketState::ESTABLISHED);
            sock->setSendWnd(tcpHeader->th_win);
            sock->setSendWl1(tcpHeader->th_ack);
            sock->setSendWl2(tcpHeader->th_seq);

            // Notify completeConns queue 
            if (!sock->isActiveOpen()) {
                TCPTuple listenTuple = TCPTuple(NULL_IPADDR, sock->toTuple().getSrcPort(), NULL_IPADDR, 0);
                if (socket_tuple_table.count(listenTuple)) {
                    TCPSocket& listenSock = getSocket(listenTuple);
                    listenSock->moveToCompleteconnection(sock);
                }
            }

            // Need to continue processing in ESTABLISHED state
        } else {
            // send reset
            auto tcpPacket = sock->createTCPPacket(TH_RST, tcpHeader->th_ack, 0, "");
            sock->sendTCPPacket(tcpPacket);
            return;
        }
    }

    // ESTABLISHED, FIN_WAIT1, FIN_WAIT2, and CLOSE_WAIT states
    // Note, the reason why they are ORs is because they all have to do at least the processing for 
    // the established state.
    if (sockState == TCPSocket::SocketState::ESTABLISHED || 
        sockState == TCPSocket::SocketState::FIN_WAIT1   ||
        sockState == TCPSocket::SocketState::FIN_WAIT2   || 
        sockState == TCPSocket::SocketState::CLOSE_WAIT  ||
        sockState == TCPSocket::SocketState::CLOSING) {

            // Update unAck, if needed
            if (sock->getUnack() < ack && ack <= sock->getSendNext()) { 
                // If ACK follows within the window, then it is valid so update UNA
                sock->setUnack(ack);

                // Handle retransmission queue: remove those that have been acked
                sock->receiveTCPPacket(ipHeader, tcpHeader, payload);
            } else if (ack > sock->getSendNext()) {
                // This is reached if an ack has been received for something that hasn't even 
                // been sent yet.
                // Send an ack w/ old seq and ack nums
                auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSendNext(), 
                                                       sock->getRecvNext(), "");
                sock->sendTCPPacket(tcpPacket);
                return;
            }

            // Update send window, if needed
            if (sock->getUnack() <= ack && ack <= sock->getSendNext()) {
                // If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), 
                // set SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
                if ((sock->getSendWl1() < tcpHeader->th_seq) || 
                    (sock->getSendWl1() == tcpHeader->th_seq && sock->getSendWl2() <= ack)) {
                    // WL1 records the sequence number of the last segment used to update SND.WND, 
                    // and that SND.WL2 records the acknowledgment number of the last segment used 
                    // to update SND.WND. 
                    // The check here prevents using old segments to update the window.
                    sock->setSendWnd(tcpHeader->th_win);
                    sock->setSendWl1(tcpHeader->th_seq);
                    sock->setSendWl2(ack);
                }
            }
                
            // FIN-WAIT-1
            if (sockState == TCPSocket::SocketState::FIN_WAIT1) {
                // If our FIN segment we previously sent was acknowledged, move to FIN_WAIT2
                if (ack == sock->getSendNext()) { // #todo double check this logic
                    sock->setState(TCPSocket::SocketState::FIN_WAIT2);
                }
            }

            // FIN-WAIT-2
            if (sockState == TCPSocket::SocketState::FIN_WAIT2) {
                // if the retransmission queue is empty, 
                // the user's CLOSE can be acknowledged ("ok") but do not delete the TCB.
                if (sock->retransmissionQueueEmpty()) {
                    std::cout << "ok" << std::endl;
                }
            }

            if (sockState == TCPSocket::SocketState::CLOSING) {
                // If the ACK acknowledges our FIN, enter the TIME-WAIT state; 
                // otherwise, ignore the segment
                if (ack == sock->getSendNext()) {
                    sock->setState(TCPSocket::SocketState::TIME_WAIT);
                    sock->resetTimedWaitTime();
                }
            }
        }

        if (ackBitSet && sockState == TCPSocket::SocketState::LAST_ACK) {
            // The only thing that can arrive in this state is an 
            // acknowledgment of our FIN. If our FIN is now acknowledged, 
            // delete the TCB, enter the CLOSED state, and return.
            if (ack == sock->getSendNext()) { 
                sock->setState(TCPSocket::SocketState::CLOSED);
                deleteSocket(sock->toTuple());
                return;
            }
        }

        if (ackBitSet && sockState == TCPSocket::SocketState::TIME_WAIT) {
            // The only thing that can arrive in this state is a 
            // retransmission of the remote FIN. Acknowledge it, and restart the 2 MSL timeout.
            if (tcpHeader->th_flags & TH_FIN) { // #todo check logic, do we need to check seq and ack too?
                auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSendNext(), 
                                                       sock->getRecvNext(), "");
                sock->sendTCPPacket(tcpPacket);

                // Restart 2 MSL timeout
                sock->resetTimeWaitTime();
                return;
            }
        }
}

void processSegmentText(std::shared_ptr<struct tcphdr> tcpHeader,
        std::string& payload, std:;shared_ptr<TCPSocket> sock) {

    SocketState sockState = sock->getState();
    if (sockState == TCPSocket::SocketState::ESTABLISHED || 
        sockState == TCPSocket::SocketState::FIN_WAIT1   ||
        sockState == TCPSocket::SocketState::FIN_WAIT2) {
            // TODO: handle early arrivals 

            // For now, only add if sequence number matches exactly
            // #todo handle case where seq number is less than expected
            if (tcpHeader->th_seq == sock->getRecvNext()) {
                int numWritten = sock->writeRecvBuf(payload.size(), payload, sock->getRecvNext());

                // move next byte expected pointer forward
                sock->setRecvBufNext(sock->getSendNext() + numWritten);

                // TODO: loop through out of order queue to try and fill in

                // send ack
                // note, we don't have to worry about send window bc we are sending an empty payload
                auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSendNext(), 
                                                       sock->getRecvNext(), "");
                sock->sendTCPPacket(tcpPacket);
            }
            // TODO: consider piggy backing
        }
    
    if (sockState == TCPSocket::SocketState::CLOSE_WAIT ||
        sockState == TCPSocket::SocketState::CLOSING    ||
        sockState == TCPSocket::SocketState::LAST_ACK   ||
        sockState == TCPSocket::SocketState::TIME_WAIT) {

        // this should not occur
        std::cerr << red << "error: data received after FIN from remote side" << color_reset << std::endl;
    }
}

void transitionFromOtherFIN(std::shared_ptr<struct tcphdr> tcpHeader, 
        std::string& payload, std::shared_ptr<TCPSocket> sock) {

    SocketState sockState = sock->getState();
    if (sockState == TCPSocket::SocketState::CLOSED || 
        sockState == TCPSocket::SocketState::LISTEN || 
        sockState == TCPSocket::SocketState::SYN_SENT) {

        // do not process because seg cannot be validated
        return;
    }
    
    // If the FIN bit is set, signal the user "connection closing" and 
    // return any pending RECEIVEs with same message, 
    // advance RCV.NXT over the FIN, and send an acknowledgment for the FIN. 
    // Note that FIN implies PUSH for any segment text not yet delivered to the user.
    std::cout << "connection closing" << std::endl;

    // TODO: return pending receives

    // advance RCV.NXT over the FIN
    // #todo, need a plus +1 here in case payload is empty?
    sock->setRecvBufNext(sock->getSendNext() + 1);

    // send ACK back
    auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSendNext(), 
                                           sock->getRecvNext(), "");
    sock->sendTCPPacket(tcpPacket);

    // Change states
    if (sockState == TCPSocket::SocketState::SYN_RECV || 
        sockState == TCPSocket::SocketState::ESTABLISHED) {
        sock->setState(TCPSocket::SocketState::CLOSE_WAIT);
    }

    if (sockState == TCPSocket::SocketState::FIN_WAIT1) {
        // If our FIN has been ACKed (perhaps in this segment), 
        // then enter TIME-WAIT, start the time-wait timer, turn off the other timers; 
        // otherwise, enter the CLOSING state.
        if (ack == sock->getSendNext()) {
            sock->setState(TCPSocket::SocketState::TIME_WAIT);
            sock->resetTimedWaitTime();
        } else {
            sock->setState(TCPSocket::SocketState::CLOSING);
        }
    }

    if (sockState == TCPSocket::SocketState::FIN_WAIT2) {
        // Enter the TIME-WAIT state. Start the time-wait timer, turn off the other timers.
        sock->setState(TCPSocket::SocketState::TIME_WAIT);
        sock->resetTimedWaitTime();
    }

    if (sockState == TCPSocket::SocketState::TIME_WAIT) {
        sock->resetTimedWaitTime();
    }    
}


void TCPNode::removeTimedWaitSockets() {
    for (auto& [_, sock] : sd_table) {
        if (sock->getState() == TCPSocket::SocketState::TIME_WAIT) {
            auto curTime = std::chrono::steady_clock::now();
            auto timeDiff = curTime - sock->getTimedWaitTime();
            if (timeDiff > TIME_WAIT_LEN) {
                deleteSocket(sock->toTuple());
            }
        }
    }
}

// Returns a port number > 0 or -1 if a port cannot be allocated
uint16_t TCPNode::allocatePort(std::string& srcAddr, std::string& destAddr, uint16_t destPort) {
    // Randomly select a port to use as srcPort
    int count = MAX_PORT - MIN_PORT + 1;
    while (count > 1) {
        TCPTuple proposedTuple = TCPTuple(srcAddr, nextEphemeral, destAddr, destPort);
        if (!socket_tuple_table.count(proposedTuple)) {
            break;
        }

        if (nextEphemeral == MAX_PORT) {
            nextEphemeral = MIN_PORT;
        } else {
            nextEphemeral++;
        }
        count--;
    }

    // Clean up sockets in TIME_WAIT if necessary
    if (count == 1) {
        removeTimedWaitSockets();

        TCPTuple proposedTuple = TCPTuple(srcAddr, nextEphemeral, destAddr, destPort);
        if (!socket_tuple_table.count(proposedTuple)) {
            return nextEphemeral;
        }
        return -1;
    }
    return nextEphemeral;
}

void TCPNode::tcpHandler(std::shared_ptr<struct ip> ipHeader, std::string& payload) {
    std::shared_ptr<struct tcphdr> tcpHeader = std::make_shared<struct tcphdr>();
    memcpy(tcpHeader.get(), &payload[0], sizeof(struct tcphdr));

    std::string remainingPayload = payload.substr(sizeof(tcphdr));

    // Validate checksum
    uint16_t prevCheckSum = tcpHeader->th_sum;
    tcpHeader->th_sum = 0;

    uint16_t srcIP = ipHeader->ip_src.s_addr;
    uint16_t destIP = ipHeader->ip_dst.s_addr;
    if (TCPSocket::computeTCPChecksum(srcIP, destIP, tcpHeader, remainingPayload) != 
        prevCheckSum) {
        return;
    }
    tcpHeader->th_sum = prevCheckSum;

    receive(ipHeader, tcpHeader, remainingPayload);
}

