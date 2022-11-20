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
        std::cerr << "error: socket " << socket << " could not be found" << std::endl;
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

    uint16_t srcPort = allocatePort(srcAddr, address, port);
    if (srcPort < 0) {
        return -1;
    }

    std::shared_ptr<TCPSocket> sock = std::make_shared<TCPSocket>(srcAddr, srcPort, address, port);

    // Add to socket descriptor table
    int socketId = nextSockId++;
    sd_table.insert(std::make_pair(socketId, sock));
    socket_tuple_table.insert(std::make_pair(sock->toTuple(), socketId));

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
        return -1;
    }

    std::shared_ptr<TCPSocket> sock = sockIt->second;
    std::string payload(buf.begin(), buf.end());

    auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSeqNum(), sock->getAckNum(), "");
    switch (sock->getState()) {
        case TCPSocket::SocketState::LISTEN:
            std::cerr << red << "error: remote socket unspecified" << color_reset << std::endl;
            return -1;
        case TCPSocket::SocketState::SYN_SENT: 
        case TCPSocket::SocketState::SYN_RECV:
            sock->addToWaitQueue(tcpPacket); // #todo 
            return buf.size();
        case TCPSocket::SocketState::ESTABLISHED:
        case TCPSocket::SocketState::CLOSE_WAIT:
            sock->sendTCPPacket(tcpPacket);
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
int TCPNode::read(int socket, std::string& buf) {
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
            return 0;
        case TCPSocket::SocketState::LISTEN:
        case TCPSocket::SocketState::SYN_SENT: 
        case TCPSocket::SocketState::SYN_RECV:
            return 0;
        case TCPSocket::SocketState::ESTABLISHED:
        case TCPSocket::SocketState::FIN_WAIT1:
        case TCPSocket::SocketState::FIN_WAIT2:
            // do something
            return sock->read(MAX_READ_SIZE, buf);
        case TCPSocket::SocketState::CLOSE_WAIT:
            // do something
            return sock->read(MAX_READ_SIZE, buf); // #todo check this, not sure correct
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

uint32_t calculateSegmentEnd(std::shared_ptr<struct tcphdr> tcpHeader, std::string& payload) {
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
        std::shared_ptr<TCPSocket> tempSock = std::make_shared<TCPSocket>(socketTuple);
        transitionFromClosed(tempSock, tcpHeader);
        return;
    }
    
    // ===================================================================================
    // LISTEN
    // ===================================================================================

    // Check if listen socket exists
    std::shared_ptr<TCPSocket> sock = getSocket(TCPTuple);
    if (sock && sock->getState() == TCPSocket::SocketState::LISTEN) {
        transitionFromListen(sock, tcpHeader);
        // Only continue processing if SYN present
        if (!(tcpHeader->th_flags & TH_SYN)) {
            return;
        }
    } 

    // ===================================================================================
    // SYN_SENT 
    // ===================================================================================
    
    if (sock->getState() == TCPSocket::SocketState::SYN_SENT) {
        transitionFromSynSent(sock, tcpHeader);
        return;
    }

    // ===================================================================================
    // OTHER STATES
    // ===================================================================================

    // 1) Check validity
    
    bool acceptable = true;
    int segSeq   = tcpHeader->th_seq;
    int recvNext = sock->irs + sock->recvBuffer.getNext();
    int recvLast = recvNext + sock->recvBuffer.getWindowSize();

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
        tcp_seq ack = tcpHeader->th_ack;
        
        if (ackBitSet && sock->getState() == TCPSocket::SocketState::SYN_RECV) {
            if (sock->getUnack < ack && ack <= sock->getSendNext()) { // #todo double check
                sock->setState(TCPSocket::SocketState::ESTABLISHED);
                sock->sndWnd = tcpHeader->th_win;

                sock->seqNum = tcpHeader->th_ack;
                sock->ackNum = tcpHeader->th_seq;
                // continue processing in ESTABLISHED state
            } else {
                // send reset
                sock->seqNum = tcpHeader->th_ack;
                auto tcpPacket = sock->createTCPPacket(TH_RST, tcpHeader->th_ack, 0, "");
                sock->sendTCPPacket(tcpPacket);
                return;
            }
        // Send ACK
        auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSeqNum(), sock->getAckNum(), "");
        sock->sendTCPPacket(tcpPacket);
        return;
    }
    }
    
    // trim 
    // TODO: ADJUST TCP HEADER 
    if (segSeq < recvNext) {
        payload = payload.substr(recvNext - segSeq + 1);
    }
    if (recvLast <= segSeq + payload.size() - 1) {
        payload = payload.substr(0, recvLast - segSeq);
    }
    
    // 2) Check the reset bit
    bool resetBitSet = tcpHeader->th_flags & TH_RST;

    if (resetBitSet && (sock->getState() == TCPSocket::SocketState::SYN_RECV)) {
        // If initiated with passive open, return back to listen state
        client_port_table[destPort].erase(socketId);
        client_sd_table.erase(socketId);

        // # potentially consider active vs passive open

        // # flush
        flushSendBuffer(socket);

        return;
    }

    else if (resetBitSet && (
        sock->getState() == TCPSocket::SocketState::ESTABLISHED ||
        sock->getState() == TCPSocket::SocketState::FIN_WAIT_1 ||
        sock->getState() == TCPSocket::SocketState::FIN_WAIT_2 ||
        sock->getState() == TCPSocket::SocketState::CLOSE_WAIT ||
        )) {
        // If the RST bit is set, then any outstanding RECEIVEs and SEND should receive "reset" responses. 
        // All segment queues should be flushed. Users should also receive an unsolicited general "connection reset" signal. 
        // Enter the CLOSED state, delete the TCB, and return

        // #todo send reset responses to outstanding receives and sends
        // # flush
        flushSendBuffer(socket);
        std::cout << "connection reset" << std::endl;
        sock->setSite(TCPSocket::SocketState::CLOSED);

        return;
    }

    else if (resetBitSet && (
        sock->getState() == TCPSocket::SocketState::CLOSING ||
        sock->getState() == TCPSocket::SocketState::LAST_ACK ||
        sock->getState() == TCPSocket::SocketState::TIME_WAIT)) {
            // If the RST bit is set, then enter the CLOSED state, delete the TCB, and return.
            sock->setState(TCPSocket::SocketState::CLOSED);
            // client_port_table[destPort].erase(socketId);
            // client_sd_table.erase(socketId);
            return;
    }

    // 3) Don't need to check security

    // 4) Check SYN bit
    bool synBitSet = tcpHeader->th_flags & TH_SYN;

    if (synBitSet && (sock->getState() == TCPSocket::SocketState::SYN_RECV)) {
        // Check if passive OPEN 
        if (!socket.activeOpen) {
            // Return back to listen state
            client_port_table[destPort].erase(socketId);
            client_sd_table.erase(socketId);
            
            return;
        }
    } 
    
    else if (synBitSet && (
        sock->getState() == TCPSocket::SocketState::ESTABLISHED ||
        sock->getState() == TCPSocket::SocketState::FIN_WAIT_1 ||
        sock->getState() == TCPSocket::SocketState::FIN_WAIT_2 ||
        sock->getState() == TCPSocket::SocketState::CLOSE_WAIT ||
        sock->getState() == TCPSocket::SocketState::CLOSING ||
        sock->getState() == TCPSocket::SocketState::LAST_ACK ||
        sock->getState() == TCPSocket::SocketState::TIME_WAIT)) {
            // note, this part does not follow rfc fully it seems
            // Flush
            flushSendBuffer(socket);
        }

     // 5) Check ACK bit
    bool ackBitSet = tcpHeader->th_flags & TH_ACK;
    if (!ackBitSet) {
        return;
    }
    tcp_seq ack = tcpHeader->th_ack;
    
    if (ackBitSet && sock->getState() == TCPSocket::SocketState::SYN_RECV) {
        if (sock->getUnack < ack && ack <= sock->getSendNext()) { // #todo double check
            sock->setState(TCPSocket::SocketState::ESTABLISHED);
            sock->sndWnd = tcpHeader->th_win;

            sock->seqNum = tcpHeader->th_ack;
            sock->ackNum = tcpHeader->th_seq;
            // continue processing in ESTABLISHED state
        } else {
            // send reset
            sock->seqNum = tcpHeader->th_ack;
            auto tcpPacket = sock->createTCPPacket(TH_RST, tcpHeader->th_ack, 0, "");
            sock->sendTCPPacket(tcpPacket);
            return;
        }
    }

    // ESTABLISHED, FIN_WAIT1, FIN_WAIT2, and CLOSE_WAIT states
    // Note, the reason why there are ORs is because they all have to do at least the processing for 
    // the established state.
    if (ackBitSet && (
        sock->getState() == TCPSocket::SocketState::ESTABLISHED || sock->getState() == TCPSocket::SocketState::FIN_WAIT1  ||
        sock->getState() == TCPSocket::SocketState::FIN_WAIT2   || sock->getState() == TCPSocket::SocketState::CLOSE_WAIT ||
        sock->getState() == TCPSocket::SocketState::CLOSING)) {

            // Update unAck, if needed
            if (sock->unAck < ack && ack <= sock->getSendNext()) { 
                // If ACK follows within the window, then it is valid
                // Update ack 
                sock->unAck = ack;

                // #todo handle retransmission queue: remove those that have been acked
            } else if (ack > sock->getSendNext()) {
                // This is reached if an ack has been received for something that hasn't even 
                // been sent yet.
                // Send an ack w/ old seq and ack nums
                auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSeqNum(), sock->getAckNum(), "");
                sock->sendTCPPacket(tcpPacket);
                return;
            }

            // Update send window, if needed
            if (sock->unAck <= ack && ack <= sock->getSendNext()) {
                // If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), 
                // set SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
                if (sock->getSendWl1() < tcpHeader->th_seq || 
                    // WL1 records the sequence number of the last segment used to update SND.WND, 
                    // and that SND.WL2 records the acknowledgment number of the last segment used to update SND.WND. 
                    // The check here prevents using old segments to update the window.
                    (sock->getSendWl1() == tcpHeader->th_seq && sock->getSendWl2() <= tcpHeader->th_ack)) {
                    sock->setSendWnd(tcpHeader->th_win);
                    sock->setSendWl1(tcpHeader->th_seq);
                    sock->setSendWl2(tcpHeader->th_ack);
                    }
            }
                
            // FIN-WAIT-1
            if (sock->getState() == TCPSocket::SocketState::FIN_WAIT1) {
                // If our FIN segment we previously sent was acknowledged, move to FIN_WAIT2
                if (ack == sock->getSendNext()) { // #todo double check this logic
                    sock->setState(TCPSocket::SocketState::FIN_WAIT2);
                }
            }

            // FIN-WAIT-2
            if (sock->getState() == TCPSocket::SocketState::FIN_WAIT2) {
                // if the retransmission queue is empty, 
                // the user's CLOSE can be acknowledged ("ok") but do not delete the TCB.
                if (sock->retransmissionQueue.empty()) {
                    std::cout << "ok" << std::endl;
                }
            }

            if (sock->getState() == TCPSocket::SocketState::CLOSING) {
                // If the ACK acknowledges our FIN, enter the TIME-WAIT state; otherwise, ignore the segment
                if (ack == sock->getSendNext()) { // #todo double check this logic
                    sock->setState(TCPSocket::SocketState::TIME_WAIT);
                }
            }
        }

        if (ackBitSet && sock->getState() == TCPSocket::SocketState::LAST_ACK) {
            // The only thing that can arrive in this state is an 
            // acknowledgment of our FIN. If our FIN is now acknowledged, 
            // delete the TCB, enter the CLOSED state, and return.
            if (ack == sock->getSendNext()) { // #todo double check this logic
                sock->setState(TCPSocket::SocketState::CLOSED);
                return;
            }
        }

        if (ackBitSet && sock->getState() == TCPSocket::SocketState::TIME_WAIT) {
            // The only thing that can arrive in this state is a 
            // retransmission of the remote FIN. Acknowledge it, and restart the 2 MSL timeout.
            if (tcpHeader.th_flags & TH_FIN) { // #todo check logic, do we need to check seq and ack too?
                auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSeqNum(), sock->getAckNum(), "");
                sock->sendTCPPacket(tcpPacket);
                // #todo restart 2 MSL timeout
                return;
            }
        }

    // 6) Check URG bit
    // N/A

    // 7) Process segment text

    if (sock->getState() == TCPSocket::SocketState::ESTABLISHED || 
        sock->getState() == TCPSocket::SocketState::FIN_WAIT1   ||
        sock->getState() == TCPSocket::SocketState::FIN_WAIT2   ||) {
            // #todo handle early arrivals 

            // For now, only add if sequence number matches exactly
            // #todo handle case where seq number is less than expected
            if (tcpHeader->th_seq == sock->recvBuffer.getNext() + sock->irs) {
                int numWritten = sock->recvBuffer.put(payload.size(), payload);
                // move next byte expected pointer forward
                sock->recvBuffer.setRecvBufNext(sock->getSendNext() + numWritten);

                // get new window size + update window size
                int newRecvWind = sock->recvBuffer.getWindowSize();
                sock->setRecvWnd(newRecvWind);

                // #todo loop through out of order queue to try and fill in

                // send ack
                // note, we don't have to worry about send window bc we are sending an empty payload
                auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSeqNum(), sock->getAckNum(), "");
                sock->sendTCPPacket(tcpPacket);
                return;
            }
            // #todo, consider piggy backing
        }
    
    if (sock->getState() == TCPSocket::SocketState::CLOSE_WAIT ||
        sock->getState() == TCPSocket::SocketState::CLOSING    ||
        sock->getState() == TCPSocket::SocketState::LAST_ACK   ||
        sock->getState() == TCPSocket::SocketState::TIME_WAIT) {
            // this should not occur
            std::cerr << "this should not have occured" << std::endl;
        }
        
    // 8) Check FIN bit
    bool finBitSet = tcpHeader->th_flags & TH_FIN;

    if (finBitSet && (
        sock->getState() == TCPSocket::SocketState::CLOSED || 
        sock->getState() == TCPSocket::SocketState::LISTEN || 
        sock->getState() == TCPSocket::SocketState::SYN_SENT)) {
            // do not process because seg cannot be validated
            // drop packet
            return;
        }
    
    if (finBitSet) {
        // If the FIN bit is set, signal the user "connection closing" and 
        // return any pending RECEIVEs with same message, 
        // advance RCV.NXT over the FIN, and send an acknowledgment for the FIN. 
        // Note that FIN implies PUSH for any segment text not yet delivered to the user.
        std::cout << "connection closing" << std::endl;

        // return pending receives?

        // advance RCV.NXT over the FIN
        // #todo, need a plus +1 here in case payload is empty?
        sock->recvBuffer.setRecvBufNext(sock->getSendNext() + payload.size());

        // send FIN ACK back
        auto tcpPacket = sock->createTCPPacket(TH_ACK | TH_FIN, sock->getSeqNum(), sock->getAckNum(), "");
        sock->sendTCPPacket(tcpPacket);

        // change states
        if (sock->getState() == TCPSocket::SocketState::SYN_RECV || sock->getState() == TCPSocket::SocketState::ESTABLISHED) {
            sock->setState(TCPSocket::SocketState::CLOSE_WAIT);
        }

        if (sock->getState() == TCPSocket::SocketState::FIN_WAIT1) {
            // If our FIN has been ACKed (perhaps in this segment), 
            // then enter TIME-WAIT, start the time-wait timer, turn off the other timers; 
            // otherwise, enter the CLOSING state.
            if (ack == sock->getSendNext()) { // #todo double check this logic
                sock->setState(TCPSocket::SocketState::TIME_WAIT);
                // #todo start timer
            } else {
                sock->setState(TCPSocket::SocketState::CLOSING);
            }
        }

        if (sock->getState() == TCPSocket::SocketState::FIN_WAIT2) {
            // Enter the TIME-WAIT state. Start the time-wait timer, turn off the other timers.
            sock->setState(TCPSocket::SocketState::TIME_WAIT);
            // #todo start timer
        }

        if (sock->getState() == TCPSocket::SocketState::TIME_WAIT) {
            // restart the 2 MSL timeout.
            // #todo restart timer
        }    
        // If syn in window, it is an error
        // send reset
        auto tcpPacket = sock->createTCPPacket(TH_RST, sock->getSeqNum(), sock->getAckNum(), "");
        sock->sendTCPPacket(tcpPacket);

        // Send reset response to user by making read/send return 0

        return;
    }
}
    

   


// Handles messages received when socket does not exist
void transitionFromClosed(std::shared_ptr<TCPSocket> tempSock, std::shared_ptr<struct tcphdr> tcpHeader) {
    uint32_t segEnd = calculateSegmentEnd(tcpHeader, payload);
    std::shared_ptr<TCPSocket> tempSock = std::make_shared<TCPSocket>(socketTuple);

    if (!(tcpHeader->th_flags & TH_RST)) {
        if (tcpHeader->th_flags & TH_ACK) {
            // Ack bit on
            auto tcpPacket = tempSock->createTCPPacket(TH_RST, tcpHeader->th_ack, 0, "");
            tempSock->sendTCPPacket(tcpPacket);
        } else {
            // Ack bit off
            auto tcpPacket = tempSock->createTCPPacket(TH_RST, 0, segEnd, "");
            tempSock->sendTCPPacket(tcpPacket);
        }
    } 
}

// Handles creation of new socket in SYN RECEIVED state
void transitionFromListen(std::shared_ptr<TCPSocket> sock, std::shared_ptr<struct tcphdr> tcpHeader) {
    // Check for RST
    if (tcpHeader->th_flags & TH_RST) {
        return;
    }

    // Check for ACK
    if (tcpHeader->th_flags & TH_ACK) {
        auto tcpPacket = tempSock->createTCPPacket(TH_RST, tcpHeader->th_ack, 0, "");
        tempSock->sendTCPPacket(tcpPacket);
        return;
    }

    // Check for SYN
    if (tcpHeader->th_flags & TH_SYN) {
        std::shared_ptr<TCPSocket> newSock = std::make_shared<TCPSocket>(
                socketTuple.getSrcAddr(), socketTuple.getSrcPort(), 
                socketTuple.getDestAddr(), socketTuple.getDestPort());

        sock->addIncompleteConnection(newSock);

        // Add to socket descriptor table
        int socketId = nextSockId++;
        sd_table.insert(std::make_pair(socketId, sock));
        socket_tuple_table.insert(std::make_pair(sock->toTuple(), socketId));

        // Send SYN + ACK
        auto tcpPacket = newSock->createTCPPacket(TH_SYN | TH_ACK, sock->getSeqNum(), 
                                                  sock->getAckNum(), "");
        newSock->sendTCPPacket(tcpPacket);

    // important, function should not return here!
    // that way, any payload can be processed in the syn-received state
    } 

    // Drop segment if none of the above are true
}

// Handles transition from SYN SENT to ESTABLISHED and simultaneous open
void transitionFromSynSent(std::shared_ptr<TCPSocket> sock, std::shared_ptr<struct tcphdr> tcpHeader) {
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

        // If ACK was also acceptable then signal to the user "error: connection reset", drop the segment, 
        // enter CLOSED state, delete TCB, and return. 
        // Otherwise (no ACK), drop the segment and return.
        if (ackBitSet) {
            std::cerr << "error: connection reset" << std::endl;
            int socketId = socket_tuple_table[sock->toTuple()];
            socket_tuple_table.erase(sock->toTuple());
            sd_table.erase(socketId);
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
        // and any segments on the retransmission queue that are thereby acknowledged should be removed."

        sock->initializeRecvBuffer(tcpHeader->th_seq);
        sock->setIrs(tcpHeader->th_seq);
        if (ackBitSet) {
            sock->setUnack(tcpHeader->th_ack);
            sock->receiveTCPPacket();
        }

        // "If SND.UNA > ISS (our SYN has been ACKed), change the connection state to ESTABLISHED, 
        // form an ACK segment
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        // and send it"
        if (sock->getUnack() > sock->getIss()) {
            sock->setState(TCPSocket::SocketState::ESTABLISHED);
            auto tcpPacket = sock->createTCPPacket(TH_ACK, sock->getSeqNum(), getAckNum(), "");
            sock->sendTCPPacket(tcpPacket);
            // #todo make sure you're not supposed to return here
        } else {
            // Otherwise, enter SYN-RECEIVED (simultaneous open) and form a SYN+ACK segment
            // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
            // and send it
            auto tcpPacket = sock->createTCPPacket(TH_SYN | TH_ACK, sock->getIss(), 
                                                   sock->getAckNum(), "");   
            sock->sendTCPPacket(tcpPacket);

            // Set variables
            sock->setSendWnd(tcpHeader->th_win);
            sock->setSendWl1(tcpHeader->th_seq);
            sock->setSendWl2(tcpHeader->th_ack);
        }
    }

    // 5) If neither SYN or RST bits are set, return and drop segment
}

// #todo need to rewrite 
// std::vector<std::tuple<int, socket>> TCPNode::getsockets() {
    // std::vector<std::tuple<int, socket>> sockets;
    // for (auto& sock : client_sd_table) {
        // sockets.push_back(std::make_tuple(sock->first, sock->second));
    // }
    // return sockets;
// }
//
// std::vector<std::tuple<int, ListenSocket>> TCPNode::getListenSockets() {
    // std::vector<std::tuple<int, ListenSocket>> listenSockets;
    // for (auto& listenSock : listen_sd_table) {
        // listenSockets.push_back(std::make_tuple(listensock->first, listensock->second));
    // }
    // return listenSockets;
// }
//
void flushSendBuffer(TCPSocket& sock) { // #todo: reimplement
    // int cap = sock->sendBuffer.getCapacity();
    // int sendWindowSize = cap - sock->sendBuffer.getWindowSize();

    // std::vector<char> buf(sendWindowSize);
    // int numCopied = sock->sendBuffer.getNumBytes(sendWindowSize, buf);

    // std::string payload(buf.begin(), buf.end());
    // auto tcpPacket = sock->createTCPPacket(TH_ACK, 0, sock->getAckNum(), payload);
    // sock->sendTCPPacket(tcpPacket);
}

// Returns a port number > 0 or -1 if a port cannot be allocated
uint16_t TCPNode::allocatePort(std::string& srcAddr, std::string& destAddr, uint16_t destPort) {
    // Randomly select a port to use as srcPort
    // NOTE: Inefficient when large number of ports are being used
    int count = MAX_PORT - MIN_PORT + 1;
    while (count > 0) {
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

