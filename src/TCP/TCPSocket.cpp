#include <unordered_map>
#include <list>
#include <mutex>
#include <random>
#include <include/tools/siphash.h>
#include <include/TCP/TCPSocket.h>
#include <include/TCP/TCPTuple.h>
#include <include/TCP/CircularBuffer.h>
#include <include/tools/colors.h>

TCPSocket::TCPSocket(std::string localAddr, uint16_t localPort, std::string remoteAddr, 
    uint16_t remotePort, std::shared_ptr<IPNode> ipNode) : 
   socketTuple(localAddr, localPort, remoteAddr, remotePort), 
   ipNode(ipNode),
   recvBuffer(RECV_WINDOW_SIZE),
   retransmissionActive(false),
   lastRetransmitTime(std::chrono::steady_clock::now()) {
   }

TCPSocket::TCPSocket(const TCPTuple& otherTuple, std::shared_ptr<IPNode> ipNode) : 
    socketTuple(otherTuple),
    ipNode(ipNode),
    recvBuffer(RECV_WINDOW_SIZE),
    retransmissionActive(false),
    lastRetransmitTime(std::chrono::steady_clock::now()) {}

TCPSocket::~TCPSocket() {
    retransmissionQueue = {};
    completeConns = {};
}

TCPTuple TCPSocket::toTuple() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return socketTuple;
}

TCPSocket::SocketState TCPSocket::getState() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return state;
}

void TCPSocket::setState(SocketState newState) {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    if (newState == SocketState::CLOSED) {
        // Remove from any queues socket is on if this was a passive open
        if (state == SocketState::SYN_RECV) {
            std::unique_lock<std::mutex> lkAccept(originator->acceptMutex);
            originator->incompleteConns.erase(toTuple());
        } else if (state == SocketState::ESTABLISHED) {
            for (auto it = originator->completeConns.begin(); 
                    it != originator->completeConns.end(); it++) {
                if ((*it)->toTuple() == toTuple()) {
                    completeConns.erase(it);
                    break;
                }
            }
        }
    }
    originator = nullptr;
    state = newState;
}

void TCPSocket::setSendWnd(uint16_t newSendWnd) {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    sendWnd = newSendWnd;
}

void TCPSocket::setSendWl1(uint32_t newSendWl1) {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    sendWl1 = newSendWl1;
}

void TCPSocket::setSendWl2(uint32_t newSendWl2) {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    sendWl2 = newSendWl2;
}

void TCPSocket::setUnack(uint32_t newUnack) {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    unAck = newUnack;
}

void TCPSocket::setIrs(uint32_t newIrs) {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    irs = newIrs;
}

void TCPSocket::setRecvBufNext(uint32_t newRecvBufNext) {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    recvBuffer.setNext(newRecvBufNext);
}

void TCPSocket::setRecvBufLast(uint32_t newRecvBufLast) {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    recvBuffer.setLast(newRecvBufLast);
}

void TCPSocket::setAllowRead(bool newAllowRead) {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    allowRead = newAllowRead;
    std::cout << "Setting to " << newAllowRead << std::endl;
    readCond.notify_one();
}

void TCPSocket::resetTimedWaitTime() {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    timedWaitTime = std::chrono::steady_clock::now();
}

uint32_t TCPSocket::getUnack() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return unAck;
}

uint32_t TCPSocket::getRecvNext() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return recvBuffer.getNext();
}

uint32_t TCPSocket::getRecvLast() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return recvBuffer.getLast();
}

uint32_t TCPSocket::getRecvWnd() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return recvBuffer.getWindowSize();
}

uint32_t TCPSocket::getSendNext() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return sendNext;
}
uint32_t TCPSocket::getIss() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return iss;
}

uint32_t TCPSocket::getIrs() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return irs;
}

uint16_t TCPSocket::getSendWnd() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return sendWnd;
}

uint32_t TCPSocket::getSendWl1() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return sendWl1;
}

uint32_t TCPSocket::getSendWl2() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return sendWl2;
}

bool TCPSocket::getAllowRead() {
    return allowRead.load();
}

bool TCPSocket::isActiveOpen() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return activeOpen;
}

std::chrono::time_point<std::chrono::steady_clock> TCPSocket::getTimedWaitTime() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return timedWaitTime;
}

void TCPSocket::initializeRecvBuffer(uint32_t seqNum) {
    std::unique_lock<std::shared_mutex> lk(socketMutex);
    recvBuffer.initializeWith(seqNum);
}

bool TCPSocket::retransmissionQueueEmpty() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);
    return retransmissionQueue.empty();
}

void TCPSocket::socket_listen() {
    std::unique_lock<std::shared_mutex> lk(socketMutex);

    activeOpen = false;
    state = SocketState::LISTEN;
    socketTuple = TCPTuple(NULL_IPADDR, socketTuple.getSrcPort(), NULL_IPADDR, 0);

    sendWnd = RECV_WINDOW_SIZE;
    sendWl1 = 0;
    sendWl2 = 0;
    iss = 0;
    irs = 0;
    unAck = 0;
    sendNext = 0;

    earlyArrivals = {};
    retransmitAttempts = 0;
    retransmissionActive = false;
    retransmissionQueue = {};

    recvBuffer = TCPCircularBuffer(RECV_WINDOW_SIZE);

    std::unique_lock<std::mutex> lkAccept(acceptMutex);
    incompleteConns = {};
    completeConns = {};
}

std::shared_ptr<TCPSocket> TCPSocket::socket_accept() {
    std::unique_lock<std::mutex> lk(acceptMutex);
    while (completeConns.empty()) {
        acceptCond.wait(lk);
    }

    // Remove socket from completed connections 
    std::shared_ptr<TCPSocket> acceptedSock = completeConns.front();
    completeConns.pop_front();

    // accepted socket now has no originator
    acceptedSock->originator = nullptr;

    lk.unlock();
    return acceptedSock;
}

std::shared_ptr<TCPSocket::TCPPacket> TCPSocket::createTCPPacket(unsigned char flags, uint32_t seqNum, 
        uint32_t ackNum, std::string payload) {

    std::shared_ptr<struct tcphdr> tcpHeader = std::make_shared<struct tcphdr>();
    tcpHeader->th_sport = htons(socketTuple.getSrcPort());
    tcpHeader->th_dport = htons(socketTuple.getDestPort());
    tcpHeader->th_seq = htonl(seqNum);
    tcpHeader->th_ack = htonl(ackNum);
    tcpHeader->th_flags = flags;

    uint16_t windowSize = recvBuffer.getWindowSize();
    tcpHeader->th_win = htons(windowSize);
    tcpHeader->th_off = 5;
    tcpHeader->th_sum = 0; 
    tcpHeader->th_urp = 0;

    // Compute checksum
    uint32_t srcIp = inet_addr(socketTuple.getSrcAddr().c_str());
    uint32_t destIp = inet_addr(socketTuple.getDestAddr().c_str());
    tcpHeader->th_sum = computeTCPChecksum(srcIp, destIp, tcpHeader, payload);

    std::shared_ptr<TCPPacket> tcpPacket = std::make_shared<TCPPacket>();
    tcpPacket->tcpHeader = tcpHeader;
    tcpPacket->payload = payload;
    return tcpPacket; 
}


void TCPSocket::socket_connect() {
    std::unique_lock<std::shared_mutex> lk(socketMutex);

    activeOpen = true;
    state = SocketState::SYN_SENT;

    sendWnd = RECV_WINDOW_SIZE;
    sendWl1 = 0;
    sendWl2 = 0;
    iss = generateISN(socketTuple.getSrcAddr(), socketTuple.getSrcPort(), socketTuple.getDestAddr(), 
                      socketTuple.getDestPort());
    irs = 0;
    unAck = iss;
    sendNext = iss;
    
    lk.unlock();

    // Create TCP packet and send SYN 
    auto tcpPacket = createTCPPacket(TH_SYN, iss, 0, "");
    sendTCPPacket(tcpPacket);
}

std::shared_ptr<TCPSocket> TCPSocket::addIncompleteConnection(std::shared_ptr<struct tcphdr> tcpHeader, 
        TCPTuple& socketTuple) {
        
    // Set up new client socket
    std::shared_ptr<TCPSocket> newSock = std::make_shared<TCPSocket>(
            socketTuple.getSrcAddr(), socketTuple.getSrcPort(), socketTuple.getDestAddr(), 
            socketTuple.getDestPort(), ipNode);

    std::unique_lock<std::shared_mutex> lkNew(newSock->socketMutex);
    newSock->originator = shared_from_this();

    newSock->activeOpen = false;
    newSock->state = SocketState::SYN_RECV;

    newSock->sendWnd = tcpHeader->th_win;
    newSock->sendWl1 = tcpHeader->th_seq;
    newSock->sendWl2 = 0;

    newSock->iss = generateISN(socketTuple.getSrcAddr(), socketTuple.getSrcPort(), 
                               socketTuple.getDestAddr(), socketTuple.getDestPort());
    newSock->irs = tcpHeader->th_seq;
    newSock->unAck = newSock->iss;
    newSock->sendNext = newSock->iss;

    newSock->recvBuffer.initializeWith(tcpHeader->th_seq);

    // Add socket to corresponding listening socket's incomplete connections
    lkNew.unlock();

    std::unique_lock<std::mutex> lk(acceptMutex);
    incompleteConns.insert(std::make_pair(newSock->toTuple(), newSock));

    return newSock;
}

void TCPSocket::moveToCompleteConnection(std::shared_ptr<TCPSocket> sock) {
    TCPTuple socketTuple = sock->toTuple();

    std::unique_lock<std::mutex> lk(acceptMutex);
    if (!incompleteConns.count(socketTuple)) {
        return;
    }

    completeConns.push_back(incompleteConns[socketTuple]);
    incompleteConns.erase(socketTuple);
    lk.unlock();

    acceptCond.notify_one();
}

/**
 * @brief Wrapper around read from recv buffer
 * 
 * @param buffer 
 * @param length 
 * @return int 
 */
int TCPSocket::readRecvBuf(int numBytes, std::string& buf, bool blocking) {
    std::unique_lock<std::mutex> lk(readMutex);
    int readSoFar = recvBuffer.read(numBytes, buf);
    if (!blocking && readSoFar > 0) {
        return readSoFar;
    }

    while (readSoFar < numBytes && allowRead) {
        // Must block on condition variable
        readCond.wait(lk);
        readSoFar += recvBuffer.read(numBytes - readSoFar, buf);

        if (!blocking && readSoFar > 0) {
            return readSoFar;
        }

        std::shared_lock<std::shared_mutex> lkSocket(socketMutex);
        if (state != TCPSocket::SocketState::ESTABLISHED &&
            state != TCPSocket::SocketState::FIN_WAIT1 && 
            state != TCPSocket::SocketState::FIN_WAIT2) {
            std::cerr << yellow << "warning: no more bytes can be sent over connection" 
                << color_reset << std::endl;
            break;
        }
        lkSocket.unlock();
    }

    return readSoFar;
}

int TCPSocket::writeRecvBuf(int numBytes, std::string& payload) {
    std::unique_lock<std::mutex> lk(readMutex);
    int numWritten = recvBuffer.write(numBytes, payload);
    lk.unlock();

    readCond.notify_one();
    return numWritten;
}

void TCPSocket::addEarlyArrival(std::shared_ptr<struct tcphdr> tcpHeader, 
        std::string& payload) {

    std::unique_lock<std::shared_mutex> lk(socketMutex);

    std::shared_ptr<TCPPacket> packet = std::make_shared<TCPPacket>();
    packet->tcpHeader = tcpHeader;
    packet->payload = payload;

    earlyArrivals.push(packet);
}

void TCPSocket::handleEarlyArrivals() {
    std::unique_lock<std::mutex> lk(readMutex);
    std::unique_lock<std::shared_mutex> lkSocket(socketMutex);

    if (earlyArrivals.empty()) {
        return;
    }

    // this pops off old early arrivals
    auto packet = earlyArrivals.top();
    while (recvBuffer.getNext() >= calculateSegmentEnd(packet->tcpHeader, packet->payload)) {
        earlyArrivals.pop();
        if (earlyArrivals.empty()) {
            return;
        }
        packet = earlyArrivals.top();
    }

    int offset;
    int numToCopy;
    int numCopied;
    std::string buf;
    while (recvBuffer.getNext() >= packet->tcpHeader->th_seq) {
        earlyArrivals.pop();

        offset = recvBuffer.getNext() - packet->tcpHeader->th_seq;
        numToCopy = packet->payload.size() - offset;
        buf = packet->payload.substr(offset);

        numCopied = recvBuffer.write(numToCopy, buf);
        if (earlyArrivals.empty()) {
            return;
        }
        packet = earlyArrivals.top();
    }
}

void TCPSocket::sendTCPPacket(std::shared_ptr<TCPSocket::TCPPacket>& tcpPacket) {
    std::shared_ptr<struct tcphdr> tcpHeader = tcpPacket->tcpHeader;
    std::string payload = tcpPacket->payload;

    std::string newPayload(sizeof(struct tcphdr) + payload.size(), '\0');
    memcpy(&newPayload[0], tcpHeader.get(), sizeof(struct tcphdr));
    memcpy(&newPayload[sizeof(struct tcphdr)], &payload[0], payload.size());

    // Check if sequence number is within receiver's window or we're sending a RST
    if ((ntohl(tcpHeader->th_seq) < unAck + sendWnd) || (tcpHeader->th_flags & TH_RST)) {
        // // Call IP's send method to send packet
        ipNode->sendMsg(socketTuple.getDestAddr(), socketTuple.getSrcAddr(), newPayload, 
                        TCP_PROTOCOL_NUMBER); 
    }
    if (tcpHeader->th_flags & (TH_SYN | TH_FIN)) {
        sendNext++;
    }
    sendNext += payload.size();

    // Add to retransmission queue if necessary 
    bool expectAck = (tcpHeader->th_flags & (TH_SYN | TH_FIN)) || (payload.size() > 0);
    if (expectAck) {
        retransmissionQueue.push_back(tcpPacket);

        if (!retransmissionActive) {
            retransmissionActive = true;
            lastRetransmitTime = std::chrono::steady_clock::now();
        }
    }
}

void TCPSocket::receiveTCPPacket(
    std::shared_ptr<struct ip> ipHeader, 
    std::shared_ptr<struct tcphdr> tcpHeader,
    std::string& payload) {

    if (tcpHeader->th_flags & TH_ACK) {
        std::unique_lock<std::shared_mutex> lk(socketMutex);

        while (!retransmissionQueue.empty()) {
            auto& packet = retransmissionQueue.front();

            // Need to do this conversion since tcpHeader is in network byte order
            packet->tcpHeader->th_seq = ntohl(packet->tcpHeader->th_seq);
            uint32_t segStart = packet->tcpHeader->th_seq;
            uint32_t segEnd = calculateSegmentEnd(packet->tcpHeader, packet->payload);
            packet->tcpHeader->th_seq = htonl(packet->tcpHeader->th_seq);

            if (segEnd <= tcpHeader->th_ack) {
                retransmissionQueue.pop_front();
                retransmitAttempts = 0; // important
            } else {
                // Trim retransmission packet
                if (segStart < tcpHeader->th_ack) {
                    int newStart = tcpHeader->th_ack - segStart;

                    unsigned char flags = packet->tcpHeader->th_flags;
                    uint32_t seqNum = tcpHeader->th_ack;
                    uint32_t ackNum = ntohl(packet->tcpHeader->th_ack);
                    std::string newPayload = packet->payload.substr(newStart);

                    retransmissionQueue.pop_front();
                    auto newPacket = createTCPPacket(flags, seqNum, ackNum, newPayload);
                    retransmissionQueue.push_front(newPacket);
                }
                break;
            }
        }

        if (retransmissionQueue.empty()) {
            retransmissionActive = false;
            // retransmitAttempts = 0; // important
        }
        lastRetransmitTime = std::chrono::steady_clock::now();
        probeAttempts = 0;
    }
}

void TCPSocket::retransmitPackets() {
    if (!retransmissionActive) {
        return;
    }

    std::unique_lock<std::shared_mutex> lk(socketMutex);

    int retransmitInterval(DEFAULT_RTO);
    for (int i = 0; i < retransmitAttempts; i++) {
        retransmitInterval *= 2;
    }

    auto curTime = std::chrono::steady_clock::now();
    auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(curTime - lastRetransmitTime).count();
    if (timeDiff < retransmitInterval) {
        return;
    }

    lastRetransmitTime = curTime;
    retransmitAttempts++;

    // Close socket if too many retransmission attempts have been made
    if (retransmitAttempts > maxRetransmits) {
        // TODO: Figure out how to actually remove this socket from the table
        std::cerr << yellow << "warning: max retransmission attempts exceeded; socket closing" 
            << color_reset << std::endl;
        retransmissionActive = false;
        state = SocketState::CLOSED;
        return;
    }
    lk.unlock();

    // Check if zero window probing is necessary
    if (sendWnd == 0) {
        int probeInterval(DEFAULT_PROBE_INTERVAL);
        for (int i = 0; i < probeAttempts; i++) {
            probeInterval *= 2;
            if (probeInterval >= MAX_PROBE_INTERVAL) {
                break;
            }
        }

        if (timeDiff < probeInterval) {
            return;
        }
        probeAttempts++;

        zeroWindowProbe();
        // Resetting retransmitAttempts may not be necessary but can't hurt
        retransmitAttempts = 0;
        return;
    }

    // Retransmit packets
    // flushRetransmission();
    // just send first item in queue
    auto firstPacket = retransmissionQueue.front(); // #todo pop_front?

    firstPacket->tcpHeader->th_ack = htonl(recvBuffer.getNext());

    uint32_t srcIP = inet_addr(socketTuple.getSrcAddr().c_str());
    uint32_t destIP = inet_addr(socketTuple.getDestAddr().c_str());
    firstPacket->tcpHeader->th_sum = 0;
    firstPacket->tcpHeader->th_sum = computeTCPChecksum(srcIP, destIP, firstPacket->tcpHeader,
                                                        firstPacket->payload);

    std::string newPayload(sizeof(struct tcphdr) + firstPacket->payload.size(), '\0');
    memcpy(&newPayload[0], firstPacket->tcpHeader.get(), sizeof(struct tcphdr));
    memcpy(&newPayload[sizeof(struct tcphdr)], &firstPacket->payload[0], firstPacket->payload.size());
    ipNode->sendMsg(socketTuple.getDestAddr(), socketTuple.getSrcAddr(), newPayload,
                        TCP_PROTOCOL_NUMBER);
}

void TCPSocket::flushRetransmission() {
    if (!retransmissionActive) {
        return;
    }
    std::cout << "flushing retransmission queue" << std::endl;
    std::shared_lock lkShared(socketMutex);
    for (auto& packet : retransmissionQueue) {
        packet->tcpHeader->th_ack = htonl(recvBuffer.getNext());

        uint32_t srcIP = inet_addr(socketTuple.getSrcAddr().c_str());
        uint32_t destIP = inet_addr(socketTuple.getDestAddr().c_str());
        packet->tcpHeader->th_sum = 0;
        packet->tcpHeader->th_sum = computeTCPChecksum(srcIP, destIP, packet->tcpHeader, packet->payload);

        std::string newPayload(sizeof(struct tcphdr) + packet->payload.size(), '\0');
        memcpy(&newPayload[0], packet->tcpHeader.get(), sizeof(struct tcphdr));
        memcpy(&newPayload[sizeof(struct tcphdr)], &packet->payload[0], packet->payload.size());
        ipNode->sendMsg(socketTuple.getDestAddr(), socketTuple.getSrcAddr(), newPayload, 
                        TCP_PROTOCOL_NUMBER); 
    }
}

void TCPSocket::zeroWindowProbe() {
    std::shared_lock<std::shared_mutex> lk(socketMutex);

    for (auto& packet : retransmissionQueue) {
        packet->tcpHeader->th_seq = ntohl(packet->tcpHeader->th_seq);
        uint32_t segStart = packet->tcpHeader->th_seq;
        uint32_t segEnd = calculateSegmentEnd(packet->tcpHeader, packet->payload);
        packet->tcpHeader->th_seq = htonl(packet->tcpHeader->th_seq);

        if (unAck >= segStart && unAck < segEnd) {
            char probeByte = packet->payload[unAck - segStart];
            auto zeroProbe = 
                createTCPPacket(TH_ACK, unAck, recvBuffer.getNext(), std::string(1, probeByte));

            std::string newPayload(sizeof(struct tcphdr) + zeroProbe->payload.size(), '\0');
            memcpy(&newPayload[0], zeroProbe->tcpHeader.get(), sizeof(struct tcphdr));
            memcpy(&newPayload[sizeof(struct tcphdr)], &zeroProbe->payload[0], zeroProbe->payload.size());

            ipNode->sendMsg(socketTuple.getDestAddr(), socketTuple.getSrcAddr(), newPayload, 
                            TCP_PROTOCOL_NUMBER);
            break;
        }
    }
}

// The TCP checksum is computed based on a "pesudo-header" that
// combines the (virtual) IP source and destination address, protocol value,
// as well as the TCP header and payload

// For more details, see the "Checksum" component of RFC793 Section 3.1,
// https://www.ietf.org/rfc/rfc793.txt (pages 14-15)
uint16_t TCPSocket::computeTCPChecksum(
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


    size_t ph_len = sizeof(struct pseudo_header);
    size_t hdr_len = sizeof(struct tcphdr);
    assert(ph_len == 12);
    assert(hdr_len == 20);

    // From RFC: "The TCP Length is the TCP header length plus the
    // data length in octets (this is not an explicitly transmitted
    // quantity, but is computed), and it does not count the 12 octets
    // of the pseudo header."
    uint16_t tcp_len = htons(hdr_len + payload.size());
    struct pseudo_header ph { virtual_ip_src, virtual_ip_dst, 0, 6, tcp_len };

    size_t total_len = ph_len + hdr_len + payload.size();
    char buffer[total_len];
    memset(buffer, 0, total_len);
    memcpy(buffer, &ph, ph_len);
    memcpy(buffer + ph_len, tcp_header.get(), hdr_len);
    memcpy(buffer + ph_len + hdr_len, &payload[0], payload.size());

    uint16_t checksum = IPNode::ip_sum(buffer, total_len);
    return checksum;
}

// ISN = M + F(localip, localport, remoteip, remoteport, secretkey) where
// M is an ~4 microsecond timer and F() is the SipHash pseudorandom function
// of the connection's identifying parameters and a secret key
//
// For more details, see the "Initial Sequence Number Selection" component
// of RFC9293 Section 3.4.1, https://www.rfc-editor.org/rfc/rfc9293
uint32_t TCPSocket::generateISN(
    std::string srcAddr, 
    uint16_t srcPort, 
    std::string destAddr, 
    uint16_t destPort) {

    uint32_t first = ip::address_v4::from_string(srcAddr).to_ulong();
    uint32_t second = ip::address_v4::from_string(destAddr).to_ulong();
    uint32_t third = (uint32_t)(srcPort) << 16 | (uint32_t)(destPort);
    struct siphash_key key = generateSecretKey();
    uint64_t hashVal = siphash_3u32(first, second, third, key);

    auto curTime = std::chrono::system_clock::now().time_since_epoch();
    auto timeNano = std::chrono::duration_cast<std::chrono::nanoseconds>(curTime).count();
    return hashVal + (timeNano >> 6);
}

struct siphash_key TCPSocket::generateSecretKey() {
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

// This assumes header is in HOST byte order
uint32_t TCPSocket::calculateSegmentEnd(std::shared_ptr<struct tcphdr> tcpHeader, std::string& payload) {
    int additionalByte = !!(tcpHeader->th_flags & (TH_SYN | TH_FIN));
    return tcpHeader->th_seq + payload.size() + additionalByte;
}
