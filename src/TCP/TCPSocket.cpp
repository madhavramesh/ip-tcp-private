#include <unordered_map>
#include <list>
#include <mutex>

#include <include/tools/siphash.h>
#include <include/TCP/TCPSocket.h>
#include <include/TCP/TCPTuple.h>
#include <include/TCP/CircularBuffer.h>

TCPSocket::TCPSocket(std::string localAddr, uint16_t localPort, std::string remoteAddr, uint16_t remotePort) : socketTuple(localAddr, localPort, destAddr, destPort), 
   recvBuffer(RECV_WINDOW_SIZE),
   retransmissionActive(false),
   lastRetransmitTime(std::chrono::steady_clock::now()) {}

TCPSocket::TCPSocket(const TCPTuple& otherTuple) : 
    socketTuple(otherTuple),
    recvBuffer(RECV_WINDOW_SIZE),
    retransmissionActive(false),
    lastRetransmitTime(std::chrono::steady_clock::now()) {}

TCPTuple TCPSocket::toTuple() {
    return socketTuple;
}

//
// bool TCPSocket::isListen() {
    // return state == SocketState::LISTEN;
// }

TCPSocket::SocketState TCPSocket::getState() {
    return state;
}

void TCPSocket::setState(SocketState newState) {
    state = newState;
}

void TCPSocket::setWnd(uint32_t newSendWnd) {
    sendWnd = newSendWnd;
}

void TCPSocket::setWl1(uint32_t newSendWl1) {
    sendWl1 = newSendWnd;
}

void TCPSocket::setWl2(uint32_t newSendWl2) {
    sendWl2 = newSendWnd;
}

uint32_t TCPSocket::getSeqNum() {
    return sendNext;
}

uint32_t TCPSocket::getAckNum() {
    return recvBuffer->getNext();
}

uint32_t TCPSocket::getIss() {
    return iss;
}

uint32_t TCPSocket::getIrs() {
    return irs;
}

uint16_t TCPSocket::getSendWnd() {
    return sendWnd;
}

uint32_t TCPSocket::getSendWl1() {
    return sendWl1;
}

uint32_t TCPSocket::getSendWl2() {
    return sendWl2;
}

void TCPSocket::socket_listen() {
    activeOpen = false;
    state = SocketState::LISTEN;
}

std::shared_ptr<TCPSocket> TCPSocket::socket_accept() {
    std::unique_lock<std::mutex> lk(accept_mutex);
    while (completeConns.empty()) {
        acceptCond.wait(lk);
    }

    // Remove socket from completed connections 
    std::shared_ptr<TCPSocket> acceptedSock = completeConns.front();
    completeConns.pop_front();

    lk.unlock();
    return acceptedSock;
}

void TCPSocket::socket_connect() {
    activeOpen = true;
    state = SocketState::SYN_SENT;

    sendWnd = RECV_WINDOW_SIZE;
    sendWl1 = 0;
    sendWl2 = 0;
    iss = generateISN(socketTuple.getSrcAddr(), socketTuple.getSrcPort(), socketTuple.getDestAddr(), 
                      socketTuple.getDestPort());
    irs = 0;
    maxRetransmits = MAX_RETRANSMITS;
    unAck = iss;
    sendNext = iss + 1;

    // Create TCP header and send SYN 
    auto tcpHeader = createTCPHeader(TH_SYN, iss, 0, "");
    sendTCPPacket(tcpHeader, "");
}

void TCPSocket::addIncompleteConnection(std::shared_ptr<TCPSocket> newSock) {
    // Set up new client socket
    newSock->activeOpen = false;
    newSock->state = SocketState::SYN_RECV;

    newSock->sendWnd = tcpHeader->th_win;
    newSock->sendWl1 = tcpHeader->th_seq;
    newSock->sendWl2 = 0;

    newSock->iss = generateISN(socketTuple.getSrcAddr(), socketTuple.getSrcPort(), 
                               socketTuple.getDestAddr(), socketTuple.getDestPort());
    newSock->irs = tcpHeader->th_seq;
    newSock->unAck = newSock->iss;
    newSock->sendNext = newSock->iss + 1;

    // Add socket to corresponding listening socket's incomplete connections
    incompleteConns.push_back(newSock);
}

/**
 * @brief Wrapper around read from recv buffer
 * 
 * @param buffer 
 * @param length 
 * @return int 
 */
int TCPSocket::read(int numBytes, std::string& buf) {
    return recvBuffer.read(numBytes, buf);
}

int TCPSocket::write(int numBytes, std::string& payload) {
    return recvBuffer.write(numBytes, payload);
}

void TCPSocket::addToWaitQueue(std::shared_ptr<struct tcphdr> tcpHeader, std::string payload) {

    std::unique_ptr<struct TCPPacket> tcpPacket = std::make_unique<TCPPacket>();
    tcpPacket->tcpHeader = tcpHeader;
    tcpPacket->payload = payload;

    waitToSendQueue.push_back(tcpPacket);
}

void TCPSocket::sendTCPPacket(std::unique_ptr<struct TCPPacket> tcpPacket) {
    std::shared_ptr<struct tcphdr> tcpHeader = tcpPacket->tcpHeader;
    std::string payload = tcpPacket->payload;

    std::string newPayload = "";
    newPayload.resize(sizeof(struct tcphdr));
    memcpy(&newPayload[0], tcpHeader.get(), sizeof(struct tcphdr));
    memcpy(&newPayload[sizeof(struct tcphdr)], &payload[0], payload.size());

    // Check if sequence number is within receiver's window
    if (tcpHeader->th_seq < unAck + sendWnd) {
        // Call IP's send method to send packet
        ipNode->sendMsg(socketTuple.getDestAddr(), socketTuple.getSrcAddr(), newPayload, 
                        TCP_PROTOCOL_NUMBER); 
    }
    if (tcpHeader->th_flags & (TH_SYN | TH_FIN)) {
        sendNext++;
    }
    sendNext += payload.size();

    // Add to retranmission queue if necessary 
    bool expectAck = (tcpHeader->th_flags & (th_SYN | th_FIN)) || (payload.size() > 0);
    if (expectAck) {
        retransmissionQueue.push_back(std::move(tcpPacket));
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

    if (tcpHeader->th_flags & th_ACK) {
        while (!retransmissionQueue.empty()) {
            auto& packet = retransmissionQueue.front();
            int additionalByte = tcpHeader->th_flags & (TH_SYN | TH_FIN);
            uint32_t segEnd = packet->tcpHeader->th_seq + packet->payload.size() + additionalByte;

            if (segEnd <= tcpHeader->th_ack) {
                retransmissionQueue.pop_front();
            } else {
                break;
            }
        }

        if (retransmissionQueue.empty()) {
            retransmitAttempts = 0;
            retransmissionActive = false;
        }
        lastRetransmitTime = std::chrono::steady_clock::now();
    }
}

void TCPSocket::retransmitPackets() {
    if (!retransmissionActive) {
        return;
    }

    std::chrono::milliseconds retransmitInterval(1000);
    for (int i = 0; i < retransmitAttempts; i++) {
        retransmitInterval <<= 2;
    }

    auto curTime = std::chrono::steady_clock::now();
    auto timeDiff = std::chrono::duration_cast<std::milliseconds>(curTime - it->time).count();
    if (timeDiff < retransmitInterval) {
        return;
    }

    lastRetransmitTime = curTime;
    retransmitAttempts++;

    // Close socket if too many retransmission attempts have been made
    if (retransmitAttempts > maxRetransmits) {
        state = SocketState::CLOSED;
        return;
    }

    // Retransmit packets
    for (auto& packet : retransmissionQueue) {
        std::string newPayload = "";
        newPayload.resize(sizeof(struct tcphdr));
        memcpy(&newPayload[0], packet->tcpHeader.get(), sizeof(struct tcphdr));
        memcpy(&newPayload[sizeof(struct tcphdr)], &packet->payload[0], packet->payload.size());

        ipNode->sendMsg(socketTuple.getDestAddr(), socketTuple.getSrcAddr(), newPayload, 
                        TCP_PROTOCOL_NUMBER); 
    }
}

std::unique_ptr<struct TCPPacket> TCPSocket::createTCPHeader(unsigned char flags, uint32_t seqNum, 
        uint32_t ackNum, std::string payload) {

    std::unique_ptr<struct tcphdr> tcpHeader = std::make_shared<struct tcphdr>();
    tcpHeader->th_sport = htons(socketTuple.getSrcPort());
    tcpHeader->th_dport = htons(socketTuple.getDestPort());
    tcpHeader->th_seq = htonl(seqNum);
    tcpHeader->th_ack = htonl(ackNum);
    tcpHeader->th_flags = sendFlags;

    uint16_t windowSize = recvBuffer.getWindowSize();
    tcpHeader->th_win = htons(windowSize);
    tcpHeader->th_off = 5;
    tcpHeader->th_sum = 0; 
    tcpHeader->th_urp = 0;

    // Compute checksum
    uint32_t srcIp = inet_addr(socketTuple.getSrcAddr().c_str());
    uint32_t destIp = inet_addr(socketTuple.getDestAddr().c_str());
    tcpHeader->th_sum = computeTCPChecksum(srcIp, destIp, tcpHeader, payload);

    std::unique_ptr<struct TCPPacket> tcpPacket = std::make_unique<struct TCPPacket>();
    tcpPacket->tcpHeader = tcpHeader;
    tcpPacket->payload   = payload;
    return tcpPacket;
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
uint32_t TCPSocket::generateISN(
    std::string& srcAddr, 
    uint16_t srcPort, 
    std::string& destAddr, 
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

