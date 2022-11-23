#pragma once

#include <unordered_map>
#include <deque>
#include <string>
#include <list>
#include <condition_variable>
#include <mutex>
#include <memory>
#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <unordered_map>
#include <tuple>
#include <chrono> 
#include <mutex>
#include <shared_mutex>
#include <queue>

#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <include/IP/IPNode.h>
#include <include/TCP/TCPSocket.h>
#include <include/TCP/CircularBuffer.h>

const uint16_t RECV_WINDOW_SIZE = 65535;

// RFC states that lower bound for RTO should be 1 second
// For this project, this is too long so we use 1 ms
// #todo this was changed
const int DEFAULT_RTO = 5;                     // milliseconds
const int DEFAULT_PROBE_INTERVAL = 64;         // milliseconds
const int MAX_PROBE_INTERVAL = 512;            // milliseconds

// MAX_RETRANSMIT = R1 in RFC. We use exponential backoff too though.
const int MAX_RETRANSMITS = 5;                  
const int TIME_WAIT_LEN = 120000;               // milliseconds

const int TCP_PROTOCOL_NUMBER = 6;

const std::string NULL_IPADDR = "0.0.0.0";

class IPNode; // forward declaration 


class TCPSocket : public std::enable_shared_from_this<TCPSocket> {
    public:

        struct TCPPacket {
            std::shared_ptr<struct tcphdr> tcpHeader;
            std::string payload;

            bool operator<(const TCPPacket& p) const
            {
                return tcpHeader->th_seq < p.tcpHeader->th_seq;
            };
        };

        struct ComparePacketPtrs {
            bool operator()(const std::shared_ptr<TCPPacket>& p1, const std::shared_ptr<TCPPacket>& p2)
            {
                return (*p2) < (*p1);
            }
        };
        
        enum class SocketState {
            LISTEN,
            SYN_RECV,
            SYN_SENT,
            ESTABLISHED,
            FIN_WAIT1,
            FIN_WAIT2,
            TIME_WAIT,
            CLOSING,
            CLOSE_WAIT,
            LAST_ACK,
            CLOSED
        };

        static std::string toString(SocketState state) {
            switch (state) {
                case SocketState::LISTEN:
                    return "LISTEN";
                case SocketState::SYN_RECV:
                    return "SYN_RECV";
                case SocketState::SYN_SENT:
                    return "SYN_SENT";
                case SocketState::ESTABLISHED:
                    return "ESTABLISHED";
                case SocketState::FIN_WAIT1:
                    return "FIN_WAIT1";
                case SocketState::FIN_WAIT2:
                    return "FIN_WAIT2";
                case SocketState::TIME_WAIT:
                    return "TIME_WAIT";
                case SocketState::CLOSING:
                    return "CLOSING";
                case SocketState::CLOSE_WAIT:
                    return "CLOSE_WAIT";
                case SocketState::LAST_ACK:
                    return "LAST_ACK";
                case SocketState::CLOSED:
                    return "CLOSED";
                default:
                    return "NONE";
            }
        };

        TCPSocket(
            std::string localAddr, 
            uint16_t localPort, 
            std::string destAddr, 
            uint16_t destPort, 
            std::shared_ptr<IPNode> node
        );
        TCPSocket(const TCPTuple& otherTuple, std::shared_ptr<IPNode> node);
        ~TCPSocket();

        TCPTuple toTuple();

        void setState(SocketState newState);
        void setUnack(uint32_t newUnack);
        void setSendWnd(uint16_t newSendWnd);
        void setSendWl1(uint32_t newSendWl1);
        void setSendWl2(uint32_t newSendWl2);
        void setAckNum(uint32_t newAckNum);
        void setSeqNum(uint32_t newSeqNum);
        void setIrs(uint32_t newIrs);
        void setRecvBufNext(uint32_t newRecvBufNext);
        void setRecvBufLast(uint32_t newRecvBufLast);
        void setAllowRead(bool newAllowRead);
        void resetTimedWaitTime();
        
        SocketState getState();
        uint32_t getUnack();
        uint32_t getRecvNext();
        uint32_t getRecvLast();
        uint32_t getRecvWnd();
        uint32_t getSendNext();
        uint32_t getIss();
        uint32_t getIrs();
        uint16_t getSendWnd();
        uint32_t getSendWl1();
        uint32_t getSendWl2();
        bool getAllowRead();
        bool isActiveOpen();
        std::chrono::time_point<std::chrono::steady_clock> getTimedWaitTime();

        void initializeRecvBuffer(uint32_t seqNum);
        bool retransmissionQueueEmpty();

        void socket_listen();
        std::shared_ptr<TCPSocket> socket_accept();
        void socket_connect();

        std::shared_ptr<TCPSocket> addIncompleteConnection(std::shared_ptr<struct tcphdr> tcpHeader, TCPTuple& socketTuple);
        void moveToCompleteConnection(std::shared_ptr<TCPSocket> newSock);

        int readRecvBuf(int numBytes, std::string& buf, bool blocking);
        int writeRecvBuf(int numBytes, std::string& payload);

        void sendTCPPacket(std::shared_ptr<struct TCPPacket>& tcpPacket);
        void receiveTCPPacket(
            std::shared_ptr<struct ip> ipHeader, 
            std::shared_ptr<struct tcphdr> tcpHeader,
            std::string& payload
        );

        std::shared_ptr<struct TCPPacket> createTCPPacket(unsigned char flags, uint32_t seqNum, 
                uint32_t ackNum, std::string payload);
        void addEarlyArrival(std::shared_ptr<struct tcphdr> tcpHeader, std::string& payload);
        void handleEarlyArrivals();

        void retransmitPackets();
        void flushRetransmission();

        static uint32_t calculateSegmentEnd(
            std::shared_ptr<struct tcphdr> tcpHeader,
            std::string& payload
        );


        static uint16_t computeTCPChecksum(
            uint32_t virtual_ip_src,
            uint32_t virtual_ip_dst,
            std::shared_ptr<struct tcphdr> tcp_header,
            std::string& payload
        );


    private:
        std::shared_ptr<IPNode> ipNode;
        std::shared_mutex socketMutex;
        
        // ONLY used by passive open sockets 
        // Cleans up any data in listen socket if it exists
        std::shared_ptr<TCPSocket> originator { nullptr };
        
        std::atomic<bool> allowRead { true };
        bool activeOpen { false };
        SocketState state { SocketState::CLOSED };
        TCPTuple socketTuple;

        uint16_t sendWnd { RECV_WINDOW_SIZE };
        uint32_t sendWl1 { 0 };
        uint32_t sendWl2 { 0 };

        uint32_t iss { 0 };
        uint32_t irs { 0 };

        uint32_t unAck { 0 };
        uint32_t sendNext { 0 };

        // TCP Packets that were received out of order
        std::priority_queue<
            std::shared_ptr<TCPPacket>, 
            std::vector<std::shared_ptr<TCPPacket>>, 
            ComparePacketPtrs> earlyArrivals;

        // TODO: Dynamically calculate RTO

        // TODO: Silly Window Syndrome

        // Retransmission information
        int maxRetransmits { MAX_RETRANSMITS };
        int retransmitAttempts { 0 };
        std::chrono::time_point<std::chrono::steady_clock> lastRetransmitTime;
        std::atomic<bool> retransmissionActive;

        // Zero window probing information 
        int probeAttempts { 0 };

        // TCP Packets to retransmit. Removed from queue once ACKed
        std::deque<std::shared_ptr<TCPPacket>> retransmissionQueue;

        // Recv Buffer and condition variable to use when new bytes have been added
        std::mutex readMutex;
        std::condition_variable readCond;
        TCPCircularBuffer recvBuffer;

        // NOTE: Condition variables used ONLY by listen sockets
        std::mutex acceptMutex;
        std::condition_variable acceptCond;

        // NOTE: ONLY used by listen sockets
        // ESTABLISHED state
        std::deque<std::shared_ptr<TCPSocket>> completeConns;                   
        // SYN-RECEIVED state
        std::unordered_map<TCPTuple, std::shared_ptr<TCPSocket>> incompleteConns;  

        void zeroWindowProbe();

        // Timer used after entering timed wait state
        std::chrono::time_point<std::chrono::steady_clock> timedWaitTime;

        uint32_t generateISN(
            std::string srcAddr,
            uint16_t srcPort,
            std::string destAddr,
            uint16_t destPort
        );

        struct siphash_key generateSecretKey();
};
