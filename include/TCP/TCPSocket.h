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

#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <include/TCP/TCPSocket.h>
#include <include/TCP/CircularBuffer.h>

const uint16_t RECV_WINDOW_SIZE = 65535;

const int DEFAULT_RTO = 1;              // In seconds
const int MAX_RETRANSMITS = 5;          // Avoids the calculation of R1 and R2

const int TCP_PROTOCOL_NUMBER = 6;

const std::string NULL_IPADDR = "0.0.0.0";

class TCPSocket {
    public:

        struct TCPPacket {
            std::shared_ptr<struct tcphdr> tcpHeader;
            std::string payload;
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
            CLOSED,
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
        }

        TCPSocket(std::string localAddr, uint16_t localPort, std::string destAddr, uint16_t destPort);
        TCPSocket(const TCPTuple& otherTuple);
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
        
        SocketState getState();
        uint32_t getUnack();
        uint32_t getRecvNext();
        uint32_t getRecvWnd();
        uint16_t getSendNext();
        uint32_t getIss();
        uint32_t getIrs();
        uint16_t getSendWnd();
        uint32_t getSendWl1();
        uint32_t getSendWl2();
        bool isActiveOpen();

        void initializeRecvBuffer(uint32_t seqNum);
        bool retransmissionQueueEmpty();

        void socket_listen();
        std::shared_ptr<TCPSocket> socket_accept();
        void socket_connect();

        void addIncompleteConnection(std::shared_ptr<TCPSocket> newSock);

        int readRecvBuf(int numBytes, std::string& buf);
        int putRecvBuf(int numBytes, std::string& payload);

        void sendTCPPacket(std::unique_ptr<struct TCPPacket>& tcpPacket);
        void receiveTCPPacket(
            std::shared_ptr<struct ip> ipHeader, 
            std::shared_ptr<struct tcphdr> tcpHeader,
            std::string& payload
        );

        std::unique_ptr<struct TCPPacket> createTCPPacket(unsigned char flags, uint32_t seqNum, 
        uint32_t ackNum, std::string payload);

        void retransmitPackets();

        static uint16_t computeTCPChecksum(
            uint32_t virtual_ip_src,
            uint32_t virtual_ip_dst,
            std::shared_ptr<struct tcphdr> tcp_header,
            std::string& payload
        );

    private:
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
        std::deque<std::unique_ptr<TCPPacket>> outOfOrderQueue;

        // TODO: Potentially include both R1 and R2 timeouts
        // TODO: Dynamically calculate RTO

        // TODO: Implement zero-window probing and Silly Window Syndrome

        // Retransmission information
        int maxRetransmits { MAX_RETRANSMITS };
        int retransmitAttempts { 0 };
        std::chrono::time_point<std::chrono::steady_clock> lastRetransmitTime;
        std::atomic<bool> retransmissionActive;

        // TCP Packets to retransmit. Removed from queue once ACKed
        std::deque<std::unique_ptr<TCPPacket>> retransmissionQueue;
        TCPCircularBuffer recvBuffer;

        // NOTE: Only used by listen sockets
        std::mutex acceptMutex;
        std::condition_variable acceptCond;

        // NOTE: Only used by listen sockets
        // ESTABLISHED state
        std::deque<std::shared_ptr<TCPSocket>> completeConns;                   
        // SYN-RECEIVED state
        std::unordered_map<TCPTuple, std::shared_ptr<TCPSocket>> incompleteConns;  

        void flushRetransmission();

        unsigned int generateISN(
            std::string& srcAddr,
            unsigned int srcPort,
            std::string& destAddr,
            unsigned int destPort
        );

        struct siphash_key generateSecretKey();
};
