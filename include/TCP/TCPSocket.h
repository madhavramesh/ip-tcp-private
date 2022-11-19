#pragma once

#include <unordered_map>
#include <deque>
#include <string>
#include <list>
#include <condition_variable>
#include <mutex>
#include <memory>

#include <netinet/tcp.h>

#include <include/TCP/TCPSocket.h>
#include <include/TCP/CircularBuffer.h>

const uint16_t RECV_WINDOW_SIZE = 65535;
const int MAX_RETRANSMITS = 5;

const int TCP_PROTOCOL_NUMBER = 6;

class TCPSocket : public std::enable_shared_from_this<TCPSocket> {
    public:
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

        TCPSocket(std::string localAddr, unsigned int localPort, std::string destAddr, unsigned int destPort);
        TCPSocket(const TCPTuple& otherTuple);

        TCPTuple toTuple();
        SocketState getState();

        void socket_listen();
        std::shared_ptr<TCPSocket> socket_accept();
        void socket_connect();

        void sendTCPPacket(unsigned char sendFlags, std::string payload);
        void receiveTCPPacket(
            std::shared_ptr<struct ip> ipHeader, 
            std::shared_ptr<struct tcphdr> tcpHeader,
            std::string& payload
        );

        void retransmitPackets();

    private:
        bool activeOpen { false };
        SocketState state { SocketState::CLOSED };
        TCPTuple socketTuple;

        uint16_t sendWnd { RECV_WINDOW_SIZE };
        uint32_t sendWl1 { 0 };
        uint32_t sendWl2 { 0 };

        uint32_t iss { 0 };
        uint32_t irs { 0 };

        int maxRetransmits { MAX_RETRANSMITS };

        uint32_t unAck { 0 };
        uint32_t sendNext { 0 };

        struct TCPPacket {
            std::shared_ptr<struct tcphdr> tcpHeader;
            std::string payload;
        };
        // TCP Packets that were written while node was in SYN_SEND or SYN_RECV
        std::list<std::unique_ptr<TCPPacket>> waitToSendQueue;
        // TCP Packets that were received out of order
        std::list<std::unique_ptr<TCPPacket>> outOfOrderQueue;

        struct RetransmitPacket {
            std::shared_ptr<struct tcphdr> tcpHeader;
            std::string payload;
            std::chrono::time_point<std::chrono::steady_clock> retransmitTime;
            std::chrono::seconds retransmitInterval;
            int numRetransmits;
        };

        // TCP Packets to retransmit. Removed from queue once ACKed
        std::list<std::unique_ptr<RetransmitPacket>> retransmissionQueue;
        TCPCircularBuffer recvBuffer;

        // NOTE: Only used by listen sockets
        std::mutex acceptMutex;
        std::condition_variable acceptCond;

        // NOTE: Only used by listen sockets
        std::deque<std::shared_ptr<TCPSocket>> completeConns;                        // ESTABLISHED state
        std::unordered_map<TCPTuple, std::shared_ptr<TCPSocket>> incompleteConns;    // SYN-RECEIVED state
        std::shared_ptr<struct tcphdr> createTCPHeader(unsigned char flags, std::string payload);

        uint16_t computeTCPChecksum(
            uint32_t virtual_ip_src,
            uint32_t virtual_ip_dst,
            std::shared_ptr<struct tcphdr> tcp_header,
            std::string& payload
        );

        unsigned int generateISN(
            std::string& srcAddr,
            unsigned int srcPort,
            std::string& destAddr,
            unsigned int destPort
        );

        struct siphash_key generateSecretKey();
};
