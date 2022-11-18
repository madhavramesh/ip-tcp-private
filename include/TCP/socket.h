#pragma once

#include <unordered_map>
#include <deque>
#include <string>
#include <list>

#include <netinet/tcp.h>

#include "include/TCP/CircularBuffer.h"

#include <boost/circular_buffer.hpp>

enum SocketState {
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

static std::unordered_map<SocketState, std::string> SocketStateString = {
    {LISTEN, "LISTEN"},
    {SYN_RECV, "SYN_RECV"},
    {SYN_SENT, "SYN_SENT"},
    {ESTABLISHED, "ESTABLISHED"},
    {FIN_WAIT1, "FIN_WAIT1"},
    {FIN_WAIT2, "FIN_WAIT2"},
    {TIME_WAIT, "TIME_WAIT"},
    {CLOSING, "CLOSING"},
    {CLOSE_WAIT, "CLOSE_WAIT"},
    {LAST_ACK, "LAST_ACK"},
    {CLOSED, "CLOSED"},
};

struct RetransmitPacket {
    std::shared_ptr<struct tcphdr> tcpHeader;
    std::string payload;
    std::chrono::time_point<std::chrono::steady_clock> retransmitTime;
    std::chrono::seconds retransmitInterval;
    int numRetransmits;
};

struct ClientSocket {
    int id;
    bool activeOpen;
    SocketState state;
    std::string destAddr;
    unsigned int destPort;
    std::string srcAddr;
    unsigned int srcPort;

    unsigned int sendWnd;
    unsigned int sendWl1;
    unsigned int sendWl2;

    unsigned int iss;
    unsigned int irs;

    int maxRetransmits;

    unsigned int unAck;
    unsigned int sendNext;

    std::list<struct RetransmitPacket> retransmissionQueue;
    TCPCircularBuffer recvBuffer;
};

struct ListenSocket {
    int id;
    SocketState state;
    std::string srcAddr;
    unsigned int srcPort;
    std::deque<int> completeConns;   // ESTABLISHED state
    std::deque<int> incompleteConns; // SYN-RECEIVED state
};

