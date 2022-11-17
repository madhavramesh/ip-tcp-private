#pragma once

#include <unordered_map>
#include <deque>
#include <string>

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

struct ClientSocket {
    int id;
    SocketState state;
    std::string destAddr;
    unsigned int destPort;
    std::string srcAddr;
    unsigned int srcPort;
    unsigned int seqNum;
    unsigned int ackNum;

    // boost::circular_buffer<char> sendBuffer();
    // boost::circular_buffer<char> recvBuffer();
};

struct ListenSocket {
    int id;
    SocketState state;
    std::string srcAddr;
    unsigned int srcPort;
    std::deque<int> completeConns;   // ESTABLISHED state
    std::deque<int> incompleteConns; // SYN-RECEIVED state
};

