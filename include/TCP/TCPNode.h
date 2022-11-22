#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <list>
#include <memory>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <iostream>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <include/TCP/TCPTuple.h>
#include <include/TCP/TCPSocket.h>
#include <include/IP/IPNode.h>

class IPNode;
class TCPSocket;


const uint16_t MIN_PORT = 1024;
const uint16_t MAX_PORT = 65535;

const int MAX_TRANSMIT_UNIT = 1400 - sizeof(struct ip) - sizeof(struct tcphdr);

struct SockInfo {
    int id;
    TCPTuple tuple;
    std::string state;
};

// type for shutdown
enum ShutdownType { READ, WRITE, BOTH };

class TCPNode {
    public:

        std::shared_ptr<IPNode> ipNode;
        
        // Initializes new IPNode
        TCPNode(uint16_t port);

        // creates a new socket and connects to an address (active OPEN in the RFC)
        // returns the socket number on success or a negative number on failure
        // You may choose to implement a blocking connect or non-blocking connect
        // Some possible failures: EAGAIN, ECONNREFUSED, ENETUNREACH, ETIMEDOUT
        int connect(std::string& address, uint16_t port);

        // creates a new socket, binds the socket to an address/port
        // If addr is nil/0, bind to any available interface
        // After binding, moves socket into LISTEN state (passive OPEN in the RFC)
        // returns socket number on success or negative number on failure
        // Some possible failures: ENOMEM, EADDRINUSE, EADDRNOTAVAIL
        // (Note that a listening socket is used for "accepting new
        // connections")
        int listen(std::string& address, uint16_t port);

        // accept a requested connection from the listening socket's connection queue
        // returns new socket handle on success or error on failure.
        // if node is not null, it should fill node with the new connection's address accept 
        // is REQUIRED to block when there is no awaiting connection
        // Some possible failures: EBADF, EINVAL, ENOMEM
        int accept(int socket, std::string& address);

        // write on an open socket (SEND in the RFC)
        // return num bytes written or negative number on failure
        // nbyte = 0 should return 0 as well
        // write is REQUIRED to block until all bytes are in the send buffer
        // Some possible failures : EBADF, EINVAL, EPIPE
        int write(int socket, std::string& buf, int numBytes);

        // read on an open socket (RECEIVE in the RFC)
        // return num bytes read or negative number on failure or 0 on eof and shutdown_read
        // nbyte = 0 should return 0 as well
        // read is REQUIRED to block when there is no available data
        // All reads should return at least one data byte unless failure or eof occurs
        // Some possible failures : EBADF, EINVAL
        int read(int socket, std::string& buf, int numBytes, bool blocking);

        // shutdown an connection. If type is 1, close the writing part of
        // the socket (CLOSE call in the RFC. This should send a FIN, etc.)
        // If 2 is specified, close the reading part (no equivalent in the RFC;
        // v_read calls should return 0, and the window size should not grow any
        // more). If 3 is specified, do both. The socket is NOT invalidated.
        // returns 0 on success, or negative number on failure
        // If the writing part is closed, any data not yet ACKed should still be
        // retransmitted.
        // Some possible failures : EBAF, EINVAL, ENOTCONN
        void shutdown(int socket, int type);

        // Invalidate this socket, making the underlying connection inaccessible to
        // ANY of these API functions. If the writing part of the socket has not been
        // shutdown yet, then do so. The connection shouldn't be terminated, though;
        // any data not yet ACKed should still be retransmitted.
        // Some possible failures : EBADF
        void close(int socket);

        // Returns all sockets in socket descriptor table
        std::vector<SockInfo> getSockets();

        // Used to start a separate thread to retransmit packets
        void retransmitPackets();

    private:
        int nextSockId;
        int nextEphemeral;

        // socket descriptor -> Socket
        std::unordered_map<int, std::shared_ptr<TCPSocket>> sd_table;
        // (srcAddr, srcPort, destAddr, destPort) -> socket descriptor
        std::unordered_map<TCPTuple, int> socket_tuple_table;
        std::mutex sd_table_mutex;

        std::mutex readMutex;
        std::condition_variable readCond;
        
        // Gets the TCP socket corresponding to a tuple (srcAddr, srcPort, destAddr, destPort)
        std::shared_ptr<TCPSocket> getSocket(const TCPTuple& socketTuple);
        void deleteSocket(TCPTuple socketTuple);

        TCPTuple extractTCPTuple(
            std::shared_ptr<struct ip> ipHeader,
            std::shared_ptr<struct tcphdr> tcpHeader
        );

        void receive(
            std::shared_ptr<struct ip> ipHeader, 
            std::shared_ptr<struct tcphdr> tcpHeader,
            std::string& payload
        );

        void handleClient(
            std::shared_ptr<struct ip> ipHeader, 
            std::shared_ptr<struct tcphdr> tcpHeader, 
            std::string& payload
        );

        void transitionFromClosed(
            std::shared_ptr<struct tcphdr> tcpHeader,
            std::string& payload,
            TCPTuple& socketTuple
        );

        void transitionFromListen(
            std::shared_ptr<struct tcphdr> tcpHeader,
            std::string& payload,
            std::shared_ptr<TCPSocket> listenSock, 
            TCPTuple& socketTuple
        );

        void transitionFromSynSent(
            std::shared_ptr<struct tcphdr> tcpHeader,
            std::shared_ptr<struct ip> ipHeader,
            std::string& payload,
            std::shared_ptr<TCPSocket> sock
        );

        bool segmentIsAcceptable(
            std::shared_ptr<struct tcphdr> tcpHeader,
            std::string& payload,
            std::shared_ptr<TCPSocket> sock 
        );

        void trimPayload(std::shared_ptr<TCPSocket> sock, std::shared_ptr<struct tcphdr> tcpHeder, std::string& payload);

        void transitionFromOtherRSTBit(
            std::shared_ptr<struct tcphdr> tcpHeader, 
            std::string& payload, 
            std::shared_ptr<TCPSocket> sock
        );

        void transitionFromOtherSYNBit(
            std::shared_ptr<struct tcphdr> tcpHeader, 
            std::string& payload, 
            std::shared_ptr<TCPSocket> sock
        );

        void transitionFromOtherACKBit(
            std::shared_ptr<struct ip> ipHeader,
            std::shared_ptr<struct tcphdr> tcpHeader, 
            std::string& payload, 
            std::shared_ptr<TCPSocket> sock
        );

        void processSegmentText(
            std::shared_ptr<struct tcphdr> tcpHeader, 
            std::string& payload, 
            std::shared_ptr<TCPSocket> sock
        );

        void transitionFromOtherFINBit(
            std::shared_ptr<struct tcphdr> tcpHeader, 
            std::string& payload, 
            std::shared_ptr<TCPSocket> sock
        );

        void removeTimedWaitSockets();

        // Allocates a random ephemeral port
        uint16_t allocatePort(std::string& srcAddr, std::string& destAddr, uint16_t destPort);

        void tcpHandler(std::shared_ptr<struct ip> ipHeader, std::string& payload);

        friend class IPNode;
};
