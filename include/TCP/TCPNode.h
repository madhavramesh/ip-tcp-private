#pragma once

#include <unordered_map>
#include <vector>
#include <deque>
#include <string>
#include <list>
#include <memory>

#include <boost/circular_buffer.hpp>

#include <include/IP/IPNode.h>

class IPNode;

const int MIN_PORT = 1024;
const int MAX_PORT = 65535;

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

std::unordered_map<SocketState, std::string> SocketStateString = {
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


class TCPNode {
    public:
        std::shared_ptr<IPNode> ipNode;
        
        // Initializes new IPNode
        TCPNode(unsigned int port);

        // creates a new socket and connects to an address (active OPEN in the RFC)
        // returns the socket number on success or a negative number on failure
        // You may choose to implement a blocking connect or non-blocking connect
        // Some possible failures: EAGAIN, ECONNREFUSED, ENETUNREACH, ETIMEDOUT
        int connect(std::string& address, unsigned int port);

        // creates a new socket, binds the socket to an address/port
        // If addr is nil/0, bind to any available interface
        // After binding, moves socket into LISTEN state (passive OPEN in the RFC)
        // returns socket number on success or negative number on failure
        // Some possible failures: ENOMEM, EADDRINUSE, EADDRNOTAVAIL
        // (Note that a listening socket is used for "accepting new
        // connections")
        int listen(std::string& address, unsigned int port);

        // accept a requested connection from the listening socket's connection queue
        // returns new socket handle on success or error on failure.
        // if node is not null, it should fill node with the new connection's address accept 
        // is REQUIRED to block when there is no awaiting connection
        // Some possible failures: EBADF, EINVAL, ENOMEM
        int accept(int socket, std::string& address);

        // read on an open socket (RECEIVE in the RFC)
        // return num bytes read or negative number on failure or 0 on eof and shutdown_read
        // nbyte = 0 should return 0 as well
        // read is REQUIRED to block when there is no available data
        // All reads should return at least one data byte unless failure or eof occurs
        // Some possible failures : EBADF, EINVAL
        int read(int socket, std::vector<char>& buf);

        // write on an open socket (SEND in the RFC)
        // return num bytes written or negative number on failure
        // nbyte = 0 should return 0 as well
        // write is REQUIRED to block until all bytes are in the send buffer
        // Some possible failures : EBADF, EINVAL, EPIPE
        int write(int socket, std::vector<char>& buf);

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


        // Helper function
        std::vector<std::tuple<int, ClientSocket>> getClientSockets();
        std::vector<std::tuple<int, ListenSocket>> getListenSockets();

    private:
        int nextSockId;
        // socket descriptor -> Client Socket
        std::unordered_map<int, struct ClientSocket> client_sd_table;
        // socket descriptor -> Listen Socket
        std::unordered_map<int, struct ListenSocket> listen_sd_table;

        // dest port -> list of Listen Socket Descriptor
        std::unordered_map<unsigned int, std::list<int>> listen_port_table;
        // dest port -> list of Client Socket Descriptors
        std::unordered_map<unsigned int, std::list<int>> client_port_table;

        void send(ClientSocket& clientSock, unsigned char sendFlags);

        typedef std::tuple<std::string, unsigned int, std::string, unsigned int> AddrAndPort;
        AddrAndPort extractAddrPort(
            std::shared_ptr<struct ip> ipHeader,
            std::shared_ptr<struct tcphdr> tcpHeader
        );

        void receive(
            std::shared_ptr<struct ip> ipHeader, 
            std::shared_ptr<struct tcphdr> tcpHeader,
            std::string& payload
        );

        void receiveSYN(
            std::shared_ptr<struct ip> ipHeader, 
            std::shared_ptr<struct tcphdr> tcpHeader
        );

        void receiveSYNACK(
            std::shared_ptr<struct ip> ipHeader, 
            std::shared_ptr<struct tcphdr> tcpHeader
        );

        void receiveACK(
            std::shared_ptr<struct ip> ipHeader, 
            std::shared_ptr<struct tcphdr> tcpHeader
        );

        template <typename Iter>
        typename Iter::iterator getClientSocket(
            std::string& srcAddr,
            unsigned int srcPort,
            std::string& destAddr,
            unsigned int destPort,
            Iter& iterable) {
            static_assert(std::is_same<typename Iter::value_type, int>::value, 
                          "Iterable must contain ints");

            typename Iter::iterator it;
            for (it = iterable.begin(); it != iterable.end(); it++) {
                int socketDescriptor = *it;
                if (!client_sd_table.count(socketDescriptor)) {
                    continue;
                }

                // Check that (srcAddr, srcPort, destAddr, destPort) match
                ClientSocket& clientSock = client_sd_table[socketDescriptor];
                if (clientSock.srcAddr == destAddr && clientSock.srcPort == destPort && 
                        clientSock.destAddr == srcAddr && clientSock.destPort == srcPort) {
                    break;
                }
            }
            return it;
        };

        template <typename Iter>
        typename Iter::iterator getListenSocket(unsigned int destPort, Iter& iterable) {
            static_assert(std::is_same<typename Iter::value_type, int>::value, 
                          "Iterable must contain ints");

            typename Iter::iterator it;
            for (it = iterable.begin(); it != iterable.end(); it++) {
                int socketDescriptor = *it;
                if (!listen_sd_table.count(socketDescriptor)) {
                    continue;
                }

                if (listen_sd_table[socketDescriptor].srcPort == destPort) {
                    break;
                }
            }
            return it;
        };

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

        friend class IPNode;
};
