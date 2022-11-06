#pragma once

#include <unordered_map>
#include <vector>
<<<<<<< Updated upstream
#include <deque>
#include <unordered_map>
=======
#include <string>
>>>>>>> Stashed changes

#include <include/IP/IPNode.h>

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

struct ListenSocket {
    int id;
    std::string srcAddr;
    unsigned int srcPort;
    deque<ClientSocket> completeConns;   // ESTABLISHED state
    deque<ClientSocket> incompleteConns; // SYN-RECEIVED state
}

struct ClientSocket {
    int id;
    SocketState state;
    std::string destAddr;
    unsigned int destPort;
    std::string srcAddr;
    unsigned int srcPort;
};

class TCPNode {
    public:
        TCPNode(unsigned int port);

        // creates a new socket, binds the socket to an address/port
        // If addr is nil/0, bind to any available interface
        // After binding, moves socket into LISTEN state (passive OPEN in the RFC)
        // returns socket number on success or negative number on failure
        // Some possible failures: ENOMEM, EADDRINUSE, EADDRNOTAVAIL
        // (Note that a listening socket is used for "accepting new
        // connections")
        int connect(std::string& address, unsigned int port);


        // creates a new socket and connects to an address (active OPEN in the RFC)
        // returns the socket number on success or a negative number on failure
        // You may choose to implement a blocking connect or non-blocking connect
        // Some possible failures: EAGAIN, ECONNREFUSED, ENETUNREACH, ETIMEDOUT
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

    private:
        IPNode ipNode;
        // socket descriptor -> socket struct
        std::unordered_map<int, struct ClientSocket> client_socket_table;
        std::unordered_map<int, struct ListenSocket> listen_socket_table;
};
