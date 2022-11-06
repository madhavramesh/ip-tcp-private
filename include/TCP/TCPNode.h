#pragma once

#include <vector>

using namespace boost::asio;

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

struct Socket {
    int id;
    std::string destAddr;
    unsigned int destPort;
    std::string srcAddr;
    unsigned int srcPort;
};

class TCPNode {
    public:
        TCPNode(unsigned int port);

        // connect();
        // listen();
        // accept();
        void read(int socket, std::vector<char> buf);
        void write(int socket, std::vector<char> buf);
        void shutdown(int socket, int type);
        void close(int socket);

    private:
};
