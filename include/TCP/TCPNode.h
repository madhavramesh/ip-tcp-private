#pragma once

#include <vector>
#include <deque>
#include <unordered_map>

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

struct ListenSocket {
    int id;
    std::string srcAddr;
    unsigned int srcPort;
    deque<ClientSocket> completeConns;   // ESTABLISHED state
    deque<ClientSocket> incompleteConns; // SYN-RECEIVED state
}

struct ClientSocket {
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
        IPNode ipNode;
        std::unordered_map<int, struct ClientSocket> client_socket_table;
        std::unordered_map<int, struct ListenSocket> listen_socket_table;
};
