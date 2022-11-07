#pragma once

#include "include/repl/REPL.h"
#include "include/IP/IPCommands.h"
#include "include/TCP/TCPNode.h"
#include <iostream>
#include <memory>

class TCPCommands : public IPCommands {
    public:
        TCPCommands(std::shared_ptr<TCPNode> node);

        // ls
        void sockets(std::string& args);

        // a <port>
        void accept(std::string& args);

        // c <ip> <port>
        void connect(std::string& args);

        // s <socket ID> <data>
        // #todo make sure this overrides the one in ipcommands
        void send(std::string& args);

        // r <socket ID> <numbytes> <y|N>
        void recv(std::string& args);

        // sd <socket ID> <read|write|both>
        void shutdown(std::string& args);

        // cl <socket ID>
        void close(std::string& args);

        // sf <filename> <ip> <port>	
        void sendfile(std::string& args);

        // rf <filename> <port>	
        void recvfile(std::string& args);

        // q
        // #todo make sure this overrides old quit
        void quit(std::string& args);
        
        // #todo make sure this overrides old register_commands
        void register_commands() override;

    private:
        std::shared_ptr<TCPNode> tcpNode;

        void accept_loop(int sockClient, int sockListener, std::string address);
};
