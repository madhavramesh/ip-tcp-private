#pragma once

#include "include/repl/REPL.h"
#include "include/IP/Node.h"
#include <iostream>
#include <memory>

class IPCommands : public REPL {
    public:
        IPCommands(std::shared_ptr<Node> node);

        void interfaces(std::string& args);
        void routes(std::string& args);

        void send(std::string& args);

        void up(std::string& args);
        void down(std::string& args);
        void quit(std::string& args);

        void help(std::string& args);
        void register_commands() override;

    private:
        std::shared_ptr<Node> node;
};
