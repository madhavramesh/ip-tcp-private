#pragma once

#include "include/repl/REPL.h"
#include <iostream>

class IPCommands : public REPL {
    public:
        IPCommands();

        std::string interfaces(std::vector<std::string> args);
        std::string routes(std::vector<std::string> args);

        std::string send(std::vector<std::string> args);

        std::string up(std::vector<std::string> args);
        std::string down(std::vector<std::string> args);
        std::string quit(std::vector<std::string> args);

        std::string help(std::vector<std::string> args);
        void register_commands() override;

    private:
        std::shared_ptr<Node> node;
};
