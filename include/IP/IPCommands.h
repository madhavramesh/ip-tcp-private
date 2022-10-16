#pragma once

#include "include/repl/REPL.h"
#include <iostream>

class IPCommands : public REPL {
    public:
        IPCommands();

        static std::string hello(std::vector<std::string> args);
        void register_commands() override;
};
