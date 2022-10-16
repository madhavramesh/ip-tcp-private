#pragma once

#include "../utils/REPL.h"
#include <iostream>

class IPCommands : REPL {
    public:
        IPCommands();

        static std::string hello(std::vector<std::string> args);
        void register_commands() override;
};
