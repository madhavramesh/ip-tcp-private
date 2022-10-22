#pragma once

#include <functional>
#include <string>
#include <sstream>
#include <unordered_map>
#include <vector>

typedef std::function<void(std::string&)> CommandHandler;

class REPL {
    public:
        REPL();

        virtual void register_commands() = 0;
        void eval(const std::string& text);

    protected:
        struct Command {
            CommandHandler func;
            std::string name;
            std::string params;
            std::string help;
            Command(CommandHandler f, 
                    const std::string& s, 
                    const std::string& p,
                    const std::string& h) : func(f), name(s), params(p), help(h) {}
        };

        std::unordered_map<std::string, Command> commands;

        void register_command(CommandHandler func,
                const std::string& name, 
                const std::string& params,
                const std::string& help);
        void help();
};
