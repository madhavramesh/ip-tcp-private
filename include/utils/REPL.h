#pragma once

#include <functional>
#include <string>
#include <sstream>
#include <unordered_map>
#include <vector>

typedef std::function<std::string(std::vector<std::string>)> CommandHandler;

class REPL {
    public:
        REPL();

        virtual void register_commands() = 0;
        std::string eval(const std::string& text);

    protected:
        struct Command {
            CommandHandler func;
            std::string name;
            std::vector<std::string> params;
            std::string help;
            Command(CommandHandler f, 
                    const std::string& s, 
                    const std::vector<std::string>& p,
                    const std::string &h) : func(f), params(p), name(s), help(h) {}
        };

        std::unordered_map<std::string, Command> commands;

        void register_command(CommandHandler func,
                const std::string& name, 
                const std::vector<std::string>& params,
                const std::string& help);
        std::vector<std::string> parse(const std::string& text);
        std::string help();
};
