#include "../../include/utils/REPL.h"

REPL::REPL() {};

std::string REPL::eval(const std::string& text) {
    std::vector<std::string> args = parse(text);
    if (!args.empty()) {
        std::string command = args[0];
        if (!commands.count(command)) {
            // Call something
            return help();
        } else {
            args.erase(args.begin());
            return commands[command].func(args);
        }
    } else {
        // Call something
        return help();
    }
}

void REPL::register_command(CommandHandler func,
        const std::string& name, 
        const std::vector<std::string>& params,
        const std::string& help) {
    Command command = Command(func, name, params, help);
    commands[name] = command;
};

std::vector<std::string> parse(const std::string& text) {
    std::stringstream ss(text);
    std::string word;

    std::vector<std::string> args;
    while (ss >> word) {
        args.push_back(word);
    }
    return args;
}

std::string REPL::help() {
    std::string str;
    for (auto &[_, command] : commands) {
        str += command.name + ' ';
        for (auto &param : command.params) {
            str += "<" + param + ">" + ' ';
        }
        str.insert(str.end(), 80 - str.size(), ' ');
        str += command.help;
    }

    if (str.empty()) {
        str += "No available commands";
    }
    return str;
}
