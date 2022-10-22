#include "include/repl/REPL.h"
#include <iostream>

const int MAX_LINE_SIZE = 80;
const int FUNC_NAME_SIZE = 40;

REPL::REPL() {};

std::string REPL::eval(const std::string& text) {
    std::vector<std::string> args = parse(text);
    if (!args.empty()) {
        std::string command = args[0];
        if (commands.count(command)) {
            return commands.find(command)->second.func(args);
        } else {
            return help();
        }
    }
    return help();
}

void REPL::register_command(CommandHandler func,
        const std::string& name, 
        const std::vector<std::string>& params,
        const std::string& help) {
    Command command = Command(func, name, params, help);
    commands.insert(make_pair(name, command));
};

std::vector<std::string> REPL::parse(const std::string& text) {
    std::stringstream ss(text);
    std::string word;

    std::vector<std::string> args;
    while (ss >> word) {
        args.push_back(word);
    }
    return args;
}

std::string REPL::help() {
    std::string finalStr;
    for (auto &[_, command] : commands) {
        std::string lineStr;
        lineStr += command.name + " ";
        for (auto &param : command.params) {
            lineStr += "<" + param + ">" + " ";
        }

        lineStr.insert(lineStr.end(), FUNC_NAME_SIZE - lineStr.size(), ' ');
        lineStr += "- " + command.help;
        finalStr += lineStr + "\n";
    }

    if (finalStr.empty()) {
        finalStr += "No available commands";
    }
    finalStr.pop_back();
    return finalStr;
}
