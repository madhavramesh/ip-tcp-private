#include <iostream>

#include "include/tools/REPL.h"
#include "include/tools/colors.h"

const int MAX_LINE_SIZE = 80;
const int FUNC_NAME_SIZE = 40;

REPL::REPL(){};

void REPL::eval(const std::string &text) {
  int spaceIdx = text.find(' ');
  std::string command = text.substr(0, spaceIdx);

  std::string remaining = "";
  if (spaceIdx != std::string::npos) {
      remaining = text.substr(spaceIdx + 1);
  }

  if (!text.empty()) {
    if (commands.count(command)) {
      commands.find(command)->second.func(remaining);
    } else {
      help();
    }
  } else {
    help();
  }
}

void REPL::register_command(CommandHandler func, const std::string &name,
                            const std::string &params,
                            const std::string &help) {
  Command command = Command(func, name, params, help);
  commands.insert(make_pair(name, command));
};

void REPL::help() {
  std::string finalStr;
  for (auto &[_, command] : commands) {
    std::string lineStr;
    lineStr += command.name + " ";
    lineStr += command.params;

    lineStr.insert(lineStr.end(), FUNC_NAME_SIZE - lineStr.size(), ' ');
    lineStr += "- " + command.help;
    finalStr += lineStr + "\n";
  }

  if (finalStr.empty()) {
    finalStr += "No available commands";
  }

  std::cout << dim << finalStr << dim_reset;
}
