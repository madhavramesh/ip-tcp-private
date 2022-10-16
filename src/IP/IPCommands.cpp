#include "../../include/IP/IPCommands.h"

std::string IPCommands::hello(std::vector<std::string> args) {
    return "Hello world";
}

void IPCommands::register_commands() {
    register_command(&IPCommands::hello, "hello", {}, "test");
}
