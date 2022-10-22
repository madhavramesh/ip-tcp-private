#include "../../include/IP/IPCommands.h"

#include <string>

const int ROUTE_COL_SIZE = 15;

IPCommands::IPCommands(std::shared_ptr<Node> node) node(node) {}

std::string IPCommands::interfaces(std::vector<std::string> args) {

    return "interfaces";
}

std::string IPCommands::routes(std::vector<std::string> args) {
    // if (args.size() > 1) {
        // return "";
    // }
//
    // std::vector<std::string> colNames = { "dest", "next", "cost" };
//
    // std::string routeString;
    // for (auto& colName : colNames) {
        // routeString.insert(routeString.end(), ROUTE_COL_SIZE - colName.size(), ' ');
        // routeString += colName;
    // }
//
    // auto routes = node->getRoutes();
    // for (auto& [srcName, destInfo] : routes) {
        // auto& [destName, cost] = destInfo;
        // std::cout << srcName << " " << destName << " " << std::to_string(cost) << std::endl;
    // }
    return "Routes";
}

std::string IPCommands::send(std::vector<std::string> args) {
    
    return "Sending";
}

std::string IPCommands::up(std::vector<std::string> args) {
    return "Bringing up";
}

std::string IPCommands::down(std::vector<std::string> args) {
    return "Bringing down";
}

std::string IPCommands::quit(std::vector<std::string> args) {
    exit(0);
    return "";
}

std::string IPCommands::help(std::vector<std::string> args) {
    return REPL::help();
}

void IPCommands::register_commands() {
    using namespace std::placeholders;

    auto interfaces_func = std::bind(&IPCommands::interfaces, this, _1);
    register_command(interfaces_func, "interfaces", {}, "Print information about "
            "each interface, one per line. Optionally specify a destination file.");

    auto routes_func = std::bind(&IPCommands::routes, this, _1);
    register_command(routes_func, "routes", { "file" }, "Print information about the route "
            "to each known destination, one per line. Optionally specify a destination file.");

    auto send_func = std::bind(&IPCommands::send, this, _1);
    register_command(send_func, "send", { "ip", "proto", "string" },
            "Sends the string payload to the given ip address with the specified protocol.");

    auto up_func = std::bind(&IPCommands::up, this, _1);
    register_command(up_func, "up", { "interface-num" }, "Bring an interface 'up'.");

    auto down_func = std::bind(&IPCommands::down, this, _1);
    register_command(down_func, "down", { "interface-num" }, "Bring an interface 'down'.");

    auto quit_func = std::bind(&IPCommands::quit, this, _1);
    register_command(quit_func, "quit", {}, "Quit this node.");

    auto help_func = std::bind(&IPCommands::help, this, _1);
    register_command(help_func, "help", {}, "Show this help.");
}
