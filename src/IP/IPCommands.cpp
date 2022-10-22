#include "../../include/IP/IPCommands.h"

#include <string>
#include <vector>

const int ROUTE_COL_SIZE = 15;

const std::vector<std::string> routesParams = "<file>";
const std::vector<std::string> sendParams = "<ip> <proto> <string>";
const std::vector<std::string> upParams = "<interface-num>";
const std::vector<std::string> downParams = "<interface-num>";

const std::string interfacesInfo = 
    "Print information about each interface, one per line. "
    "Optionally specify a destination file";
const std::string routesInfo = 
    "Print information about the route to each know destination, "
    "one per line. Optionally specify a destination file.";
const std::string sendInfo = 
    "Sends the string payload to the given ip address with the"
    "specified protocol.";
const std::string upInfo = "Bring an interface 'up'.";
const std::string downInfo = "Bring an interface 'down'.";
const std::string quitInfo = "Quit this node.";
const std::string helpInfo = "Show this help.";

IPCommands::IPCommands(std::shared_ptr<Node> node) : node(node) {}

void IPCommands::interfaces(std::string& args) {

    return "interfaces";
}

void IPCommands::routes(std::string& args) {
    std::vector<std::string> colNames = { "dest", "next", "cost" };

    std::string routeString;
    for (auto& colName : colNames) {
        routeString.insert(routeString.end(), ROUTE_COL_SIZE - colName.size(), ' ');
        routeString += colName;
    }
    routeString += "\n";

    auto routes = node->getRoutes();
    for (auto& [srcName, destInfo] : routes) {
        auto& [destName, cost] = destInfo;
        std::string costStr = std::to_string(cost);

        routeString.insert(routeString.end(), ROUTE_COL_SIZE - srcName.size(), ' ');
        routeString += srcName;

        routeString.insert(routeString.end(), ROUTE_COL_SIZE - destName.size(), ' ');
        routeString += destName;

        routeString.insert(routeString.end(), ROUTE_COL_SIZE - costStr.size(), ' ');
        routeString += costStr;

        routeString += "\n";
    }
    routeString.pop_back();

    int spaceIdx = args.find(' ');
    std::string filename = args.substr(0, spaceIdx);
    if (filename.empty()) {
        std::cout << routeString << std::endl;
    } else {
        std::ofstream(filename);

        ofstream << routeString << std::endl;
        ofstream.close();
    }
    return routeString;
}

void IPCommands::send(std::string& args) {
    if (args.size() != )
    return "Sending";
}

void IPCommands::up(std::string& args) {
    return "Bringing up";
}

void IPCommands::down(std::string& args) {
    return "Bringing down";
}

void IPCommands::quit(std::string& args) {
    exit(0);
    return "";
}

void IPCommands::help(std::string& args) {
    return REPL::help();
}

void IPCommands::register_commands() {
    using namespace std::placeholders;

    auto interfaces_func = std::bind(&IPCommands::interfaces, this, _1);
    register_command(interfaces_func, "interfaces", "", interfacesInfo);

    auto routes_func = std::bind(&IPCommands::routes, this, _1);
    register_command(routes_func, "routes", routesParams, routesInfo);

    auto send_func = std::bind(&IPCommands::send, this, _1);
    register_command(send_func, "send", sendParams, sendInfo);

    auto up_func = std::bind(&IPCommands::up, this, _1);
    register_command(up_func, "up", upParams, upInfo);

    auto down_func = std::bind(&IPCommands::down, this, _1);
    register_command(down_func, "down", downParams, downInfo);

    auto quit_func = std::bind(&IPCommands::quit, this, _1);
    register_command(quit_func, "quit", "", quitInfo);

    auto help_func = std::bind(&IPCommands::help, this, _1);
    register_command(help_func, "help", "", helpInfo);
}
