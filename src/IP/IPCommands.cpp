#include "../../include/IP/IPCommands.h"

#include <string>
#include <vector>
#include <fstream>
#include <iomanip>

const int INTERFACE_COL_SIZE = 15;
const int ROUTE_COL_SIZE = 15;

const std::string routesParams = "<file>";
const std::string sendParams = "<ip> <proto> <string>";
const std::string upParams = "<interface-num>";
const std::string downParams = "<interface-num>";

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
    std::vector<std::string> colNames = { "id", "state", "local", "remote", "port" };

    std::ostringstream interfaceString;
    for (auto& colName : colNames) {
        interfaceString << std::setw(INTERFACE_COL_SIZE) << colName << " ";
    }
    interfaceString << std::endl;

    auto interfaces = node->getInterfaces();
    for (auto& interface : interfaces) {
        std::string upStr = interface.up ? "up" : "down";

        interfaceString << std::setw(INTERFACE_COL_SIZE) << interface.id << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << upStr << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << interface.srcAddr << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << interface.destAddr << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << interface.destPort << std::endl;
    }

    int spaceIdx = args.find(' ');
    std::string filename = args.substr(0, spaceIdx);
    if (filename.empty()) {
        std::cout << interfaceString.str();
    } else {
        std::ofstream file(filename);

        file << interfaceString.str();
        file.close();
    }
}

void IPCommands::routes(std::string& args) {
    std::vector<std::string> colNames = { "dest", "next", "cost" };

    std::ostringstream routeString;
    for (auto& colName : colNames) {
        routeString << std::setw(ROUTE_COL_SIZE) << colName << " ";
    }
    routeString << std::endl;

    auto routes = node->getRoutes();
    for (auto& [srcAddr, destAddr, cost] : routes) {
        routeString << std::setw(ROUTE_COL_SIZE) << srcAddr << " ";
        routeString << std::setw(ROUTE_COL_SIZE) << destAddr << " ";
        routeString << std::setw(ROUTE_COL_SIZE) << cost << std::endl;;
    }

    int spaceIdx = args.find(' ');
    std::string filename = args.substr(0, spaceIdx);
    if (filename.empty()) {
        std::cout << routeString.str();
    } else {
        std::ofstream file(filename);

        file << routeString.str();
        file.close();
    }
}

void IPCommands::send(std::string& args) {
    // if (args.size() != )
    // std::string address = args[1];
    // int protocol = std::stoi(args[2]);
    // std::string payload = args[3];
    // std::cout << "calling IPCommand send with args " << address << " " << protocol << " " << payload << std::endl;
//
    // node->send(address, protocol, payload);
    std::cout << "Sending" << std::endl;
}

void IPCommands::up(std::string& args) {
    int spaceIdx = args.find(' ');
    int interfaceNum = stoi(args.substr(0, spaceIdx));

    if (node->enableInterface(interfaceNum)) {
        std::cout << "interface " << interfaceNum << " is now enabled" << std::endl;
    }
}

void IPCommands::down(std::string& args) {
    int spaceIdx = args.find(' ');
    int interfaceNum = stoi(args.substr(0, spaceIdx));

    if (node->disableInterface(interfaceNum)) {
        std::cout << "interface " << interfaceNum << " is now disabled" << std::endl;
    }
}

void IPCommands::quit(std::string& args) {
    exit(0);
}

void IPCommands::help(std::string& args) {
    REPL::help();
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
