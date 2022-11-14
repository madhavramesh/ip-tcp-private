#include <string>
#include <vector>
#include <fstream>
#include <iomanip>

#include "include/IP/IPCommands.h"
#include "include/repl/colors.h"
#include "third_party/bonsai.h"

const int INTERFACE_COL_SIZE = 15;
const int ROUTE_COL_SIZE = 15;

const std::string interfacesParams = "<file>";
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

IPCommands::IPCommands(std::shared_ptr<IPNode> node) : node(node) {}

void IPCommands::interfaces(std::string& args) {
    std::vector<std::string> colNames = { "id", "state", "local", "remote", "port" };

    std::ostringstream interfaceString;
    for (auto& colName : colNames) {
        interfaceString << std::setw(INTERFACE_COL_SIZE) << colName << " ";
    }
    interfaceString << std::endl;

    auto interfaces = node->getInterfaces();
    for (auto& [interface, destAddr, destPort] : interfaces) {
        std::string upStr = interface.up ? "up" : "down";

        interfaceString << std::setw(INTERFACE_COL_SIZE) << interface.id << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << upStr << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << interface.srcAddr << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << destAddr << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << destPort << std::endl;
    }

    int spaceIdx = args.find(' ');
    std::string filename = args.substr(0, spaceIdx);
    if (filename.empty()) {
        std::cout << dim << interfaceString.str() << dim_reset;
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
        std::cout << dim << routeString.str() << dim_reset;
    } else {
        std::ofstream file(filename);

        file << routeString.str();
        file.close();
    }
}

void IPCommands::send(std::string& args) {
    std::vector<std::string> parsedArgs;
    int prevSpaceIdx = -1;
    int spaceIdx = -1;
    for (int i = 0; i < 2; i++) {
        prevSpaceIdx = spaceIdx + 1;
        spaceIdx = args.find(' ', prevSpaceIdx);

        if (prevSpaceIdx == std::string::npos) {
            std::cerr << red << "usage: " << "send " << sendParams << color_reset << std::endl;
            return;
        }
        parsedArgs.push_back(args.substr(prevSpaceIdx, spaceIdx - prevSpaceIdx));
    }
    std::string payload = args.substr(spaceIdx + 1);
    std::string addr = parsedArgs[0];

    // Check that protocol is a number
    for (char c : parsedArgs[1]) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "send " << sendParams << color_reset << std::endl;
            return;
        }
    }
    int protocol = stoi(parsedArgs[1]);

    // Just return if protocol is anything other than 0 (TestProtocol)
    if (protocol != 0) {
        return;
    }

    node->sendMsg(addr, "", payload, 0);
}

void IPCommands::up(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "down " << downParams << color_reset << std::endl;
        return;
    }

    int spaceIdx = args.find(' ');
    std::string interfaceStr = args.substr(0, spaceIdx);
    for (char c : interfaceStr) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "up "<< upParams << color_reset << std::endl;
            return;
        }
    }
    int interfaceNum = stoi(args.substr(0, spaceIdx));

    if (node->enableInterface(interfaceNum)) {
        std::cout << dim << "interface " << interfaceNum << " is now enabled" << dim_reset << std::endl;
    }
}

void IPCommands::down(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "down " << downParams << color_reset << std::endl;
        return;
    }

    int spaceIdx = args.find(' ');
    std::string interfaceStr = args.substr(0, spaceIdx);
    for (char c : interfaceStr) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "down " << downParams << color_reset << std::endl;
            return;
        }
    }
    int interfaceNum = stoi(args.substr(0, spaceIdx));

    if (node->disableInterface(interfaceNum)) {
        std::cout << dim << "interface " << interfaceNum << " is now disabled" << dim_reset << std::endl;
    }
}

void IPCommands::quit(std::string& args) {
    int argc = 2;
    char *argv[] = {"bonsai", "-l", NULL};
    // argv[1] = ;
    runBonsai(argc, argv);
    // execv("third_party/bonsai", argv);
    exit(0);
}

void IPCommands::help(std::string& args) {
    REPL::help();
}

void IPCommands::register_commands() {
    using namespace std::placeholders;

    auto interfaces_func = std::bind(&IPCommands::interfaces, this, _1);
    register_command(interfaces_func, "interfaces", interfacesParams, interfacesInfo);
    register_command(interfaces_func, "li", interfacesParams, interfacesInfo);
    
    auto routes_func = std::bind(&IPCommands::routes, this, _1);
    register_command(routes_func, "routes", routesParams, routesInfo);
    register_command(routes_func, "lr", routesParams, routesInfo);


    auto send_func = std::bind(&IPCommands::send, this, _1);
    register_command(send_func, "send", sendParams, sendInfo);

    auto up_func = std::bind(&IPCommands::up, this, _1);
    register_command(up_func, "up", upParams, upInfo);

    auto down_func = std::bind(&IPCommands::down, this, _1);
    register_command(down_func, "down", downParams, downInfo);

    auto quit_func = std::bind(&IPCommands::quit, this, _1);
    register_command(quit_func, "quit", "", quitInfo);
    register_command(quit_func, "q", "", quitInfo);

    auto help_func = std::bind(&IPCommands::help, this, _1);
    register_command(help_func, "help", "", helpInfo);
    register_command(help_func, "h", "", helpInfo);

}
