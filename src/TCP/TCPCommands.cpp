#include "include/repl/REPL.h"
#include "include/TCP/TCPNode.h"
#include "include/TCP/TCPCommands.h"
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <fstream>
#include <iomanip>

#include "include/repl/colors.h"
#include "third_party/bonsai.h"

const int INTERFACE_COL_SIZE = 15;
const int ROUTE_COL_SIZE = 15;

// param info
const std::string socketParams      = "";
const std::string acceptParams      = "<port>";
const std::string connectParams     = "<ip> <port>";
const std::string sendParams        = "<socket ID> <data>";
const std::string recvParams        = "<socket ID> <numbytes> <y|N>";
const std::string shutdownParams    = "<socket id> <read|write|both>";
const std::string closeParams       = "<socket id>";
const std::string sendfileParams    = "<filename> <ip> <port>";
const std::string recvfileParams    = "<filename> <port>";
const std::string quitParams        = "";

// command info
const std::string socketInfo        = "Prints out the socket information";
const std::string acceptInfo        = "Accepts a connection on the given port";
const std::string connectInfo       = "Connects to the given ip and port";
const std::string sendInfo          = "Sends data to the given socket";
const std::string recvInfo          = "Receives data from the given socket";
const std::string shutdownInfo      = "Shuts down the given socket";
const std::string closeInfo         = "Closes the given socket";
const std::string sendfileInfo      = "Sends a file to the given ip and port";
const std::string recvfileInfo      = "Receives a file from the given port";
const std::string quitInfo          = "Quits the program";

// Constructor
TCPCommands::TCPCommands(std::shared_ptr<TCPNode> node) : tcpNode(node), IPCommands(node->ipNode) {
    this->tcpNode = node;
}

// Prints out the socket information
void TCPCommands::sockets(std::string& args) {
    // Topmost column names
    std::vector<std::string> colNames = { "socket", "local-addr", "port", "dst-addr", "port", "status"};

    // Print out top row
    std::ostringstream interfaceString;
    for (auto& colName : colNames) {
        interfaceString << std::setw(INTERFACE_COL_SIZE) << colName << " ";
    }
    interfaceString << std::endl;

    // Print out divider
    for (int i = 0; i < colNames.size(); i++) {
        interfaceString << std::setw(INTERFACE_COL_SIZE) << "----------";
    }
    interfaceString << std::endl;

    // For each socket, print out the socket information
    std::vector<std::tuple<int, ClientSocket>> clientSockets = tcpNode->getClientSockets();
    std::vector<std::tuple<int, ListenSocket>> listenSockets = tcpNode->getListenSockets();

    for (auto listenSocket : listenSockets) {
        interfaceString << std::setw(INTERFACE_COL_SIZE) << std::get<0>(listenSocket) << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << std::get<1>(listenSocket).srcAddr << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << std::get<1>(listenSocket).srcPort << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << "0.0.0.0" << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << "0" << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << "LISTEN" << " ";
        interfaceString << std::endl;
    }

    for (auto clientSocket : clientSockets) {
        int socketID = std::get<0>(clientSocket);
        ClientSocket socket = std::get<1>(clientSocket);

        interfaceString << std::setw(INTERFACE_COL_SIZE) << socketID << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << socket.srcAddr << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << socket.srcPort << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << socket.destAddr << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << socket.destPort << " ";
        interfaceString << std::setw(INTERFACE_COL_SIZE) << SocketStateString[socket.state] << " ";
        interfaceString << std::endl;
    }

    // Print to file if specified
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


// Accepts a connection on the given port
void TCPCommands::accept(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "accept " << acceptParams << color_reset << std::endl;
        return;
    }

    // Parse the port
    int port = std::stoi(args);

    // Listen and accept.
    // Note, hard coded "127.0.0.1"
    // #todo put accept into while loop and/or makenot blocking
    std::string default_addr = "127.0.0.1";
    int sockListener = tcpNode->listen(default_addr, port);
    std::string address = "";
    int sockClient; 
    
    while ((sockClient = tcpNode->accept(sockListener, address)) > 0) {
        std::cout << "Accepted connection from " << address << std::endl;
    }
}

// Connects to the given ip and port
void TCPCommands::connect(std::string& args) {
    std::vector<std::string> parsedArgs;
    // Parse the ip and port
    int prevSpaceIdx = -1;
    int spaceIdx = -1;
    for (int i = 0; i < 2; i++) {
        prevSpaceIdx = spaceIdx + 1;
        spaceIdx = args.find(' ', prevSpaceIdx);

        if (prevSpaceIdx == std::string::npos) {
            std::cerr << red << "usage: " << "connect " << connectParams << color_reset << std::endl;
        }
        parsedArgs.push_back(args.substr(prevSpaceIdx, spaceIdx - prevSpaceIdx));
    }

    std::string ip = parsedArgs[0];
    std::string port = parsedArgs[1];

    // Connect
    // #todo implement failures e.g. ENOMEM EADDRINUSE EADDRNOTAVAIL
    int sock = tcpNode->connect(ip, std::stoi(port));
    if (sock < 0) {
        std::cerr << red << "Failed to connect to " << ip << ":" << port << color_reset << std::endl;
    }
    std::cout << "Connected to " << ip << ":" << port << std::endl;
}

// Sends data to the given socket
void TCPCommands::send(std::string& args) {
    std::vector<std::string> parsedArgs;
    // Parse the ip and port
    int prevSpaceIdx = -1;
    int spaceIdx = -1;
    for (int i = 0; i < 1; i++) {
        prevSpaceIdx = spaceIdx + 1;
        spaceIdx = args.find(' ', prevSpaceIdx);

        if (prevSpaceIdx == std::string::npos) {
            std::cerr << red << "usage: " << "send " << connectParams << color_reset << std::endl;
        }
        parsedArgs.push_back(args.substr(prevSpaceIdx, spaceIdx - prevSpaceIdx));
    }

    std::string sockID = parsedArgs[0];
    std::string payload = args.substr(spaceIdx + 1);
    std::cout << "your payload would be " << payload << std::endl;
}

void TCPCommands::recv(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "recv " << recvParams << color_reset << std::endl;
        return;
    }
}

void TCPCommands::shutdown(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "shutdown " << shutdownParams << color_reset << std::endl;
        return;
    }
}

void TCPCommands::close(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "close " << closeParams << color_reset << std::endl;
        return;
    }
}

void TCPCommands::sendfile(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "sendfile " << sendfileParams << color_reset << std::endl;
        return;
    }
}

void TCPCommands::recvfile(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "recvfile " << recvfileParams << color_reset << std::endl;
        return;
    }
}

// bonsai
void TCPCommands::quit(std::string& args) {
     int argc = 2;
    char *argv[] = {"bonsai", "-l", NULL};
    // argv[1] = ;
    runBonsai(argc, argv);
    // execv("third_party/bonsai", argv);
    exit(0);
}

void TCPCommands::register_commands() {
    using namespace std::placeholders;

    // Register commands

    auto socket_func = std::bind(&TCPCommands::sockets, this, _1);
    register_command(socket_func, "socket", socketParams, socketInfo);

    auto accept_func = std::bind(&TCPCommands::accept, this, _1);
    register_command(accept_func, "accept", acceptParams, acceptInfo);

    auto connect_func = std::bind(&TCPCommands::connect, this, _1);
    register_command(connect_func, "connect", connectParams, connectInfo);

    auto send_func = std::bind(&TCPCommands::send, this, _1);
    register_command(send_func, "send", sendParams, sendInfo);

    auto recv_func = std::bind(&TCPCommands::recv, this, _1);
    register_command(recv_func, "recv", recvParams, recvInfo);

    auto shutdown_func = std::bind(&TCPCommands::shutdown, this, _1);
    register_command(shutdown_func, "shutdown", shutdownParams, shutdownInfo);

    auto close_func = std::bind(&TCPCommands::close, this, _1);
    register_command(close_func, "close", closeParams, closeInfo);

    auto sendfile_func = std::bind(&TCPCommands::sendfile, this, _1);
    register_command(sendfile_func, "sendfile", sendfileParams, sendfileInfo);

    auto recvfile_func = std::bind(&TCPCommands::recvfile, this, _1);
    register_command(recvfile_func, "recvfile", recvfileParams, recvfileInfo);

    auto quit_func = std::bind(&TCPCommands::quit, this, _1);
    register_command(quit_func, "quit", quitParams, quitInfo);
}
