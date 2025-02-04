#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <fstream>
#include <iomanip>
#include <thread>

// #include "third_party/bonsai.h"

#include "include/tools/REPL.h"
#include "include/tools/colors.h"
#include "include/TCP/TCPNode.h"
#include "include/TCP/TCPCommands.h"
#include "include/TCP/TCPSocket.h"

const int INTERFACE_COL_SIZE = 15;
const int ROUTE_COL_SIZE = 15;

// param info
const std::string lsParams          = "";
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
const std::string lsInfo            = "Prints out the socket information";
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
    // // Topmost column names
    std::vector<std::string> colNames = { "socket", "local-addr", "local-port", "dest-addr", "dest-port", "status"};

    // // Print out top row
    std::ostringstream interfaceString;
    for (auto& colName : colNames) {
        interfaceString << std::setw(INTERFACE_COL_SIZE) << colName;
    }
    interfaceString << std::endl;

    // // Print out divider
    for (int i = 0; i < colNames.size(); i++) {
        interfaceString << std::setw(INTERFACE_COL_SIZE) << "----------";
    }
    interfaceString << std::endl;

    // For each socket, print out the socket information
    auto sockInfo = tcpNode->getSockets();

    for (auto& [id, socketTuple, state] : sockInfo) {
        // TCPTuple socketTuple = socket->toTuple();
        // std::string state = TCPSocket::toString(socket->getState());

        interfaceString << std::setw(INTERFACE_COL_SIZE) << id;
        interfaceString << std::setw(INTERFACE_COL_SIZE) << socketTuple.getSrcAddr();
        interfaceString << std::setw(INTERFACE_COL_SIZE) << socketTuple.getSrcPort();
        interfaceString << std::setw(INTERFACE_COL_SIZE) << socketTuple.getDestAddr();
        interfaceString << std::setw(INTERFACE_COL_SIZE) << socketTuple.getDestPort();
        interfaceString << std::setw(INTERFACE_COL_SIZE) << state;
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

void TCPCommands::accept_loop(int sockClient, int sockListener, std::string address) {
    while ((sockClient = tcpNode->accept(sockListener, address)) >= 0) {
        std::cout << dim << "accept on socket " << sockListener << " returned " << sockClient 
            << color_reset << std::endl;
    }
}

// Accepts a connection on the given port
void TCPCommands::accept(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "accept " << acceptParams << color_reset << std::endl;
        return;
    }

    // Parse the port
    int spaceIdx = args.find(' ');
    int port = stoi(args.substr(0, spaceIdx));

    // Listen and accept.
    // Note, hard coded "127.0.0.1"
    // #todo put accept into while loop and/or makenot blocking
    std::string default_addr = "127.0.0.1";
    int sockListener = tcpNode->listen(default_addr, port);

    if (sockListener < 0) {
        std::cerr << "error: cannot bind to port " << port << std::endl;
        return;
    }

    std::string address = "";
    int sockClient; 
    
    // maybe use boost::ref() on address
    std::thread accept_thread = std::thread(&TCPCommands::accept_loop, this, std::cref(sockClient), 
                                            std::cref(sockListener), std::cref(address));
    accept_thread.detach();
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

    // Check that port is a number
    for (char c : parsedArgs[1]) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "connect " << connectParams << color_reset << std::endl;
            return;
        }
    }
    uint16_t port = std::stoi(parsedArgs[1]);

    // Connect
    // TODO: implement specific failures e.g. ENOMEM EADDRINUSE EADDRNOTAVAIL
    int sock = tcpNode->connect(ip, port);
    if (sock < 0) {
        std::cerr << red << "Failed to connect to " << ip << ":" << port << color_reset << std::endl;
    }
    std::cout << dim << "connect returned " << sock << color_reset << std::endl;
}

// Sends data to the given socket
void TCPCommands::send(std::string& args) {
    std::vector<std::string> parsedArgs;
    // Parse the socket id and payload
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

    // Confirm that socket id is a digit
    for (char c : parsedArgs[0]) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "send " << sendParams << color_reset << std::endl;
            return;
        }
    }

    int socketId = stoi(parsedArgs[0]);
    std::string payload = args.substr(spaceIdx + 1);
    // std::cout << "your payload would be " << payload << std::endl;

    int numSent = tcpNode->write(socketId, payload, payload.size());
    if (numSent < 0) {
        return;
    }

    std::cout << dim << "write on " << payload.size() << " bytes returned "
        << numSent << color_reset << std::endl;
}

void TCPCommands::recv(std::string& args) {
    std::vector<std::string> parsedArgs;
    // Parse the socket id, number of bytes to read, and whether to block
    int prevSpaceIdx = -1;
    int spaceIdx = -1;
    for (int i = 0; i < 2; i++) {
        prevSpaceIdx = spaceIdx + 1;
        spaceIdx = args.find(' ', prevSpaceIdx);

        if (prevSpaceIdx == std::string::npos) {
            std::cerr << red << "usage: " << "recv " << recvParams << color_reset << std::endl;
        }
        parsedArgs.push_back(args.substr(prevSpaceIdx, spaceIdx - prevSpaceIdx));
    }

    // Confirm that socket id is a digit
    for (char c : parsedArgs[0]) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "recv " << recvParams << color_reset << std::endl;
            return;
        }
    }
    int socketId = stoi(parsedArgs[0]);

    // Confirm that number of bytes to read is a digit
    for (char c : parsedArgs[1]) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "recv " << recvParams << color_reset << std::endl;
            return;
        }
    }
    int bytesToRead = stoi(parsedArgs[1]);

    bool blocking = false;
    if (spaceIdx != std::string::npos) {
        prevSpaceIdx = spaceIdx + 1;
        spaceIdx = args.find(' ', prevSpaceIdx);
        std::string blockingStr = args.substr(prevSpaceIdx, spaceIdx);
        
        if (blockingStr != "y" && blockingStr != "n") {
            std::cerr << red << "syntax error: loop option must be 'y' or 'n'"
                << color_reset << std::endl;
            return;
        } else {
            blocking = blockingStr == "y" ? true : false;
        }
    }

    std::string buf;
    int bytesRead = tcpNode->read(socketId, buf, bytesToRead, blocking);

    if (bytesRead >= 0) {
        std::cout << dim << "read on " << bytesToRead << " bytes returned " << bytesRead 
        << "; contents of buffer: '" << buf << "'" << color_reset << std::endl;
    }
}

std::vector<std::string> TCPCommands::splitString(std::string& str, std::string delimiter)
{
    std::vector<std::string> ret;
    int start = 0;
    int end = str.find(delimiter);
    while (end != -1) {
        ret.push_back(str.substr(start, end - start));
        start = end + delimiter.size();
        end = str.find(delimiter, start);
    }
    ret.push_back(str.substr(start, end - start));
    return ret;
}

void TCPCommands::shutdown(std::string& args) {
    std::vector<std::string> parsedArgs = splitString(args, " ");

    // Confirm that socket id is a digit
    for (char c : parsedArgs[0]) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "close " << closeParams << color_reset << std::endl;
            return;
        }
    }

    int socketId = stoi(parsedArgs[0]);
    ShutdownType type = WRITE; // perhaps make these enums

    if (parsedArgs.size() == 2) {
        std::string shutdownStr = parsedArgs[1];
        if (shutdownStr == "read") {
            type = READ;
        } else if (shutdownStr == "write") {
            type = WRITE;
        } else if (shutdownStr == "both") {
            type = BOTH;
        } else {
            std::cerr << red << "syntax error: type must be 'read', 'write', or 'both'"
                << color_reset << std::endl;
        return;
        }
    }   
    tcpNode->shutdown(socketId, type);
}

void TCPCommands::close(std::string& args) {
    std::vector<std::string> parsedArgs;
    int prevSpaceIdx = -1;
    int spaceIdx = -1;
    for (int i = 0; i < 2; i++) {
        prevSpaceIdx = spaceIdx + 1;
        spaceIdx = args.find(' ', prevSpaceIdx);

        if (prevSpaceIdx == std::string::npos) {
            std::cerr << red << "usage: " << "close " << closeParams << color_reset << std::endl;
        }
        parsedArgs.push_back(args.substr(prevSpaceIdx, spaceIdx - prevSpaceIdx));
    }

    // Confirm that socket id is a digit
    for (char c : parsedArgs[0]) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "close " << closeParams << color_reset << std::endl;
            return;
        }
    }

    int socketId = stoi(parsedArgs[0]);

    tcpNode->close(socketId);
}

void TCPCommands::sendfile(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "sendfile " << sendfileParams << color_reset << std::endl;
        return;
    }
    std::vector<std::string> parsedArgs;
    // Parse the filename, destination string, and destination port
    int prevSpaceIdx = -1;
    int spaceIdx = -1;
    for (int i = 0; i < 3; i++) {
        prevSpaceIdx = spaceIdx + 1;
        spaceIdx = args.find(' ', prevSpaceIdx);

        if (prevSpaceIdx == std::string::npos) {
            std::cerr << red << "usage: " << "sf " << sendfileParams << color_reset << std::endl;
        }
        parsedArgs.push_back(args.substr(prevSpaceIdx, spaceIdx - prevSpaceIdx));
    }

    // Confirm that socket id is a digit
    for (char c : parsedArgs[2]) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "sf " << sendfileParams << color_reset << std::endl;
            return;
        }
    };
    tcpNode->sf(parsedArgs[0], parsedArgs[1], stoi(parsedArgs[2]));
}

void TCPCommands::recvfile(std::string& args) {
    if (args.empty()) {
        std::cerr << red << "usage: " << "recvfile " << recvfileParams << color_reset << std::endl;
        return;
    }
    std::vector<std::string> parsedArgs;
    // Parse the filename and listener port
    int prevSpaceIdx = -1;
    int spaceIdx = -1;
    for (int i = 0; i < 2; i++) {
        prevSpaceIdx = spaceIdx + 1;
        spaceIdx = args.find(' ', prevSpaceIdx);

        if (prevSpaceIdx == std::string::npos) {
            std::cerr << red << "usage: " << "rf " << recvfileParams << color_reset << std::endl;
        }
        parsedArgs.push_back(args.substr(prevSpaceIdx, spaceIdx - prevSpaceIdx));
    }

    // Confirm that socket id is a digit
    for (char c : parsedArgs[1]) {
        if (!isdigit(c)) {
            std::cerr << red << "usage: " << "rf " << recvfileParams << color_reset << std::endl;
            return;
        }
    };
    tcpNode->rf(parsedArgs[0], stoi(parsedArgs[1]));
}

// bonsai
void TCPCommands::quit(std::string& args) {
    // int argc = 2;
    // char *argv[] = {"bonsai", "-l", NULL};
    // runBonsai(argc, argv);
    exit(0);
}

void TCPCommands::register_commands() {
    using namespace std::placeholders;

    // Register commands

    auto socket_func = std::bind(&TCPCommands::sockets, this, _1);
    register_command(socket_func, "ls", lsParams, lsInfo);

    auto accept_func = std::bind(&TCPCommands::accept, this, _1);
    register_command(accept_func, "a", acceptParams, acceptInfo);

    auto connect_func = std::bind(&TCPCommands::connect, this, _1);
    register_command(connect_func, "c", connectParams, connectInfo);

    auto send_func = std::bind(&TCPCommands::send, this, _1);
    register_command(send_func, "s", sendParams, sendInfo);

    auto recv_func = std::bind(&TCPCommands::recv, this, _1);
    register_command(recv_func, "r", recvParams, recvInfo);

    auto shutdown_func = std::bind(&TCPCommands::shutdown, this, _1);
    register_command(shutdown_func, "sd", shutdownParams, shutdownInfo);

    auto close_func = std::bind(&TCPCommands::close, this, _1);
    register_command(close_func, "cl", closeParams, closeInfo);

    auto sendfile_func = std::bind(&TCPCommands::sendfile, this, _1);
    register_command(sendfile_func, "sf", sendfileParams, sendfileInfo);

    auto recvfile_func = std::bind(&TCPCommands::recvfile, this, _1);
    register_command(recvfile_func, "rf", recvfileParams, recvfileInfo);

    auto quit_func = std::bind(&TCPCommands::quit, this, _1);
    register_command(quit_func, "q", quitParams, quitInfo);
}
