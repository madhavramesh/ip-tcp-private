#include <arpa/inet.h>

#include <iostream>
#include <boost/asio.hpp>

#include "utils/parselinks.h"

#include "include/TCP/TCPCommands.h"
#include "include/TCP/TCPNode.h"
#include "include/tools/colors.h"

using namespace boost::asio;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << red << "usage: ./node <linksfile>" << color_reset << std::endl;
        return -1;
    }

    char *filename = argv[1];
    lnxinfo_t *root = parse_links(filename);

    if (root == NULL) {
        std::cerr << "error: invalid links file" << std::endl;
        return -1;
    }

    // This is the port our UDP socket should bind to
    unsigned int local_phys_port = root->local_phys_port;

    // Create node
    std::shared_ptr<TCPNode> node = std::make_shared<TCPNode>(local_phys_port);

    // Loop through each interface
    lnxbody_t *curr, *next;
    int id = 0;
    for (curr = root->body; curr != NULL; curr = next) {
        next = curr->next;

        // Extracting data from the utilities parser
        std::string remote_phys_host = curr->remote_phys_host;
        uint16_t remote_phys_port    = curr->remote_phys_port;
        uint32_t local_virt_ip       = ntohl(curr->local_virt_ip.s_addr);
        uint32_t remote_virt_ip      = ntohl(curr->remote_virt_ip.s_addr);

        ip::address_v4 lv_ip = ip::make_address_v4(local_virt_ip);
        ip::address_v4 rv_ip = ip::make_address_v4(remote_virt_ip);
        
        // Print out the local virtual ip and its ID
        std::cout << id << ": " << lv_ip << std::endl;

        // Add interface
        node->ipNode->addInterface(id, lv_ip.to_string(), rv_ip.to_string(), remote_phys_port);
        id++;
    }

    // ------------------------------------------------------------------------- 
    // Start RIP thread in IP node

    auto ripFunc = std::bind(&IPNode::RIP, node->ipNode);
    std::thread(ripFunc).detach();

    // -------------------------------------------------------------------------
    // Start listening thread on IP node

    auto receiveFunc = std::bind(&IPNode::receive, node->ipNode);
    std::thread(receiveFunc).detach();

    // -------------------------------------------------------------------------
    // Start retransmit thread on TCP node

    auto retransmitFunc = std::bind(&TCPNode::retransmitPackets, node);
    std::thread(retransmitFunc).detach();

    // ------------------------------------------------------------------------- 

    // Set up REPL
    TCPCommands repl = TCPCommands(std::shared_ptr<TCPNode>(node));
    repl.register_commands();

    std::string text;
    std::cout << "> ";
    while (std::getline(std::cin, text)) {
        try {
            std::cout << "Attempt: " << text.size() << std::endl;
            repl.eval(text);
        } catch (std::exception& e) {
            std::cerr << red << "exception: " << e.what() << color_reset << std::endl;
        }
        std::cout << "> ";
    }

    // ------------------------------------------------------------------------- 

    // Clean up
    free_links(root);
}
