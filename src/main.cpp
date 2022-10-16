#include "include/IP/IPCommands.h"
#include "utils/parselinks.h"
#include "include/IP/Node.h"
#include "include/Link/UDPLink.h"

#include <arpa/inet.h>
#include <iostream>

#include <boost/asio.hpp>

using namespace boost::asio;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "usage: ./node <linksfile>" << std::endl;
        return -1;
    }

    char *filename = argv[1];
    lnxinfo_t *root = parse_links(filename);

    if (root == NULL) {
        std::cerr << "error: invalid links file" << std::endl;
        return -1;
    }

    // This is the port our UDP socket should bind to
    int local_phys_port = root->local_phys_port;

    // #TODO call node constructor
    Node myNode = Node(local_phys_port);

    // #TODO create new thread for listening


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
        myNode.addInterface(remote_phys_port, lv_ip.to_string(), rv_ip.to_string());

        id++;
    }

    // testing .


    // testing ^

    IPCommands repl = IPCommands();
    repl.register_commands();
    
    std::string text;
    std::cout << "> ";
    while (std::getline(std::cin, text)) {
        std::cout << repl.eval(text) << std::endl;
        std::cout << "> ";
    }

    // Clean up
    free_links(root);
}
