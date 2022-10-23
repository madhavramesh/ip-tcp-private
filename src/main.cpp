#include <arpa/inet.h>

#include <iostream>
#include <boost/asio.hpp>

#include "utils/parselinks.h"

#include "include/IP/IPCommands.h"
#include "include/IP/Node.h"
#include "include/repl/colors.h"

using namespace boost::asio;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << red << "usage: ./node <linksfile>" << reset << std::endl;
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
    std::shared_ptr<Node> node = std::make_shared<Node>(local_phys_port);

    // Loop through each interface
    lnxbody_t *curr, *next;
    int posId = 0;
    int negId = -1;

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
        std::cout << posId << ": " << lv_ip << std::endl;

        // Add interface
        node->addInterface(posId, lv_ip.to_string(), rv_ip.to_string(), remote_phys_port, 1);
        node->addInterface(negId, lv_ip.to_string(), lv_ip.to_string(), local_phys_port, 0);

        posId++;
        negId--;
    }

    // ------------------------------------------------------------------------- 
    // Start RIP thread

    auto ripFunc = std::bind(&Node::RIP, node);
    std::thread(ripFunc).detach();

    // -------------------------------------------------------------------------

    // Start listening thread on node
    auto receiveFunc = std::bind(&Node::receive, node);
    std::thread(receiveFunc).detach();

    // ------------------------------------------------------------------------- 

    // Set up REPL
    IPCommands repl = IPCommands(node);
    repl.register_commands();
    
    // Start listening thread on node
    auto receiveFunc = std::bind(&Node::receive, node);
    std::thread(receiveFunc).detach();

    std::string text;
    std::cout << "> ";
    while (std::getline(std::cin, text)) {
        try {
            repl.eval(text);
        } catch (std::exception& e) {
            std::cerr << red << "exception: " << e.what() << reset << std::endl;
        }
        std::cout << "> ";
    }

<<<<<<< HEAD
=======
    // ------------------------------------------------------------------------- 

>>>>>>> e90bc37752d194afc9fda0ad3fe7e1c2ea7cbe51
    // Clean up
    free_links(root);
}
