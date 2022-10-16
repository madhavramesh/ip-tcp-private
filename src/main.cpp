#include <arpa/inet.h>
#include <iostream>
#include "utils/parselinks.h"

#include <boost/asio.hpp>

using namespace boost::asio;

int main(int argc, char *argv[]) {

    if (argc != 2) {
        std::cerr << "usage: ./node linksfile" << std::endl;
        return -1;
    }

    char *filename = argv[1];
    lnxinfo_t *root = parse_links(filename);

    if (root == NULL) {
        std::cerr << "Error: invalid links file" << std::endl;
        return -1;
    }

    int local_phys_port          = root->local_phys_port;

    // #todo print pretty
    // std::string *lv_ip, *rv_ip;
    // if (inet_ntop(AF_INET, &local_virt_ip, lv_ip) <= 0 || inet_ntop)

    std::cout << "local phys port "  << local_phys_port  << std::endl;

    lnxbody_t *curr, *next;

    for (curr = root->body; curr != NULL; curr = next) {
        next = curr->next;

        std::string remote_phys_host = curr->remote_phys_host;
        uint16_t remote_phys_port    = curr->remote_phys_port;
        uint32_t local_virt_ip       = ntohl(curr->local_virt_ip.s_addr);
        uint32_t remote_virt_ip      = ntohl(curr->remote_virt_ip.s_addr);

        ip::address_v4 lv_ip = ip::make_address_v4(local_virt_ip);
        ip::address_v4 rv_ip = ip::make_address_v4(remote_virt_ip);


        std::cout << "-----------------" << std::endl;  
        std::cout << "remote phys host " << remote_phys_host << std::endl;
        std::cout << "remote phys port " << remote_phys_port << std::endl;
        std::cout << "local virt ip s_addr "    << lv_ip << std::endl;
        std::cout << "remote virt ip s_addr "   << rv_ip << std::endl;
    }
    std::cout << "-----------------" << std::endl;
    
    free_links(root);

}