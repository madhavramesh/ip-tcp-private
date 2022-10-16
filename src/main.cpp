#include <arpa/inet.h>
#include <iostream>
#include "../include/IP/IPCommands.h"

int main(int argc, char *argv[]) {
    IPCommands repl = IPCommands();
    repl.register_commands();

    std::string text;
    std::cout << "> ";
    while (std::getline(std::cin, text)) {
        std::cout << repl.eval(text) << std::endl;
        std::cout << "> ";
    }

    // if (argc != 2) {
        // std::cerr << "usage: ./node linksfile" << std::endl;
        // return -1;
    // }
//
    // char *filename = argv[1];
    // lnxinfo_t *root = parse_links(filename);
//
    // if (root == NULL) {
        // std::cerr << "Error: invalid links file" << std::endl;
        // return -1;
    // }
//
    // int local_phys_port          = root->local_phys_port;
    // std::string remote_phys_host = root->body->remote_phys_host;
    // uint16_t remote_phys_port    = root->body->remote_phys_port;
    // in_addr local_virt_ip        = root->body->local_virt_ip;
    // in_addr remote_virt_ip       = root->body->remote_virt_ip;
//
    // // #todo print pretty
    // // std::string *lv_ip, *rv_ip;
    // // if (inet_ntop(AF_INET, &local_virt_ip, lv_ip) <= 0 || inet_ntop)
//
    // lnxbody_t *curr, *next;
//
    // for (curr = root->body; curr != NULL; curr = next) {
        // next = curr->next;
        // std::cout << "local phys port "  << local_phys_port  << std::endl;
        // std::cout << "remote phys host " << remote_phys_host << std::endl;
        // std::cout << "remote phys port " << remote_phys_port << std::endl;
        // std::cout << "local virt ip s_addr "    << inet_ntop(AF_INET, local_virt_ip.s_addr) << std::endl;
        // std::cout << "remote virt ip s_addr "   << remote_virt_ip.s_addr << std::endl;
    // }
    //
    // free_links(root);
//
}
