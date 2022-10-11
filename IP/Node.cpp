#include <iostream>
#include "utils/parselinks.h"

int main(int argc, char *argv[]) {
    std::cout << "main" << std::endl;

    if (argc != 3) {
        std::cerr << "Error: input must be of format ./node <linksfile>" << std::endl;
        return -1;
    }

    char *filename = argv[2];
    lnxinfo_t *res = parse_links(filename);

    if (res == NULL) {
        std::cerr << "Error: invalid links file" << std::endl;
    }

    std::cout << res->body->local_virt_ip.s_addr << std::endl;

}