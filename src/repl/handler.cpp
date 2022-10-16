#include "include/repl/handler.h"

Handler::Handler() {}

void Handler::registerHandler(int protocol, ProtocolHandler func) {
    handlers[protocol] = func;
}

void Handler::callHandler(const boost::system::error_code& error, 
        size_t receivedBytes, boost::array<char, MAX_IP_PACKET_SIZE> buf) {
    ip *ipHeaderRaw = (ip *)(&buf[0]);

    std::unique_ptr<ip> ipHeader = std::make_unique<ip>();
    ipHeader->ip_hl = ntohs(ipHeaderRaw->ip_hl);
    ipHeader->ip_p = ntohs(ipHeaderRaw->ip_p);
    ipHeader->ip_len = ntohs(ipHeaderRaw->ip_len);
    ipHeader->ip_ttl = ntohs(ipHeaderRaw->ip_ttl);
    ipHeader->ip_sum = ntohs(ipHeaderRaw->ip_sum);
    ipHeader->ip_src.s_addr = ntohl(ipHeaderRaw->ip_src.s_addr);
    ipHeader->ip_dst.s_addr = ntohl(ipHeaderRaw->ip_dst.s_addr);

    std::string payload(buf.begin() + sizeof(ipHeader), buf.end());
    genericHandler(std::move(ipHeader), payload);
}

void Handler::genericHandler(std::unique_ptr<ip> ipHeader, std::string& payload) {
    if (handlers.count(ipHeader->ip_p)) {
        handlers.find(ipHeader->ip_p)->second(std::move(ipHeader), payload);
    }
    throw std::runtime_error("Handler for protocol " + std::to_string(ipHeader->ip_p) + " not found");
}
