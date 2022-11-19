#pragma once 

#include <string>
#include <cmath>

#include <unordered_map>
#include <deque>
#include <string>
#include <list>
#include <condition_variable>
#include <mutex>
#include <memory>
#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <unordered_map>
#include <tuple>
#include <chrono> 
#include <mutex>

#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <include/tools/hash.h>

using namespace boost::asio;

class TCPTuple {
    public:
        TCPTuple(std::string localAddr, uint16_t localPort, std::string remoteAddr, uint16_t remotePort) : 
            srcAddr(localAddr), 
            srcPort(localPort), 
            destAddr(remoteAddr), 
            destPort(remotePort) {}

        TCPTuple(const TCPTuple& other) : 
            srcAddr(other.getSrcAddr()), 
            srcPort(other.getSrcPort()), 
            destAddr(other.getDestAddr()), 
            destPort(other.getDestPort()) {}

        std::string getSrcAddr() const { return srcAddr; }
        uint16_t getSrcPort() const { return srcPort; }
        std::string getDestAddr() const { return destAddr; }
        uint16_t getDestPort() const { return destPort; }

        bool operator==(const TCPTuple& other) {
            return srcAddr == other.getSrcAddr() && srcPort == other.getSrcPort() && 
                destAddr == other.getDestAddr() && destPort == other.getDestPort();
        }
    private:
        std::string srcAddr;
        uint16_t srcPort;
        std::string destAddr;
        uint16_t destPort;
};


template<> struct std::hash<TCPTuple> {
    std::size_t operator()(TCPTuple const& t) const noexcept {
        uint32_t srcAddr = ip::address_v4::from_string(t.getSrcAddr()).to_ulong();
        uint32_t destAddr = ip::address_v4::from_string(t.getDestAddr()).to_ulong();
        auto hash1 = pair_int_hash(srcAddr, uint32_t(t.getSrcPort()));
        auto hash2 = pair_int_hash(destAddr, uint32_t(t.getDestPort()));
        return pair_int_hash(hash1, hash2);
    }
};
