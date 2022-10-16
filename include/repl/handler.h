#pragma once

#include <boost/asio.hpp>
#include <boost/array.hpp>

#include <functional>
#include <string>
#include <unordered_map>
#include <netinet/ip.h>

const int MAX_IP_PACKET_SIZE = 1400;

typedef std::function<void(std::unique_ptr<ip>, std::string&)> ProtocolHandler;

class Handler {
    public:
        Handler();

        void registerHandler(int protocol, ProtocolHandler func);
        void callHandler(const boost::system::error_code& error, 
                size_t receivedBytes, boost::array<char, MAX_IP_PACKET_SIZE> buf);

    private:
        std::unordered_map<int, ProtocolHandler> handlers;

        void genericHandler(std::unique_ptr<ip> ipHeader, std::string& data);
};
