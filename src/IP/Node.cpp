#include "include/IP/Node.h"

#include <boost/asio.hpp>

using namespace boost::asio;

Node::Node(unsigned int port) : port(port), io_context(), socket(io_context, {ip::udp::v4(), port}) {}

Node::addInterface() {

}
