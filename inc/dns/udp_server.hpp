#pragma once

#include "dns/blocklist.hpp"
#include "dns/types.hpp"
#include "dns/dns_message.hpp"
#include "dns/rec_resolver.hpp"
#include <boost/asio.hpp>
#include <iostream>

namespace dns {
    class UdpServer {
    private:
        void receive_next();
        void send_response(std::size_t bytes_received);

        boost::asio::ip::udp::socket socket;
        boost::asio::ip::udp::endpoint remote_endpoint;

        Buffer receive_buffer;
        Buffer response_buffer;
        DomainBlocklist blocklist;

    public:
        UdpServer(boost::asio::io_context& io, std::uint16_t port);
        void start();
    };

    /*
        Get a request and return a response.
    */
    Buffer handle_query(const Buffer& request);
    Buffer handle_query_rr(const Buffer& request);
    Buffer handle_query_rr(
        const Buffer& request,
        const DomainBlocklist& blocklist
    );
}
