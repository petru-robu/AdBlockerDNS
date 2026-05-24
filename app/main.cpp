#include <iostream>
#include <boost/asio.hpp>

#include <dns/dns_name.hpp>

#include <dns/udp_server.hpp>

int main() {

    std::cout << "DNS Resolver!\n";

    dns::Buffer bytes;
    dns::DnsNameParser::write_uncompressed(bytes, "www.example.com");

    // for (auto byte : bytes) {
    //     std::cout << std::hex << static_cast<int>(byte) << " ";
    // }

    std::size_t offset = 0;

    std::string name = dns::DnsNameParser::parse(bytes, offset);
    std::cout << "\n" << name << "\n";

    // Server
    try {
        const std::uint16_t port = 5300;
        boost::asio::io_context io;

        dns::UdpServer server(io, port);

        server.start();
        std::cout << "DNS UDP server running on " << port << "!\n";

        io.run();

    } catch (const std::exception& error) {
        std::cout << "Server error!" << error.what() << "\n";
        return 1;
    }

    return 0;
}