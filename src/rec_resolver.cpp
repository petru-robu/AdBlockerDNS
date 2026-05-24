#include "dns/rec_resolver.hpp"

#include <boost/asio.hpp>
#include <stdexcept>

namespace dns {
    NameServer::NameServer(std::string name, std::string ip): name(name), ip(ip) {}

    const std::string& NameServer::get_name() const {
        return name;
    }

    const std::string& NameServer::get_ip() const {
        return ip;
    }

    void RecursiveResolver::read_root_servers(std::string file_path) {
        std::ifstream root_sv_file(file_path);

        if (!root_sv_file) {
            std::cout << "Could not open file " << file_path << "\n";
            return;
        }

        std::string ip_address;
        std::string root_sv_name;

        while (root_sv_file >> ip_address >> root_sv_name) {
            // std::cout << root_sv_name << "\n";
            root_servers.push_back(NameServer(root_sv_name, ip_address));
        }
    }

    RecursiveResolver::RecursiveResolver(DnsMessage query): query(query) {
        read_root_servers("res/root_servers.txt");
    }

    DnsMessage RecursiveResolver::query_server(const std::string& server_ip, DnsMessage& query) {
        Buffer to_send = query.serialize();

        boost::asio::io_context io;
        boost::asio::ip::udp::socket socket(io);
        boost::asio::ip::udp::endpoint server_endpoint(
            boost::asio::ip::make_address(server_ip),
            53
        );

        socket.open(boost::asio::ip::udp::v4());
        socket.send_to(boost::asio::buffer(to_send), server_endpoint);

        Buffer response_bytes(512);
        boost::asio::ip::udp::endpoint sender_endpoint;

        const std::size_t bytes_received = socket.receive_from(
            boost::asio::buffer(response_bytes),
            sender_endpoint
        );

        response_bytes.resize(bytes_received);

        return DnsMessage::parse(response_bytes);

    }

    DnsMessage RecursiveResolver::resolve(DnsMessage query) {
        std::vector<NameServer> current_servers = root_servers;

        while(true) {
            for(auto& server : current_servers) {
                DnsMessage response = query_server(server.get_ip(), query);

                // if (response has answer) {
                //     return response;
                // }

                // if (response has referral with glue IPs) {
                //     current_servers = extract_glue_nameservers(response);
                //     break;
                // }

                // if (response has referral without glue IPs) {
                //     current_servers = resolve_nameserver_ips(response);
                //     break;
                // }

                // if (response says NXDOMAIN) {
                //     return response;
                // }
            }
        }
         
    }
}
