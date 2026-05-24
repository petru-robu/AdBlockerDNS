#pragma once
#include "types.hpp"
#include "dns_message.hpp"
#include <iostream>
#include <fstream>

namespace dns {
    class NameServer {
    private:
        std::string name;
        std::string ip;

    public:
        NameServer(std::string name, std::string ip);

        const std::string& get_name() const;
        const std::string& get_ip() const;
    };

    class RecursiveResolver {
    private:
        DnsMessage query;
        std::vector<NameServer> root_servers;

        void read_root_servers(std::string file_path);

        DnsMessage query_server(const std::string& server_ip, DnsMessage& query);

    public:
        RecursiveResolver(DnsMessage query);
        DnsMessage resolve(DnsMessage query);
    };
}
