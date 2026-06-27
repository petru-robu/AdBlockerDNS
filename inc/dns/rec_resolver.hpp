#pragma once
#include "blocklist.hpp"
#include "types.hpp"
#include "dns_message.hpp"

#include <cstddef>
#include <string>
#include <unordered_set>
#include <vector>

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
        const DomainBlocklist* blocklist{};

        void read_root_servers(const std::string& file_path);

        DnsMessage query_server(const std::string& server_ip, const DnsMessage& query);
        DnsMessage query_server_tcp(const std::string& server_ip, const DnsMessage& query);

        DnsMessage resolve_impl(
            DnsMessage query,
            std::size_t depth,
            std::unordered_set<std::string>& active_queries,
            bool apply_blocklist
        );

        std::vector<NameServer> extract_glue_nameservers(
            const DnsMessage& response
        ) const;

        std::vector<NameServer> resolve_nameserver_ips(
            const DnsMessage& response,
            std::size_t depth,
            std::unordered_set<std::string>& active_queries
        );

    public:
        RecursiveResolver(DnsMessage query);
        RecursiveResolver(DnsMessage query, const DomainBlocklist& blocklist);
        DnsMessage resolve(DnsMessage query);
    };
}
