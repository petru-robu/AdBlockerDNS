#include "dns/rec_resolver.hpp"

#include <boost/asio.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace dns {
    namespace {
        constexpr std::size_t max_resolution_depth = 32;
        constexpr std::size_t max_referral_hops = 32;
        constexpr std::size_t max_resolved_nameservers = 4;
        constexpr auto network_timeout = std::chrono::seconds(2);

        std::string canonical_name(std::string name) {
            while (!name.empty() && name.back() == '.') {
                name.pop_back();
            }

            std::transform(
                name.begin(),
                name.end(),
                name.begin(),
                [](unsigned char character) {
                    return static_cast<char>(std::tolower(character));
                }
            );

            return name;
        }

        std::optional<std::string> domain_name_from_rdata(const DnsRecord& record) {
            try {
                std::size_t offset = 0;
                std::string name = DnsNameParser::parse(record.rdata, offset);

                if (offset != record.rdata.size()) {
                    return std::nullopt;
                }

                return name;
            } catch (const std::exception&) {
                return std::nullopt;
            }
        }

        std::optional<std::string> address_from_record(const DnsRecord& record) {
            if (record.type == RecordType::A && record.rdata.size() == 4) {
                boost::asio::ip::address_v4::bytes_type bytes{};
                std::copy(record.rdata.begin(), record.rdata.end(), bytes.begin());
                return boost::asio::ip::address_v4(bytes).to_string();
            }

            if (record.type == RecordType::AAAA && record.rdata.size() == 16) {
                boost::asio::ip::address_v6::bytes_type bytes{};
                std::copy(record.rdata.begin(), record.rdata.end(), bytes.begin());
                return boost::asio::ip::address_v6(bytes).to_string();
            }

            return std::nullopt;
        }

        std::vector<std::string> referral_names(const DnsMessage& response) {
            std::vector<std::string> names;
            std::unordered_set<std::string> seen;

            for (const DnsRecord& authority : response.authorities) {
                if (
                    authority.type != RecordType::NS ||
                    authority.klass != RecordClass::IN
                ) {
                    continue;
                }

                const auto name = domain_name_from_rdata(authority);
                if (!name) {
                    continue;
                }

                const std::string key = canonical_name(*name);
                if (seen.insert(key).second) {
                    names.push_back(*name);
                }
            }

            return names;
        }

        void append_unique_nameserver(
            std::vector<NameServer>& output,
            std::unordered_set<std::string>& seen_addresses,
            const std::string& name,
            const std::string& address
        ) {
            if (seen_addresses.insert(address).second) {
                output.emplace_back(name, address);
            }
        }

        bool has_soa_authority(const DnsMessage& response) {
            return std::any_of(
                response.authorities.begin(),
                response.authorities.end(),
                [](const DnsRecord& record) {
                    return record.type == RecordType::SOA;
                }
            );
        }

        DnsMessage make_blocked_response(const DnsMessage& query) {
            DnsMessage response;
            response.header.id = query.header.id;
            response.header.flags.qr = true;
            response.header.flags.opcode = query.header.flags.opcode;
            response.header.flags.rd = query.header.flags.rd;
            response.header.flags.ra = true;
            response.header.flags.rcode =
                static_cast<std::uint8_t>(ResponseCode::NXDomain);
            response.questions = query.questions;
            return response;
        }

        std::string referral_zone(const DnsMessage& response) {
            const auto nameserver_record = std::find_if(
                response.authorities.begin(),
                response.authorities.end(),
                [](const DnsRecord& record) {
                    return record.type == RecordType::NS;
                }
            );

            if (nameserver_record == response.authorities.end()) {
                return {};
            }

            return canonical_name(nameserver_record->name);
        }

        std::string nameserver_set_key(const std::vector<NameServer>& nameservers) {
            std::vector<std::string> addresses;
            addresses.reserve(nameservers.size());

            for (const NameServer& nameserver : nameservers) {
                addresses.push_back(nameserver.get_ip());
            }

            std::sort(addresses.begin(), addresses.end());

            std::string key;
            for (const std::string& address : addresses) {
                key += address;
                key.push_back(';');
            }

            return key;
        }

        class ActiveQueryGuard {
        public:
            ActiveQueryGuard(
                std::unordered_set<std::string>& active_queries,
                std::string key
            ) :
                active_queries(active_queries),
                key(std::move(key))
            {
            }

            ~ActiveQueryGuard() {
                active_queries.erase(key);
            }

            ActiveQueryGuard(const ActiveQueryGuard&) = delete;
            ActiveQueryGuard& operator=(const ActiveQueryGuard&) = delete;

        private:
            std::unordered_set<std::string>& active_queries;
            std::string key;
        };
    }

    NameServer::NameServer(std::string name, std::string ip) :
        name(std::move(name)),
        ip(std::move(ip))
    {
    }

    const std::string& NameServer::get_name() const {
        return name;
    }

    const std::string& NameServer::get_ip() const {
        return ip;
    }

    void RecursiveResolver::read_root_servers(const std::string& file_path) {
        std::ifstream root_server_file(file_path);
        if (!root_server_file) {
            throw std::runtime_error("could not open root server file: " + file_path);
        }

        std::string ip_address;
        std::string root_server_name;

        while (root_server_file >> ip_address >> root_server_name) {
            root_servers.emplace_back(root_server_name, ip_address);
        }

        if (root_servers.empty()) {
            throw std::runtime_error("root server file is empty: " + file_path);
        }
    }

    RecursiveResolver::RecursiveResolver(DnsMessage query) :
        query(std::move(query))
    {
        read_root_servers("res/root_servers.txt");
    }

    RecursiveResolver::RecursiveResolver(
        DnsMessage query,
        const DomainBlocklist& blocklist
    ) :
        RecursiveResolver(std::move(query))
    {
        this->blocklist = &blocklist;
    }

    DnsMessage RecursiveResolver::query_server(
        const std::string& server_ip,
        const DnsMessage& query
    ) {
        const Buffer to_send = query.serialize();
        const boost::asio::ip::address address =
            boost::asio::ip::make_address(server_ip);

        boost::asio::io_context io;
        boost::asio::ip::udp::socket socket(io);
        socket.open(address.is_v4()
            ? boost::asio::ip::udp::v4()
            : boost::asio::ip::udp::v6());
        socket.connect(boost::asio::ip::udp::endpoint(address, 53));
        socket.send(boost::asio::buffer(to_send));

        Buffer response_bytes(65535);
        boost::asio::steady_timer timer(io);
        boost::system::error_code receive_error;
        std::size_t bytes_received = 0;
        bool receive_finished = false;
        bool timed_out = false;

        socket.async_receive(
            boost::asio::buffer(response_bytes),
            [&](const boost::system::error_code& error, std::size_t byte_count) {
                receive_error = error;
                bytes_received = byte_count;
                receive_finished = true;
                timer.cancel();
            }
        );

        timer.expires_after(network_timeout);
        timer.async_wait([&](const boost::system::error_code& error) {
            if (!error && !receive_finished) {
                timed_out = true;
                boost::system::error_code ignored;
                socket.cancel(ignored);
            }
        });

        io.run();

        if (timed_out) {
            throw std::runtime_error("DNS query to " + server_ip + " timed out");
        }

        if (receive_error) {
            throw std::runtime_error(
                "DNS query to " + server_ip + " failed: " +
                receive_error.message()
            );
        }

        response_bytes.resize(bytes_received);
        DnsMessage response = DnsMessage::parse(response_bytes);

        if (response.header.id != query.header.id) {
            throw std::runtime_error("DNS response transaction ID does not match query");
        }

        if (response.header.flags.tc) {
            return query_server_tcp(server_ip, query);
        }

        return response;
    }

    DnsMessage RecursiveResolver::query_server_tcp(
        const std::string& server_ip,
        const DnsMessage& query
    ) {
        const Buffer payload = query.serialize();
        if (payload.size() > 0xffff) {
            throw std::runtime_error("DNS query is too large for TCP framing");
        }

        boost::asio::ip::tcp::iostream stream;
        stream.expires_after(network_timeout);
        stream.connect(server_ip, "53");

        if (!stream) {
            throw std::runtime_error("TCP DNS connection to " + server_ip + " failed");
        }

        const std::uint16_t payload_size =
            static_cast<std::uint16_t>(payload.size());
        const std::array<char, 2> length_prefix{
            static_cast<char>((payload_size >> 8) & 0xff),
            static_cast<char>(payload_size & 0xff)
        };

        stream.write(length_prefix.data(), length_prefix.size());
        stream.write(
            reinterpret_cast<const char*>(payload.data()),
            static_cast<std::streamsize>(payload.size())
        );
        stream.flush();

        std::array<unsigned char, 2> response_length_bytes{};
        stream.read(
            reinterpret_cast<char*>(response_length_bytes.data()),
            response_length_bytes.size()
        );

        if (!stream) {
            throw std::runtime_error("failed to read TCP DNS response length");
        }

        const std::size_t response_size =
            (static_cast<std::size_t>(response_length_bytes[0]) << 8) |
            static_cast<std::size_t>(response_length_bytes[1]);

        Buffer response_bytes(response_size);
        stream.read(
            reinterpret_cast<char*>(response_bytes.data()),
            static_cast<std::streamsize>(response_bytes.size())
        );

        if (!stream) {
            throw std::runtime_error("failed to read complete TCP DNS response");
        }

        DnsMessage response = DnsMessage::parse(response_bytes);
        if (response.header.id != query.header.id) {
            throw std::runtime_error("TCP DNS response transaction ID does not match query");
        }

        return response;
    }

    std::vector<NameServer> RecursiveResolver::extract_glue_nameservers(
        const DnsMessage& response
    ) const {
        const std::vector<std::string> referred_names = referral_names(response);
        std::unordered_set<std::string> referred_name_keys;
        for (const std::string& name : referred_names) {
            referred_name_keys.insert(canonical_name(name));
        }

        std::vector<NameServer> nameservers;
        std::unordered_set<std::string> seen_addresses;

        for (const DnsRecord& additional : response.additionals) {
            if (additional.klass != RecordClass::IN) {
                continue;
            }

            const std::string record_name = canonical_name(additional.name);
            if (!referred_name_keys.contains(record_name)) {
                continue;
            }

            const auto address = address_from_record(additional);
            if (address) {
                append_unique_nameserver(
                    nameservers,
                    seen_addresses,
                    additional.name,
                    *address
                );
            }
        }

        return nameservers;
    }

    std::vector<NameServer> RecursiveResolver::resolve_nameserver_ips(
        const DnsMessage& response,
        std::size_t depth,
        std::unordered_set<std::string>& active_queries
    ) {
        std::vector<NameServer> nameservers;
        std::unordered_set<std::string> seen_addresses;

        for (const std::string& nameserver_name : referral_names(response)) {
            const std::array<RecordType, 2> address_types{
                RecordType::A,
                RecordType::AAAA
            };

            for (const RecordType address_type : address_types) {
                DnsMessage address_query;
                address_query.header.id = query.header.id;
                address_query.questions.push_back(DnsQuestion{
                    nameserver_name,
                    address_type,
                    RecordClass::IN
                });

                try {
                    const DnsMessage address_response = resolve_impl(
                        std::move(address_query),
                        depth + 1,
                        active_queries,
                        false
                    );

                    for (const DnsRecord& answer : address_response.answers) {
                        const auto address = address_from_record(answer);
                        if (address) {
                            append_unique_nameserver(
                                nameservers,
                                seen_addresses,
                                nameserver_name,
                                *address
                            );
                        }
                    }
                } catch (const std::exception&) {
                    // Another NS name or address family may still be usable.
                }

                if (!nameservers.empty()) {
                    break;
                }
            }

            if (nameservers.size() >= max_resolved_nameservers) {
                break;
            }
        }

        return nameservers;
    }

    DnsMessage RecursiveResolver::resolve_impl(
        DnsMessage query,
        std::size_t depth,
        std::unordered_set<std::string>& active_queries,
        bool apply_blocklist
    ) {
        if (depth > max_resolution_depth) {
            throw std::runtime_error("maximum DNS resolution depth exceeded");
        }

        if (query.questions.size() != 1) {
            throw std::runtime_error("recursive resolver requires exactly one question");
        }

        DnsQuestion& question = query.questions.front();

        if (
            apply_blocklist &&
            blocklist &&
            blocklist->is_blocked(question.qname)
        ) {
            return make_blocked_response(query);
        }

        const std::string active_key =
            canonical_name(question.qname) + "#" +
            std::to_string(static_cast<std::uint16_t>(question.qtype));

        if (!active_queries.insert(active_key).second) {
            throw std::runtime_error("DNS dependency or CNAME loop detected");
        }
        ActiveQueryGuard active_query_guard(active_queries, active_key);

        query.header.flags.qr = false;
        query.header.flags.aa = false;
        query.header.flags.tc = false;
        query.header.flags.rd = false;
        query.header.flags.ra = false;
        query.header.flags.rcode =
            static_cast<std::uint8_t>(ResponseCode::NoError);
        query.answers.clear();
        query.authorities.clear();

        // Keep only an incoming OPT pseudo-record, if the client sent one.
        std::erase_if(query.additionals, [](const DnsRecord& record) {
            return static_cast<std::uint16_t>(record.type) != 41;
        });

        std::vector<NameServer> current_servers = root_servers;
        std::unordered_set<std::string> visited_nameserver_sets;
        visited_nameserver_sets.insert(".|" + nameserver_set_key(current_servers));

        for (std::size_t hop = 0; hop < max_referral_hops; ++hop) {
            std::vector<NameServer> next_servers;
            std::string next_referral_zone;

            for (const NameServer& server : current_servers) {
                DnsMessage response;
                try {
                    response = query_server(server.get_ip(), query);
                } catch (const std::exception&) {
                    continue;
                }

                const auto response_code =
                    static_cast<ResponseCode>(response.header.flags.rcode);

                if (response_code == ResponseCode::NXDomain) {
                    return response;
                }

                if (response_code != ResponseCode::NoError) {
                    continue;
                }

                if (!response.answers.empty()) {
                    if (question.qtype == RecordType::CNAME) {
                        return response;
                    }

                    std::string answer_name = canonical_name(question.qname);
                    std::unordered_set<std::string> cname_names;
                    bool found_cname = false;

                    while (cname_names.insert(answer_name).second) {
                        const auto requested_answer = std::find_if(
                            response.answers.begin(),
                            response.answers.end(),
                            [&](const DnsRecord& answer) {
                                return (
                                    canonical_name(answer.name) == answer_name &&
                                    (
                                        answer.type == question.qtype ||
                                        static_cast<std::uint16_t>(question.qtype) == 255
                                    )
                                );
                            }
                        );

                        if (requested_answer != response.answers.end()) {
                            return response;
                        }

                        const auto cname = std::find_if(
                            response.answers.begin(),
                            response.answers.end(),
                            [&](const DnsRecord& answer) {
                                return (
                                    canonical_name(answer.name) == answer_name &&
                                    answer.type == RecordType::CNAME
                                );
                            }
                        );

                        if (cname == response.answers.end()) {
                            break;
                        }

                        const auto target = domain_name_from_rdata(*cname);
                        if (!target) {
                            return response;
                        }

                        if (
                            apply_blocklist &&
                            blocklist &&
                            blocklist->is_blocked(*target)
                        ) {
                            return make_blocked_response(query);
                        }

                        found_cname = true;
                        answer_name = canonical_name(*target);
                    }

                    if (!found_cname) {
                        return response;
                    }

                    DnsMessage target_query = query;
                    target_query.questions.front().qname = answer_name;
                    DnsMessage target_response = resolve_impl(
                        std::move(target_query),
                        depth + 1,
                        active_queries,
                        apply_blocklist
                    );

                    response.answers.insert(
                        response.answers.end(),
                        target_response.answers.begin(),
                        target_response.answers.end()
                    );
                    response.authorities = std::move(target_response.authorities);
                    response.additionals = std::move(target_response.additionals);
                    response.header.flags.rcode =
                        target_response.header.flags.rcode;
                    response.questions = query.questions;
                    return response;
                }

                if (response.header.flags.aa || has_soa_authority(response)) {
                    // An authoritative empty answer is a valid NODATA response.
                    return response;
                }

                next_servers = extract_glue_nameservers(response);
                if (next_servers.empty() && !referral_names(response).empty()) {
                    next_servers = resolve_nameserver_ips(
                        response,
                        depth,
                        active_queries
                    );
                }

                if (!next_servers.empty()) {
                    next_referral_zone = referral_zone(response);
                    break;
                }
            }

            if (next_servers.empty()) {
                throw std::runtime_error("all DNS nameservers failed");
            }

            const std::string set_key =
                next_referral_zone + "|" + nameserver_set_key(next_servers);
            if (!visited_nameserver_sets.insert(set_key).second) {
                throw std::runtime_error("DNS referral loop detected");
            }

            current_servers = std::move(next_servers);
        }

        throw std::runtime_error("maximum DNS referral count exceeded");
    }

    DnsMessage RecursiveResolver::resolve(DnsMessage requested_query) {
        if (requested_query.questions.empty() && !query.questions.empty()) {
            requested_query = query;
        }

        std::unordered_set<std::string> active_queries;
        return resolve_impl(
            std::move(requested_query),
            0,
            active_queries,
            true
        );
    }
}
