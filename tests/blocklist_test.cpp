#include "dns/blocklist.hpp"
#include "dns/dns_message.hpp"
#include "dns/udp_server.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>

int main() {
    const dns::DomainBlocklist blocklist("res/blocklist.txt");

    assert(blocklist.is_blocked("doubleclick.net"));
    assert(blocklist.is_blocked("ads.DOUBLECLICK.net."));
    assert(blocklist.is_blocked("sb.scorecardresearch.com"));
    assert(!blocklist.is_blocked("example.com"));

    dns::DnsMessage query;
    query.header.id = 0x1234;
    query.header.flags.rd = true;
    query.questions.push_back(dns::DnsQuestion{
        "subdomain.doubleclick.net",
        dns::RecordType::A,
        dns::RecordClass::IN
    });

    const dns::DnsMessage response = dns::DnsMessage::parse(
        dns::handle_query_rr(query.serialize(), blocklist)
    );

    assert(response.header.id == query.header.id);
    assert(response.header.flags.qr);
    assert(response.header.flags.ra);
    assert(
        response.header.flags.rcode ==
        static_cast<std::uint8_t>(dns::ResponseCode::NXDomain)
    );
    assert(response.answers.empty());

    std::cout << "blocklist tests passed\n";
}
