#pragma once

#include "dns_name.hpp"
#include <iostream>

namespace dns {
    /*
    DNS packet contains:

    DNS header
    question section
    answer section
    authority section
    additional section

    From RFC 1035 specification
    https://datatracker.ietf.org/doc/html/rfc1035 section 4.1
    */

    /*
        Header flags, RD - recursion desired, we want to see if DNS wants recursion
        |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
    */
    struct DnsFlags {
        bool qr{};              
        std::uint8_t opcode{};  
        bool aa{};             
        bool tc{};              
        bool rd{};              
        bool ra{};             
        std::uint8_t z{};       
        std::uint8_t rcode{};
        
        static DnsFlags from_u16(std::uint16_t value);
        std::uint16_t to_u16() const;
    };

    /*
        Info about the dns packet content.
    */
    struct DnsHeader {
        std::uint16_t id{};
        DnsFlags flags{};
        std::uint16_t question_count{};
        std::uint16_t answer_count{};
        std::uint16_t authority_count{};
        std::uint16_t additional_count{};
    };

    /*
        Question:
        <name> <class> <type>
        www.example.com AAAA
    */
    struct DnsQuestion {
        std::string qname;
        RecordType qtype{ RecordType::A };
        RecordClass qclass{ RecordClass::IN };
    };

    /*
        Record:
        <name> <ttl> <class> <type> <data>
        www.example.com 3600 IN AAAA data
    */
    struct DnsRecord {
        std::string name;
        RecordType type{ RecordType::A };
        RecordClass klass{ RecordClass::IN };
        std::uint32_t ttl{};
        Buffer rdata;
    };

    /*
        Final DnsPacket structure:
    */
    struct DnsMessage {
        DnsHeader header;
        std::vector<DnsQuestion> questions;
        std::vector<DnsRecord> answers;
        std::vector<DnsRecord> authorities;
        std::vector<DnsRecord> additionals;

        static DnsMessage parse(const Buffer& packet);
        Buffer serialize();
    };

    class DnsMessageParser {
    public:
        static std::uint16_t read_u16(const Buffer& packet, std::size_t& offset);
        static std::uint32_t read_u32(const Buffer& packet, std::size_t& offset);

        static DnsHeader parse_header(const Buffer& packet, std::size_t& offset);
        static DnsQuestion parse_question(const Buffer& packet, std::size_t& offset);
        static DnsRecord parse_record(const Buffer& packet, std::size_t& offset);

        static void parse_questions(
            const Buffer& packet,
            std::size_t& offset,
            std::uint16_t count,
            std::vector<DnsQuestion>& output
        );

        static void parse_records(
            const Buffer& packet,
            std::size_t& offset,
            std::uint16_t count,
            std::vector<DnsRecord>& output
        );
    };
    
    class DnsMessageSerializer {
    public:
        static void write_u16(Buffer& output, std::uint16_t value);
        static void write_u32(Buffer& output, std::uint32_t value);

        static void write_header(Buffer& output, const DnsHeader& header);
        static void write_question(Buffer& output, const DnsQuestion& question);
        static void write_record(Buffer& output, const DnsRecord& record);

        static void write_questions(Buffer& output, const std::vector<DnsQuestion>& questions);

        static void write_records(Buffer& output, const std::vector<DnsRecord>& records);
    };

}
