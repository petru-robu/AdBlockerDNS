#include "dns/dns_message.hpp"

#include <cstdint>
#include <stdexcept>

namespace dns {
    namespace {
        void append_name(Buffer& output, const Buffer& packet, std::size_t& offset) {
            DnsNameParser::write_uncompressed(
                output,
                DnsNameParser::parse(packet, offset)
            );
        }

        Buffer parse_rdata(
            const Buffer& packet,
            std::size_t start,
            std::size_t end,
            RecordType type
        ) {
            Buffer output;
            std::size_t cursor = start;
            const auto type_value = static_cast<std::uint16_t>(type);

            // These RDATA formats contain domain names which may use compression
            // pointers into the original packet. Expand them now so a parsed
            // message remains valid when it is serialized again.
            if (
                type_value == static_cast<std::uint16_t>(RecordType::NS) ||
                type_value == static_cast<std::uint16_t>(RecordType::CNAME) ||
                type_value == 12 // PTR
            ) {
                append_name(output, packet, cursor);
            } else if (type_value == static_cast<std::uint16_t>(RecordType::SOA)) {
                append_name(output, packet, cursor);
                append_name(output, packet, cursor);

                constexpr std::size_t soa_integer_bytes = 20;
                if (cursor + soa_integer_bytes != end) {
                    throw std::runtime_error("invalid SOA RDATA length");
                }

                output.insert(
                    output.end(),
                    packet.begin() + cursor,
                    packet.begin() + end
                );
                cursor = end;
            } else if (type_value == 15) { // MX: preference followed by exchange
                constexpr std::size_t preference_bytes = 2;
                if (cursor + preference_bytes > end) {
                    throw std::runtime_error("invalid MX RDATA length");
                }

                output.insert(
                    output.end(),
                    packet.begin() + cursor,
                    packet.begin() + cursor + preference_bytes
                );
                cursor += preference_bytes;
                append_name(output, packet, cursor);
            } else {
                output.assign(packet.begin() + start, packet.begin() + end);
                return output;
            }

            if (cursor != end) {
                throw std::runtime_error("domain name does not match RDATA length");
            }

            return output;
        }
    }

    /*
        Flag parsing methods.
    */

    DnsFlags DnsFlags::from_u16(std::uint16_t value) {
        DnsFlags flags;

        flags.qr = (value & 0x8000) != 0; // 1 bit, check if it is set
        flags.opcode = static_cast<std::uint8_t>((value >> 11) & 0x0f);
        flags.aa = (value & 0x0400) != 0; // 1bit
        flags.tc = (value & 0x0200) != 0; // 1bit
        flags.rd = (value & 0x0100) != 0; // 1bit
        flags.ra = (value & 0x0080) != 0; // 1bit
        flags.z = static_cast<std::uint8_t>((value >> 4) & 0x07);
        flags.rcode = static_cast<std::uint8_t>(value & 0x0f);

        return flags;
    }

    std::uint16_t DnsFlags::to_u16() const {
        std::uint16_t value = 0;
        value |= static_cast<std::uint16_t>(qr ? 0x8000 : 0);
        value |= static_cast<std::uint16_t>((opcode & 0x0f) << 11);
        value |= static_cast<std::uint16_t>(aa ? 0x0400 : 0);
        value |= static_cast<std::uint16_t>(tc ? 0x0200 : 0);
        value |= static_cast<std::uint16_t>(rd ? 0x0100 : 0);
        value |= static_cast<std::uint16_t>(ra ? 0x0080 : 0);
        value |= static_cast<std::uint16_t>((z & 0x07) << 4);
        value |= static_cast<std::uint16_t>(rcode & 0x0f);
        return value;
    }

    /*
        Parsing methods.
    */
    std::uint16_t DnsMessageParser::read_u16(const Buffer& packet, std::size_t& offset) {
        if (offset + 2 > packet.size()) {
            throw std::runtime_error("Exceeded packet size!");
        }

        const std::uint16_t value =
            (static_cast<std::uint16_t>(packet[offset]) << 8) | // high byte
            static_cast<std::uint16_t>(packet[offset + 1]);

        offset += 2;
        return value;
    }

    std::uint32_t DnsMessageParser::read_u32(const Buffer& packet, std::size_t& offset) {
        if (offset + 4 > packet.size()) {
            throw std::runtime_error("Exceeded packet size!");
        }

        const std::uint32_t value =
            (static_cast<std::uint32_t>(packet[offset]) << 24) |
            (static_cast<std::uint32_t>(packet[offset + 1]) << 16) |
            (static_cast<std::uint32_t>(packet[offset + 2]) << 8) |
            static_cast<std::uint32_t>(packet[offset + 3]);

        offset += 4;
        return value;
    }

    DnsHeader DnsMessageParser::parse_header(const Buffer& packet, std::size_t& offset) {
        if (packet.size() < 12) {
            throw std::runtime_error("DNS packet too short!");
        }

        DnsHeader header;

        header.id = read_u16(packet, offset);
        header.flags = DnsFlags::from_u16(read_u16(packet, offset));
        header.question_count = read_u16(packet, offset);
        header.answer_count = read_u16(packet, offset);
        header.authority_count = read_u16(packet, offset);
        header.additional_count = read_u16(packet, offset);

        return header;
    }

    DnsQuestion DnsMessageParser::parse_question(const Buffer& packet, std::size_t& offset) {
        DnsQuestion question;
        
        question.qname = DnsNameParser::parse(packet, offset);
        question.qtype = static_cast<RecordType>(read_u16(packet, offset));
        question.qclass = static_cast<RecordClass>(read_u16(packet, offset));
        

        return question;
    }

    DnsRecord DnsMessageParser::parse_record(const Buffer& packet, std::size_t& offset) {
        DnsRecord record;

        record.name = DnsNameParser::parse(packet, offset);
        record.type = static_cast<RecordType>(read_u16(packet, offset));
        record.klass = static_cast<RecordClass>(read_u16(packet, offset));
        record.ttl = read_u32(packet, offset);

        const std::uint16_t rdlength = read_u16(packet, offset);

        if (offset + rdlength > packet.size()) {
            throw std::runtime_error("DNS packet truncated while reading record rdata");
        }

        const std::size_t rdata_end = offset + rdlength;
        record.rdata = parse_rdata(
            packet,
            offset,
            rdata_end,
            record.type
        );
        offset = rdata_end;

        return record;
    }

    void DnsMessageParser::parse_questions(const Buffer& packet, std::size_t& offset, std::uint16_t count, std::vector<DnsQuestion>& output) {
        output.reserve(output.size() + count);

        for (std::uint16_t i = 0; i < count; i++) {
            output.push_back(parse_question(packet, offset));
        }
    }

    void DnsMessageParser::parse_records(const Buffer& packet, std::size_t& offset, std::uint16_t count, std::vector<DnsRecord>& output) {
        output.reserve(output.size() + count);

        for (std::uint16_t i = 0; i < count; ++i) {
            output.push_back(parse_record(packet, offset));
        }
    }

    DnsMessage DnsMessage::parse(const Buffer& packet) {
        std::size_t offset = 0;

        DnsMessage message;

        // parse header
        message.header = DnsMessageParser::parse_header(packet, offset);

        // parse questions
        DnsMessageParser::parse_questions(
            packet,
            offset,
            message.header.question_count,
            message.questions
        );

        // parse records
        DnsMessageParser::parse_records(
            packet,
            offset,
            message.header.answer_count,
            message.answers
        );

        DnsMessageParser::parse_records(
            packet,
            offset,
            message.header.authority_count,
            message.authorities
        );

        DnsMessageParser::parse_records(
            packet,
            offset,
            message.header.additional_count,
            message.additionals
        );

        return message;
    }

    /*
        Serializing methods.
    */
    void DnsMessageSerializer::write_u16(Buffer& output, std::uint16_t value) {
        output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
        output.push_back(static_cast<std::uint8_t>(value & 0xff));
    }

    void DnsMessageSerializer::write_u32(Buffer& output, std::uint32_t value) {
        output.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
        output.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
        output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
        output.push_back(static_cast<std::uint8_t>(value & 0xff));
    }

    void DnsMessageSerializer::write_header(Buffer& output, const DnsHeader& header) {
        write_u16(output, header.id);
        write_u16(output, header.flags.to_u16());
        write_u16(output, header.question_count);
        write_u16(output, header.answer_count);
        write_u16(output, header.authority_count);
        write_u16(output, header.additional_count);
    }

    void DnsMessageSerializer::write_question(Buffer& output, const DnsQuestion& question) {
        DnsNameParser::write_uncompressed(output, question.qname);

        write_u16(output, static_cast<std::uint16_t>(question.qtype));
        write_u16(output, static_cast<std::uint16_t>(question.qclass));
    }

    void DnsMessageSerializer::write_record(Buffer& output, const DnsRecord& record) {
        DnsNameParser::write_uncompressed(output, record.name);

        write_u16(output, static_cast<std::uint16_t>(record.type));
        write_u16(output, static_cast<std::uint16_t>(record.klass));
        write_u32(output, record.ttl);

        if (record.rdata.size() > 0xffff) {
            throw std::runtime_error("DNS record rdata too large!");
        }

        write_u16(output, static_cast<std::uint16_t>(record.rdata.size()));

        output.insert(
            output.end(),
            record.rdata.begin(),
            record.rdata.end()
        );
    }

    void DnsMessageSerializer::write_questions(Buffer& output, const std::vector<DnsQuestion>& questions) {
        for (const DnsQuestion& question : questions) {
            write_question(output, question);
        }
    }

    void DnsMessageSerializer::write_records(Buffer& output, const std::vector<DnsRecord>& records) {
        for (const DnsRecord& record : records) {
            write_record(output, record);
        }
    }

    Buffer DnsMessage::serialize() const {
        Buffer output;

        DnsHeader real_header = header;

        real_header.question_count = static_cast<std::uint16_t>(questions.size());

        real_header.answer_count = static_cast<std::uint16_t>(answers.size());

        real_header.authority_count = static_cast<std::uint16_t>(authorities.size());

        real_header.additional_count = static_cast<std::uint16_t>(additionals.size());

        // compose dnsmessage
        DnsMessageSerializer::write_header(output, real_header);
        DnsMessageSerializer::write_questions(output, questions);
        DnsMessageSerializer::write_records(output, answers);
        DnsMessageSerializer::write_records(output, authorities);
        DnsMessageSerializer::write_records(output, additionals);

        return output;
    }

}
