#include "dns/udp_server.hpp"

namespace dns {
    UdpServer::UdpServer(boost::asio::io_context& io, std::uint16_t port) :
        socket(
            io,
            boost::asio::ip::udp::endpoint(
                boost::asio::ip::udp::v4(),
                port
            )
        ),
        receive_buffer(512),
        blocklist("res/blocklist.txt")
    {
        std::cout << "Loaded " << blocklist.size() << " blocked domains\n";
    }

    void UdpServer::start() {
        receive_next();
    }

    void UdpServer::receive_next() {
        // get next from receive_buffer using boost
        socket.async_receive_from(
            boost::asio::buffer(receive_buffer),
            remote_endpoint,
            [this](const boost::system::error_code& error, std::size_t bytes_received) {
                if (error) {
                    std::cerr << "Receive error: " << error.message() << '\n';
                    receive_next();
                    return;
                }

                send_response(bytes_received);
            }
        );
    }

    void UdpServer::send_response(std::size_t bytes_received) {
        // slice first bytes_received bytes from buffer
        Buffer request(
            receive_buffer.begin(),
            receive_buffer.begin() + bytes_received
        );

        response_buffer = handle_query_rr(request, blocklist);

        // send with boost
        socket.async_send_to(
            boost::asio::buffer(response_buffer),
            remote_endpoint,
            [this](const boost::system::error_code& error, std::size_t) {
                if (error) {
                    std::cerr << "Send error: " << error.message() << '\n';
                }

                receive_next();
            }
        );
    }

    Buffer handle_query(const Buffer& request) {
        // In here you must do logic with the DNS

        // std::cout << "Received " << request.size() << " bytes: ";

        // for (std::uint8_t byte : request) {
        //     std::cout << static_cast<char>(byte);
        // }

        // std::cout << '\n';

        DnsMessage query = DnsMessage::parse(request);

        DnsMessage response;

        // Same request ID so response and request match
        response.header.id = query.header.id;
        response.header.flags.qr = true;
        response.header.flags.opcode = query.header.flags.opcode;
        response.header.flags.rd = query.header.flags.rd;
        response.header.flags.ra = true;
        response.questions = query.questions;

        if (!query.questions.empty()) {
            const DnsQuestion& question = query.questions[0];

            if (question.qtype == RecordType::A && question.qclass == RecordClass::IN) {
                DnsRecord answer;

                answer.name = question.qname;
                answer.type = RecordType::A;
                answer.klass = RecordClass::IN;
                answer.ttl = 60;

                // Fake IPv4 address: 1.2.3.4
                answer.rdata = {1, 2, 3, 4};

                response.answers.push_back(answer);
            }
        }

        response.header.question_count = static_cast<std::uint16_t>(response.questions.size());
        response.header.answer_count = static_cast<std::uint16_t>(response.answers.size());
        response.header.authority_count = 0;
        response.header.additional_count = 0;

        return response.serialize();
    }

    Buffer handle_query_rr(const Buffer& request) {
        static const DomainBlocklist default_blocklist("res/blocklist.txt");
        return handle_query_rr(request, default_blocklist);
    }

    Buffer handle_query_rr(
        const Buffer& request,
        const DomainBlocklist& blocklist
    ) {
        DnsMessage query = DnsMessage::parse(request);
        DnsMessage response;

        if (query.questions.size() != 1) {
            response.header.flags.rcode =
                static_cast<std::uint8_t>(ResponseCode::FormErr);
        } else if (blocklist.is_blocked(query.questions.front().qname)) {
            response.header.flags.rcode =
                static_cast<std::uint8_t>(ResponseCode::NXDomain);
        } else if (!query.header.flags.rd) {
            // There is no cache to answer non-recursive requests from.
            response.header.flags.rcode =
                static_cast<std::uint8_t>(ResponseCode::Refused);
        } else {
            try {
                RecursiveResolver resolver(query, blocklist);
                response = resolver.resolve(query);
            } catch (const std::exception& error) {
                std::cerr << "Resolution error: " << error.what() << '\n';
                response.header.flags.rcode =
                    static_cast<std::uint8_t>(ResponseCode::ServFail);
            }
        }

        response.header.id = query.header.id;
        response.header.flags.qr = true;
        response.header.flags.opcode = query.header.flags.opcode;
        response.header.flags.aa = false;
        response.header.flags.rd = query.header.flags.rd;
        response.header.flags.ra = true;
        response.questions = query.questions;

        return response.serialize();
    }
}
