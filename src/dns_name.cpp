#include "dns/dns_name.hpp"

#include <stdexcept>

namespace dns {
    
    std::string DnsNameParser::parse(const Buffer& packet, std::size_t& offset) {
        std::vector<std::string> tokens;
        std::size_t cursor = offset;
        bool jumped = false;
        std::size_t jump_count = 0;

        while(true) {
            if (cursor >= packet.size()) {
                throw std::runtime_error("end of packet");
            }

            const Byte length_byte = packet[cursor];

            if ((length_byte & 0xc0) == 0xc0) {
                if (cursor + 1 >= packet.size()) {
                    throw std::runtime_error("truncated DNS compression pointer");
                }

                const std::size_t pointer =
                    ((static_cast<std::size_t>(length_byte & 0x3f)) << 8) |
                    static_cast<std::size_t>(packet[cursor + 1]);

                if (pointer >= packet.size()) {
                    throw std::runtime_error("DNS compression pointer out of bounds");
                }

                if (!jumped) {
                    offset = cursor + 2;
                    jumped = true;
                }

                cursor = pointer;

                if (++jump_count > packet.size()) {
                    throw std::runtime_error("DNS compression pointer loop");
                }

                continue;
            }

            if ((length_byte & 0xc0) != 0) {
                throw std::runtime_error("unsupported DNS label type");
            }

            std::size_t cnt = static_cast<std::size_t>(length_byte);
            
            if (cnt == 0) {
                if (!jumped) {
                    offset = cursor + 1;
                }

                break;
            }

            cursor++;

            if (cursor + cnt > packet.size()) {
                throw std::runtime_error("DNS label exceeds packet size");
            }

            std::string token = "";
            for(std::size_t i = cursor; i < cursor + cnt; i++) {
                token += static_cast<char>(packet[i]);
            }
            
            tokens.push_back(token);
            cursor += cnt;
        }

        std::string result = "";
        for (const auto& tok : tokens) {
            if (!result.empty()) {
                result += ".";
            }

            result += tok;
        } 
        return result;
    }
    
    void DnsNameParser::write_uncompressed(Buffer& output, const std::string& name) {
        std::vector<std::string> tokens;
        std::string curr_tok = "";
        for (auto& ch : name) {
            if (ch == '.') {
                tokens.push_back(curr_tok);
                curr_tok = "";
            }
            else {
                curr_tok += ch;
            }
        }   

        if(curr_tok.size() > 0)
            tokens.push_back(curr_tok);

        for (auto& tok : tokens) {
            // std::cout << tok << '\n';
            output.push_back(static_cast<Byte>(tok.size()));
            
            for (auto &btok : tok) {
                output.push_back((Byte)btok);
            }
        }

        output.push_back(0);
    }
}
