#include "dns/blocklist.hpp"

#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace dns {
    namespace {
        std::string canonical_domain(std::string domain) {
            const auto first_character = std::find_if_not(
                domain.begin(),
                domain.end(),
                [](unsigned char character) {
                    return std::isspace(character) != 0;
                }
            );
            domain.erase(domain.begin(), first_character);

            const auto last_character = std::find_if_not(
                domain.rbegin(),
                domain.rend(),
                [](unsigned char character) {
                    return std::isspace(character) != 0;
                }
            ).base();
            domain.erase(last_character, domain.end());

            if (domain.starts_with("*.")) {
                domain.erase(0, 2);
            }

            while (!domain.empty() && domain.back() == '.') {
                domain.pop_back();
            }

            std::transform(
                domain.begin(),
                domain.end(),
                domain.begin(),
                [](unsigned char character) {
                    return static_cast<char>(std::tolower(character));
                }
            );

            return domain;
        }

        bool is_ip_address(const std::string& value) {
            boost::system::error_code error;
            boost::asio::ip::make_address(value, error);
            return !error;
        }
    }

    DomainBlocklist::DomainBlocklist(const std::string& file_path) {
        std::ifstream file(file_path);
        if (!file) {
            throw std::runtime_error("could not open blocklist file: " + file_path);
        }

        std::string line;
        while (std::getline(file, line)) {
            const std::size_t comment = line.find('#');
            if (comment != std::string::npos) {
                line.erase(comment);
            }

            std::istringstream line_stream(line);
            std::vector<std::string> fields;
            std::string field;

            while (line_stream >> field) {
                fields.push_back(std::move(field));
            }

            if (fields.empty()) {
                continue;
            }

            // Support both:
            //   ads.example.com
            //   0.0.0.0 ads.example.com tracker.example.com
            const std::size_t first_domain = is_ip_address(fields.front()) ? 1 : 0;
            for (std::size_t index = first_domain; index < fields.size(); ++index) {
                std::string domain = canonical_domain(std::move(fields[index]));
                if (!domain.empty()) {
                    blocked_domains.insert(std::move(domain));
                }
            }
        }
    }

    bool DomainBlocklist::is_blocked(const std::string& domain) const {
        std::string candidate = canonical_domain(domain);

        while (!candidate.empty()) {
            if (blocked_domains.contains(candidate)) {
                return true;
            }

            const std::size_t dot = candidate.find('.');
            if (dot == std::string::npos) {
                break;
            }

            candidate.erase(0, dot + 1);
        }

        return false;
    }

    std::size_t DomainBlocklist::size() const {
        return blocked_domains.size();
    }
}
