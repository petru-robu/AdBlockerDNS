#pragma once

#include <cstddef>
#include <string>
#include <unordered_set>

namespace dns {
    class DomainBlocklist {
    public:
        explicit DomainBlocklist(const std::string& file_path);

        bool is_blocked(const std::string& domain) const;
        std::size_t size() const;

    private:
        std::unordered_set<std::string> blocked_domains;
    };
}
