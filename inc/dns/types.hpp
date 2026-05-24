#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dns {
    using Byte = std::uint8_t;
    using Buffer = std::vector<Byte>;

    enum class RecordType : std::uint16_t {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        AAAA = 28,
    };

    enum class RecordClass : std::uint16_t {
        IN = 1
    };

    enum class ResponseCode : std::uint8_t {
        NoError = 0,
        FormErr = 1,
        ServFail = 2,
        NXDomain = 3,
        NotImp = 4,
        Refused = 5,
    };

    struct Endpoint {
        std::string address;
        std::uint16_t port{53};
    };
}