#pragma once

#include "types.hpp"
#include <iostream>

namespace dns {
    class DnsNameParser {
    public:
        /*
            This parses the bytes from a buffer and constructs the string name.
        */
        static std::string parse(const Buffer& packet, std::size_t& offset);

        /*
           This writes a string name as bytes.
        */
        static void write_uncompressed(Buffer& ouput, const std::string& name);
    };
}
