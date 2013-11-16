#ifndef EXPIMSG_UTIL_H
#define EXPIMSG_UTIL_H
#include <sstream>
#include <string>
#include <iomanip>
#include <arpa/inet.h>
#include <cstdint>
#include "base64.h"

std::string to_hex(std::string s) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for(std::uint64_t i = 0; i < s.size(); ++i)
    {
        ss << std::setw(2) << (static_cast<unsigned>(s[i]) & 0xff);
    }
    return ss.str();
}

std::uint64_t htonll(std::uint64_t value) {
    int num = 42;
    if(*reinterpret_cast<char *>(&num) == 42) {
        uint32_t high_part = htonl((uint32_t)(value >> 32));
        uint32_t low_part = htonl((uint32_t)(value & 0xFFFFFFFFLL));
        return (((uint64_t)low_part) << 32) | high_part;
    } else {
        return value;
    }
}

std::uint64_t ntohll(std::uint64_t value) {
    return htonll(value);
}

#endif
