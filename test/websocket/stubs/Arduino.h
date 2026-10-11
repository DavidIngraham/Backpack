#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

struct TestSerial
{
    std::vector<uint8_t> bytes;
    size_t write(const uint8_t *data, size_t length)
    {
        bytes.insert(bytes.end(), data, data + length);
        return length;
    }
};
extern TestSerial Serial;
