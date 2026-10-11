#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace mavtls {
constexpr size_t MaxMessage = 1024;
// RFC6455 data-message assembly; control frames are handled separately.
struct Message {
    uint8_t data[MaxMessage];
    size_t length = 0;
    bool fragmented = false;
    void reset() { length = 0; fragmented = false; }
    // 0 = incomplete, 1 = complete, otherwise WebSocket close code.
    unsigned accept(unsigned opcode, bool final, const uint8_t *bytes, size_t size) {
        if (opcode == 1) return 1003;
        if ((opcode == 0 && !fragmented) || (opcode == 2 && fragmented) || (opcode != 0 && opcode != 2)) return 1002;
        if (!fragmented) length = 0;
        if (size > MaxMessage - length) return 1009;
        if (size) memcpy(data + length, bytes, size);
        length += size; fragmented = !final;
        return final ? 1 : 0;
    }
};
} // namespace mavtls
