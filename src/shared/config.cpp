#include "config.h"

#include <charconv>
#include <sstream>

namespace maple {

namespace {

std::optional<std::uint32_t> parse_u32(std::string_view text) {
    std::uint32_t value = 0;
    auto parse = [&](std::string_view raw, int base) -> bool {
        const auto result = std::from_chars(raw.data(), raw.data() + raw.size(), value, base);
        return result.ec == std::errc{} && result.ptr == raw.data() + raw.size();
    };

    if (text.starts_with("0x") || text.starts_with("0X")) {
        if (parse(text.substr(2), 16)) {
            return value;
        }
        return std::nullopt;
    }

    if (parse(text, 10)) {
        return value;
    }
    if (parse(text, 16)) {
        return value;
    }
    return std::nullopt;
}

std::optional<std::uint8_t> parse_hex_byte(std::string_view text) {
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text = text.substr(2);
    }

    std::uint32_t value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value > 0xFF) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(value);
}

}  // namespace

std::vector<std::uint8_t> build_patch_bytes(const PatchEntry& patch, std::string& error) {
    std::vector<std::uint8_t> bytes;

    switch (patch.type) {
    case PatchType::Hex: {
        std::istringstream stream(patch.value);
        std::string token;
        while (stream >> token) {
            const auto parsed = parse_hex_byte(token);
            if (!parsed) {
                error = "invalid hex byte in patch at address " + std::to_string(patch.address);
                return {};
            }
            bytes.push_back(*parsed);
        }
        break;
    }
    case PatchType::Ascii: {
        bytes.assign(patch.value.begin(), patch.value.end());
        if (patch.size) {
            if (bytes.size() > *patch.size) {
                error = "ascii patch larger than size at address " + std::to_string(patch.address);
                return {};
            }
            bytes.resize(*patch.size, 0);
        }
        break;
    }
    case PatchType::U32: {
        const auto parsed = parse_u32(patch.value);
        if (!parsed) {
            error = "invalid u32 patch value at address " + std::to_string(patch.address);
            return {};
        }
        const auto value = *parsed;
        bytes = {
            static_cast<std::uint8_t>(value & 0xFF),
            static_cast<std::uint8_t>((value >> 8) & 0xFF),
            static_cast<std::uint8_t>((value >> 16) & 0xFF),
            static_cast<std::uint8_t>((value >> 24) & 0xFF),
        };
        break;
    }
    }

    if (bytes.empty()) {
        error = "patch produced no bytes at address " + std::to_string(patch.address);
    }

    return bytes;
}

std::wstring widen(std::string_view value) {
    return std::wstring(value.begin(), value.end());
}

}  // namespace maple
