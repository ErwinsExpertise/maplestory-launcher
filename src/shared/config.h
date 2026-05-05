#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace maple {

enum class PatchType {
    Hex,
    Ascii,
    U32,
};

struct PatchEntry {
    std::uint32_t address = 0;
    PatchType type = PatchType::Hex;
    std::string value;
    std::optional<std::size_t> size;
};

struct LauncherSettings {
    std::filesystem::path client;
    std::filesystem::path working_dir;
    std::wstring arguments;
    bool unpack_mode = false;
};

struct Config {
    LauncherSettings launcher;
    std::vector<PatchEntry> patches;
};

const Config& embedded_config();
std::vector<std::uint8_t> build_patch_bytes(const PatchEntry& patch, std::string& error);
std::wstring widen(std::string_view value);

}  // namespace maple
